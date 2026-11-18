package fingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

const (
	// MaxTLSHandshakeBytes bounds how many bytes of fragmented TLS records or CRYPTO frames are buffered for a single ClientHello.
	MaxTLSHandshakeBytes = 16384

	tlsRecordTypeHandshake = 0x16
	tlsHandshakeClient     = 0x01
	tlsHandshakeServer     = 0x02

	extServerName           uint16 = 0x0000
	extSupportedGroups      uint16 = 0x000a
	extECPointFormats       uint16 = 0x000b
	extSignatureAlgorithms  uint16 = 0x000d
	extALPN                 uint16 = 0x0010
	extPadding              uint16 = 0x0015
	extCompressCertificate  uint16 = 0x001b
	extRecordSizeLimit      uint16 = 0x001c
	extDelegatedCredentials uint16 = 0x0022
	extSupportedVersions    uint16 = 0x002b
	extPSKKeyExchangeModes  uint16 = 0x002d
	extKeyShare             uint16 = 0x0033
	extQUICTransportParams  uint16 = 0x0039
	extALPSLegacy           uint16 = 0x4469
	extALPS                 uint16 = 0x44cd
	extECH                  uint16 = 0xfe0d

	// GroupX25519MLKEM768 is the IANA hybrid post-quantum key exchange group code point.
	GroupX25519MLKEM768 uint16 = 0x11ec
	// GroupSecP256r1MLKEM768 is the NIST P-256 + ML-KEM-768 hybrid group code point.
	GroupSecP256r1MLKEM768 uint16 = 0x11eb
	// GroupX25519Kyber768Draft00 is the pre-standard Chromium PQ group code point.
	GroupX25519Kyber768Draft00 uint16 = 0x6399

	emptyHash12 = "000000000000"
)

// ErrNotTLSHandshake indicates the inspected byte stream does not start with a TLS Handshake record.
var ErrNotTLSHandshake = errors.New("not a TLS handshake record")

// ErrIncompleteHandshake indicates more bytes are needed to complete the TLS Handshake message.
var ErrIncompleteHandshake = errors.New("incomplete TLS handshake message")

// ErrOversizedHandshake indicates the TLS Handshake message exceeds MaxTLSHandshakeBytes.
var ErrOversizedHandshake = errors.New("TLS handshake exceeds maximum buffer limit")

// helloRetryRequestRandom is the magic ServerHello.random defined in RFC 8446 Section 4.1.3.
var helloRetryRequestRandom = [32]byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// parsedClientHello holds raw fields extracted from a wire ClientHello before hashing.
type parsedClientHello struct {
	legacyVersion   uint16
	maxSupportedVer uint16
	hasSNIExt       bool
	serverName      string
	ciphers         []uint16
	extensions      []uint16
	groups          []uint16
	pointFormats    []uint8
	sigAlgs         []uint16
	alpnProtos      []string
}

// ComputeJA4FromHelloInfo computes a canonical JA4 fingerprint directly from Go 1.24+ tls.ClientHelloInfo.
func ComputeJA4FromHelloInfo(info *tls.ClientHelloInfo, isQUIC bool) string {
	if info == nil {
		return ""
	}

	var maxVer uint16
	for _, v := range info.SupportedVersions {
		if !IsTLSGREASE(v) && v > maxVer {
			maxVer = v
		}
	}

	hasSNI := info.ServerName != "" || slices.Contains(info.Extensions, extServerName)
	sigAlgs := make([]uint16, 0, len(info.SignatureSchemes))
	for _, s := range info.SignatureSchemes {
		sigAlgs = append(sigAlgs, uint16(s))
	}

	parsed := parsedClientHello{
		legacyVersion:   maxVer,
		maxSupportedVer: maxVer,
		hasSNIExt:       hasSNI,
		serverName:      info.ServerName,
		ciphers:         info.CipherSuites,
		extensions:      info.Extensions,
		sigAlgs:         sigAlgs,
		alpnProtos:      info.SupportedProtos,
	}
	return computeJA4(&parsed, isQUIC)
}

// ReadClientHelloFromRecords reads one or more consecutive TLS 0x16 Handshake records using readFn
// up to MaxTLSHandshakeBytes and populates out with JA4, JA3, JA3N, SNI, ALPN, and Deep TLS fields.
func ReadClientHelloFromRecords(readFn func([]byte) (int, error), out *ConnData) error {
	var (
		recordHdr [5]byte
		assembled []byte
		fragments uint8
		firstRecV uint16
	)

	for {
		if err := readFull(readFn, recordHdr[:]); err != nil {
			return err
		}
		if recordHdr[0] != tlsRecordTypeHandshake {
			if fragments == 0 {
				return ErrNotTLSHandshake
			}
			return errors.New("unexpected non-handshake TLS record during ClientHello fragmentation")
		}

		recVer := binary.BigEndian.Uint16(recordHdr[1:3])
		recLen := int(binary.BigEndian.Uint16(recordHdr[3:5]))
		if fragments == 0 {
			firstRecV = recVer
		}
		if recLen == 0 || len(assembled)+recLen > MaxTLSHandshakeBytes {
			return ErrOversizedHandshake
		}

		offset := len(assembled)
		assembled = append(assembled, make([]byte, recLen)...)
		if err := readFull(readFn, assembled[offset:]); err != nil {
			return err
		}
		fragments++

		if len(assembled) >= 4 {
			if assembled[0] != tlsHandshakeClient {
				return errors.New("first TLS handshake message is not ClientHello")
			}
			msgLen := int(assembled[1])<<16 | int(assembled[2])<<8 | int(assembled[3])
			if msgLen+4 > MaxTLSHandshakeBytes {
				return ErrOversizedHandshake
			}
			if len(assembled) >= 4+msgLen {
				if out != nil {
					out.Lock()
					out.TLSRecordVersion = firstRecV
					out.TLSRecordFragments = fragments
					out.Unlock()
				}
				return ParseClientHelloBody(assembled[4:4+msgLen], false, out)
			}
		}
	}
}

// ParseClientHelloRecords parses already buffered TLS 0x16 Handshake records containing a ClientHello.
func ParseClientHelloRecords(raw []byte, out *ConnData) error {
	var (
		pos       int
		assembled []byte
		fragments uint8
		firstRecV uint16
	)

	for pos < len(raw) {
		if len(raw)-pos < 5 {
			return ErrIncompleteHandshake
		}
		if raw[pos] != tlsRecordTypeHandshake {
			if fragments == 0 {
				return ErrNotTLSHandshake
			}
			return errors.New("unexpected non-handshake TLS record")
		}

		recVer := binary.BigEndian.Uint16(raw[pos+1 : pos+3])
		recLen := int(binary.BigEndian.Uint16(raw[pos+3 : pos+5]))
		pos += 5
		if fragments == 0 {
			firstRecV = recVer
		}
		if recLen == 0 || len(assembled)+recLen > MaxTLSHandshakeBytes {
			return ErrOversizedHandshake
		}
		if len(raw)-pos < recLen {
			return ErrIncompleteHandshake
		}

		assembled = append(assembled, raw[pos:pos+recLen]...)
		pos += recLen
		fragments++

		if len(assembled) >= 4 {
			if assembled[0] != tlsHandshakeClient {
				return errors.New("first TLS handshake message is not ClientHello")
			}
			msgLen := int(assembled[1])<<16 | int(assembled[2])<<8 | int(assembled[3])
			if msgLen+4 > MaxTLSHandshakeBytes {
				return ErrOversizedHandshake
			}
			if len(assembled) >= 4+msgLen {
				if out != nil {
					out.Lock()
					out.TLSRecordVersion = firstRecV
					out.TLSRecordFragments = fragments
					out.Unlock()
				}
				return ParseClientHelloBody(assembled[4:4+msgLen], false, out)
			}
		}
	}

	return ErrIncompleteHandshake
}

// ParseClientHelloHandshake parses a recordless TLS Handshake message (0x01 + uint24 length + ClientHello body),
// such as the payload reassembled from QUIC Initial CRYPTO frames.
func ParseClientHelloHandshake(handshakeBytes []byte, isQUIC bool, out *ConnData) error {
	if len(handshakeBytes) < 4 {
		return ErrIncompleteHandshake
	}
	if handshakeBytes[0] != tlsHandshakeClient {
		return errors.New("TLS handshake message is not ClientHello")
	}
	msgLen := int(handshakeBytes[1])<<16 | int(handshakeBytes[2])<<8 | int(handshakeBytes[3])
	if msgLen+4 > MaxTLSHandshakeBytes {
		return ErrOversizedHandshake
	}
	if len(handshakeBytes) < 4+msgLen {
		return ErrIncompleteHandshake
	}
	return ParseClientHelloBody(handshakeBytes[4:4+msgLen], isQUIC, out)
}

// ParseClientHelloBody parses the body of a TLS ClientHello message using bounds-safe cryptobyte readers.
func ParseClientHelloBody(body []byte, isQUIC bool, out *ConnData) error {
	s := cryptobyte.String(body)

	var legacyVersion uint16
	var random []byte
	var sessionID cryptobyte.String
	var cipherBytes cryptobyte.String
	var compMethods cryptobyte.String

	if !s.ReadUint16(&legacyVersion) ||
		!s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&sessionID) ||
		!s.ReadUint16LengthPrefixed(&cipherBytes) ||
		!s.ReadUint8LengthPrefixed(&compMethods) {
		return errors.New("malformed TLS ClientHello header")
	}

	if cipherBytes.Empty() || len(cipherBytes)%2 != 0 {
		return errors.New("malformed TLS ClientHello cipher suites")
	}

	var ciphersBuf [64]uint16
	ciphers := ciphersBuf[:0]
	for !cipherBytes.Empty() {
		var cs uint16
		if !cipherBytes.ReadUint16(&cs) {
			return errors.New("truncated cipher suite")
		}
		ciphers = append(ciphers, cs)
	}

	parsed := parsedClientHello{
		legacyVersion: legacyVersion,
		ciphers:       ciphers,
	}

	var (
		keyShareGroups  []uint16
		certCompression []uint16
		alpsCode        uint16
		hasDelegated    bool
		pskModes        []uint8
		recordSizeLimit uint16
		paddingLen      = -1
		echOuter        string
		echAccepted     bool
		quicTP          string
		quicHasGREASE   bool
		quicDisableMig  bool
	)

	if !s.Empty() {
		var extBlock cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&extBlock) {
			return errors.New("malformed TLS extensions block")
		}

		var extBuf [64]uint16
		parsed.extensions = extBuf[:0]

		for !extBlock.Empty() {
			var extType uint16
			var extData cryptobyte.String
			if !extBlock.ReadUint16(&extType) || !extBlock.ReadUint16LengthPrefixed(&extData) {
				return errors.New("malformed TLS extension entry")
			}
			parsed.extensions = append(parsed.extensions, extType)

			switch extType {
			case extServerName:
				parsed.hasSNIExt = true
				parseSNIExtension(extData, &parsed.serverName)
			case extSupportedGroups:
				parsed.groups = parseUint16ListPrefixed16(extData)
			case extECPointFormats:
				parsed.pointFormats = parseUint8ListPrefixed8(extData)
			case extSignatureAlgorithms:
				parsed.sigAlgs = parseUint16ListPrefixed16(extData)
			case extALPN:
				parsed.alpnProtos = parseALPNExtension(extData)
			case extPadding:
				paddingLen = len(extData)
			case extCompressCertificate:
				certCompression = parseCompressCertificateExtension(extData)
			case extRecordSizeLimit:
				_ = extData.ReadUint16(&recordSizeLimit)
			case extDelegatedCredentials:
				hasDelegated = true
			case extSupportedVersions:
				parsed.maxSupportedVer = parseSupportedVersionsExtension(extData)
			case extPSKKeyExchangeModes:
				pskModes = parseUint8ListPrefixed8(extData)
			case extKeyShare:
				keyShareGroups = parseKeyShareExtension(extData)
			case extQUICTransportParams:
				quicTP, quicHasGREASE, quicDisableMig = ParseQUICTransportParams(extData)
			case extALPSLegacy, extALPS:
				alpsCode = extType
			case extECH:
				echOuter, echAccepted = parseECHExtension(extData)
			}
		}
	}

	ja4 := computeJA4(&parsed, isQUIC)
	ja3, ja3n := computeJA3AndJA3N(&parsed)

	if out != nil {
		out.Lock()
		if out.JA4 != "" {
			out.TLSHelloRetry = true
		} else {
			out.IsQUIC = out.IsQUIC || isQUIC
			out.JA4 = ja4
			out.JA3 = ja3
			out.JA3N = ja3n
			out.ServerName = parsed.serverName
			out.ALPNProtos = parsed.alpnProtos
			out.TLSHandshakeVersion = legacyVersion
			if len(sessionID) <= 255 {
				out.TLSSessionIDLen = uint8(len(sessionID))
			}
			out.TLSKeyShareGroups = keyShareGroups
			out.TLSCertCompression = certCompression
			out.TLSALPS = alpsCode
			out.TLSHasDelegatedCred = hasDelegated
			out.TLSPSKModes = pskModes
			out.TLSRecordSizeLimit = recordSizeLimit
			out.TLSPaddingLen = paddingLen
			if echOuter != "" {
				out.TLSECHOuter = echOuter
			}
			if echAccepted {
				out.TLSECHAccepted = true
			}
			if quicTP != "" {
				out.QUICTransportParams = quicTP
				out.QUICHasGREASETP = quicHasGREASE
				out.QUICDisableMig = quicDisableMig
			}
		}
		out.Unlock()
	}

	return nil
}

// ParseServerHelloRecords parses a TLS 0x16 record containing a ServerHello and computes JA3S and JA4S.
func ParseServerHelloRecords(raw []byte, isQUIC bool) (*ServerHelloData, bool, error) {
	if len(raw) < 9 {
		return nil, false, ErrIncompleteHandshake
	}
	if raw[0] != tlsRecordTypeHandshake {
		return nil, false, ErrNotTLSHandshake
	}
	recLen := int(binary.BigEndian.Uint16(raw[3:5]))
	if len(raw) < 5+recLen {
		return nil, false, ErrIncompleteHandshake
	}
	payload := raw[5 : 5+recLen]
	if len(payload) < 4 || payload[0] != tlsHandshakeServer {
		return nil, false, errors.New("TLS record does not start with ServerHello")
	}
	msgLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+msgLen {
		return nil, false, ErrIncompleteHandshake
	}

	s := cryptobyte.String(payload[4 : 4+msgLen])
	var (
		legacyVer uint16
		random    []byte
		sessionID cryptobyte.String
		cipher    uint16
		comp      uint8
	)
	if !s.ReadUint16(&legacyVer) ||
		!s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&sessionID) ||
		!s.ReadUint16(&cipher) ||
		!s.ReadUint8(&comp) {
		return nil, false, errors.New("malformed ServerHello message")
	}

	isHRR := string(random) == string(helloRetryRequestRandom[:])
	sh := &ServerHelloData{
		Version:     legacyVer,
		CipherSuite: cipher,
	}

	if !s.Empty() {
		var extBlock cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&extBlock) {
			return nil, isHRR, errors.New("malformed ServerHello extensions")
		}
		for !extBlock.Empty() {
			var extType uint16
			var extData cryptobyte.String
			if !extBlock.ReadUint16(&extType) || !extBlock.ReadUint16LengthPrefixed(&extData) {
				return nil, isHRR, errors.New("malformed ServerHello extension")
			}
			if IsTLSGREASE(extType) {
				continue
			}
			sh.Extensions = append(sh.Extensions, extType)
			switch extType {
			case extSupportedVersions:
				var sv uint16
				if extData.ReadUint16(&sv) && !IsTLSGREASE(sv) {
					sh.SupportedVersion = sv
				}
			case extALPN:
				protos := parseALPNExtension(extData)
				if len(protos) > 0 {
					sh.ALPN = protos[0]
				}
			}
		}
	}

	sh.JA3S = computeJA3S(sh)
	sh.JA4S = computeJA4S(sh, isQUIC)
	return sh, isHRR, nil
}

// HasPostQuantumKeyShare reports whether groups includes a hybrid post-quantum key exchange group.
func HasPostQuantumKeyShare(groups []uint16) bool {
	for _, g := range groups {
		if g == GroupX25519MLKEM768 || g == GroupSecP256r1MLKEM768 || g == GroupX25519Kyber768Draft00 {
			return true
		}
	}
	return false
}

func computeJA4(p *parsedClientHello, isQUIC bool) string {
	var b strings.Builder
	b.Grow(36)

	if isQUIC {
		b.WriteByte('q')
	} else {
		b.WriteByte('t')
	}

	ver := p.maxSupportedVer
	if ver == 0 {
		ver = p.legacyVersion
	}
	b.WriteString(ja4VersionCode(ver))

	if p.hasSNIExt && p.serverName != "" && !isIPLiteral(p.serverName) {
		b.WriteByte('d')
	} else {
		b.WriteByte('i')
	}

	var ciphersBuf [64]uint16
	ciphers := ciphersBuf[:0]
	for _, c := range p.ciphers {
		if !IsTLSGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}

	var extAllCount int
	var hashExtsBuf [64]uint16
	hashExts := hashExtsBuf[:0]
	for _, e := range p.extensions {
		if IsTLSGREASE(e) {
			continue
		}
		extAllCount++
		if e != extServerName && e != extALPN {
			hashExts = append(hashExts, e)
		}
	}

	writeTwoDigits(&b, min(len(ciphers), 99))
	writeTwoDigits(&b, min(extAllCount, 99))

	firstALPN := ""
	if len(p.alpnProtos) > 0 {
		firstALPN = p.alpnProtos[0]
	}
	a0, a1 := ja4ALPNChars(firstALPN)
	b.WriteByte(a0)
	b.WriteByte(a1)
	b.WriteByte('_')

	if len(ciphers) == 0 {
		b.WriteString(emptyHash12)
	} else {
		slices.Sort(ciphers)
		b.WriteString(hashUint16HexList(ciphers, nil))
	}
	b.WriteByte('_')

	var sigsBuf [32]uint16
	sigs := sigsBuf[:0]
	for _, sig := range p.sigAlgs {
		if !IsTLSGREASE(sig) {
			sigs = append(sigs, sig)
		}
	}

	if len(hashExts) == 0 && len(sigs) == 0 {
		b.WriteString(emptyHash12)
	} else {
		slices.Sort(hashExts)
		b.WriteString(hashUint16HexList(hashExts, sigs))
	}

	return b.String()
}

func computeJA3AndJA3N(p *parsedClientHello) (ja3, ja3n string) {
	var ciphersBuf [64]uint16
	ciphers := ciphersBuf[:0]
	for _, c := range p.ciphers {
		if !IsTLSGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}

	var extsBuf [64]uint16
	exts := extsBuf[:0]
	for _, e := range p.extensions {
		if !IsTLSGREASE(e) {
			exts = append(exts, e)
		}
	}

	var groupsBuf [32]uint16
	groups := groupsBuf[:0]
	for _, g := range p.groups {
		if !IsTLSGREASE(g) {
			groups = append(groups, g)
		}
	}

	verStr := strconv.FormatUint(uint64(p.legacyVersion), 10)
	ciphersStr := joinUint16Dash(ciphers)
	groupsStr := joinUint16Dash(groups)
	ptsStr := joinUint8Dec(p.pointFormats, '-')

	rawJA3 := verStr + "," + ciphersStr + "," + joinUint16Dash(exts) + "," + groupsStr + "," + ptsStr
	sumJA3 := md5.Sum([]byte(rawJA3))

	sortedExts := slices.Clone(exts)
	slices.Sort(sortedExts)
	rawJA3N := verStr + "," + ciphersStr + "," + joinUint16Dash(sortedExts) + "," + groupsStr + "," + ptsStr
	sumJA3N := md5.Sum([]byte(rawJA3N))

	return hex.EncodeToString(sumJA3[:]), hex.EncodeToString(sumJA3N[:])
}

func computeJA3S(sh *ServerHelloData) string {
	raw := strconv.FormatUint(uint64(sh.Version), 10) + "," +
		strconv.FormatUint(uint64(sh.CipherSuite), 10) + "," +
		joinUint16Dash(sh.Extensions)
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func computeJA4S(sh *ServerHelloData, isQUIC bool) string {
	var b strings.Builder
	b.Grow(27)
	if isQUIC {
		b.WriteByte('q')
	} else {
		b.WriteByte('t')
	}
	ver := sh.SupportedVersion
	if ver == 0 {
		ver = sh.Version
	}
	b.WriteString(ja4VersionCode(ver))
	writeTwoDigits(&b, min(len(sh.Extensions), 99))
	a0, a1 := ja4ALPNChars(sh.ALPN)
	b.WriteByte(a0)
	b.WriteByte(a1)
	b.WriteByte('_')

	var csHex [4]byte
	putUint16Hex(&csHex, sh.CipherSuite)
	b.Write(csHex[:])
	b.WriteByte('_')

	if len(sh.Extensions) == 0 {
		b.WriteString(emptyHash12)
	} else {
		b.WriteString(hashUint16HexList(sh.Extensions, nil))
	}
	return b.String()
}

func ja4VersionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

func ja4ALPNChars(proto string) (byte, byte) {
	if len(proto) == 0 {
		return '0', '0'
	}
	first := proto[0]
	last := proto[len(proto)-1]
	if isASCIIAlphaNum(first) && isASCIIAlphaNum(last) {
		return first, last
	}
	const hexDigits = "0123456789abcdef"
	return hexDigits[first>>4], hexDigits[last&0x0f]
}

func isASCIIAlphaNum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isIPLiteral(host string) bool {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	_, err := netip.ParseAddr(trimmed)
	return err == nil
}

func writeTwoDigits(b *strings.Builder, n int) {
	if n < 0 {
		n = 0
	}
	if n > 99 {
		n = 99
	}
	b.WriteByte(byte('0' + n/10))
	b.WriteByte(byte('0' + n%10))
}

func putUint16Hex(dst *[4]byte, v uint16) {
	const hexDigits = "0123456789abcdef"
	dst[0] = hexDigits[(v>>12)&0x0f]
	dst[1] = hexDigits[(v>>8)&0x0f]
	dst[2] = hexDigits[(v>>4)&0x0f]
	dst[3] = hexDigits[v&0x0f]
}

func hashUint16HexList(primary, secondary []uint16) string {
	h := sha256.New()
	var item [5]byte
	for i, v := range primary {
		if i > 0 {
			item[0] = ','
			putUint16Hex((*[4]byte)(item[1:5]), v)
			_, _ = h.Write(item[:5])
		} else {
			putUint16Hex((*[4]byte)(item[0:4]), v)
			_, _ = h.Write(item[:4])
		}
	}
	if len(secondary) > 0 {
		if len(primary) > 0 {
			_, _ = h.Write([]byte{'_'})
		}
		for i, v := range secondary {
			if i > 0 {
				item[0] = ','
				putUint16Hex((*[4]byte)(item[1:5]), v)
				_, _ = h.Write(item[:5])
			} else {
				putUint16Hex((*[4]byte)(item[0:4]), v)
				_, _ = h.Write(item[:4])
			}
		}
	}
	var sum [32]byte
	h.Sum(sum[:0])
	var out [12]byte
	hex.Encode(out[:], sum[:6])
	return string(out[:])
}

func joinUint16Dash(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(vals) * 6)
	var numBuf [8]byte
	for i, v := range vals {
		if i > 0 {
			b.WriteByte('-')
		}
		b.Write(strconv.AppendUint(numBuf[:0], uint64(v), 10))
	}
	return b.String()
}

func joinUint8Dec(vals []uint8, sep byte) string {
	if len(vals) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(vals) * 4)
	var numBuf [4]byte
	for i, v := range vals {
		if i > 0 {
			b.WriteByte(sep)
		}
		b.Write(strconv.AppendUint(numBuf[:0], uint64(v), 10))
	}
	return b.String()
}

func parseSNIExtension(ext cryptobyte.String, out *string) {
	var nameList cryptobyte.String
	if !ext.ReadUint16LengthPrefixed(&nameList) {
		return
	}
	for !nameList.Empty() {
		var nameType uint8
		var hostName cryptobyte.String
		if !nameList.ReadUint8(&nameType) || !nameList.ReadUint16LengthPrefixed(&hostName) {
			return
		}
		if nameType == 0 {
			*out = string(hostName)
			return
		}
	}
}

func parseUint16ListPrefixed16(ext cryptobyte.String) []uint16 {
	var list cryptobyte.String
	if !ext.ReadUint16LengthPrefixed(&list) || len(list)%2 != 0 {
		return nil
	}
	out := make([]uint16, 0, len(list)/2)
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			return nil
		}
		out = append(out, v)
	}
	return out
}

func parseUint8ListPrefixed8(ext cryptobyte.String) []uint8 {
	var list cryptobyte.String
	if !ext.ReadUint8LengthPrefixed(&list) {
		return nil
	}
	out := make([]uint8, len(list))
	copy(out, list)
	return out
}

func parseALPNExtension(ext cryptobyte.String) []string {
	var list cryptobyte.String
	if !ext.ReadUint16LengthPrefixed(&list) {
		return nil
	}
	var protos []string
	for !list.Empty() {
		var p cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&p) || p.Empty() {
			return nil
		}
		protos = append(protos, string(p))
	}
	return protos
}

func parseCompressCertificateExtension(ext cryptobyte.String) []uint16 {
	var list cryptobyte.String
	if !ext.ReadUint8LengthPrefixed(&list) || len(list)%2 != 0 {
		return nil
	}
	var algs []uint16
	for !list.Empty() {
		var alg uint16
		if !list.ReadUint16(&alg) {
			return nil
		}
		if !IsTLSGREASE(alg) {
			algs = append(algs, alg)
		}
	}
	return algs
}

func parseSupportedVersionsExtension(ext cryptobyte.String) uint16 {
	var list cryptobyte.String
	if !ext.ReadUint8LengthPrefixed(&list) || len(list)%2 != 0 {
		return 0
	}
	var maxVer uint16
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			return maxVer
		}
		if !IsTLSGREASE(v) && v > maxVer {
			maxVer = v
		}
	}
	return maxVer
}

func parseKeyShareExtension(ext cryptobyte.String) []uint16 {
	var shares cryptobyte.String
	if !ext.ReadUint16LengthPrefixed(&shares) {
		return nil
	}
	var groups []uint16
	for !shares.Empty() {
		var group uint16
		var keyEx cryptobyte.String
		if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed(&keyEx) {
			return groups
		}
		if !IsTLSGREASE(group) {
			groups = append(groups, group)
		}
	}
	return groups
}

func parseECHExtension(ext cryptobyte.String) (outer string, isInner bool) {
	var chType uint8
	if !ext.ReadUint8(&chType) {
		return "", false
	}
	if chType == 1 {
		return "inner", true
	}
	if chType != 0 {
		return "", false
	}
	var (
		kdfID    uint16
		aeadID   uint16
		configID uint8
		enc      cryptobyte.String
		payload  cryptobyte.String
	)
	if !ext.ReadUint16(&kdfID) ||
		!ext.ReadUint16(&aeadID) ||
		!ext.ReadUint8(&configID) ||
		!ext.ReadUint16LengthPrefixed(&enc) ||
		!ext.ReadUint16LengthPrefixed(&payload) {
		return "", false
	}
	return fmt.Sprintf("%04x-%04x_id%d_enc%d_len%d", kdfID, aeadID, configID, len(enc), len(payload)), false
}

// ParseQUICTransportParams decodes TLS extension 0x0039 (RFC 9000 Section 18) preserving exact wire order.
func ParseQUICTransportParams(ext []byte) (summary string, hasGREASE, disableMig bool) {
	pos := 0
	var b strings.Builder
	first := true
	for pos < len(ext) {
		id, n1, ok := readQUICVarint(ext[pos:])
		if !ok {
			break
		}
		pos += n1
		valLen, n2, ok := readQUICVarint(ext[pos:])
		if !ok || valLen > uint64(len(ext)-pos-n2) {
			break
		}
		pos += n2
		valBytes := ext[pos : pos+int(valLen)]
		pos += int(valLen)

		if IsQUICTPGREASE(id) {
			hasGREASE = true
			continue
		}
		if id == 0x2ab2 {
			hasGREASE = true
		}
		if id == 0x0c {
			disableMig = true
		}

		if !first {
			b.WriteByte(';')
		}
		first = false
		b.WriteString(strconv.FormatUint(id, 16))
		if shouldIncludeQUICTPValue(id) && len(valBytes) > 0 {
			if v, vn, vok := readQUICVarint(valBytes); vok && vn == len(valBytes) {
				b.WriteByte(':')
				b.WriteString(strconv.FormatUint(v, 10))
			}
		}
	}
	return b.String(), hasGREASE, disableMig
}

func shouldIncludeQUICTPValue(id uint64) bool {
	switch id {
	case 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x20:
		return true
	default:
		return false
	}
}

func readQUICVarint(b []byte) (val uint64, consumed int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	if len(b) < length {
		return 0, 0, false
	}
	val = uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val, length, true
}

func readFull(readFn func([]byte) (int, error), dst []byte) error {
	offset := 0
	for offset < len(dst) {
		n, err := readFn(dst[offset:])
		offset += n
		if offset == len(dst) {
			return nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) && offset > 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}
