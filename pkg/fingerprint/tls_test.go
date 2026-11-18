package fingerprint

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type extSpec struct {
	id   uint16
	data []byte
}

func buildClientHelloBody(legacyVer uint16, sessionID []byte, ciphers []uint16, exts []extSpec) []byte {
	var b bytes.Buffer
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], legacyVer)
	b.Write(u16[:])

	var random [32]byte
	for i := range random {
		random[i] = byte(i + 1)
	}
	b.Write(random[:])

	b.WriteByte(byte(len(sessionID)))
	b.Write(sessionID)

	binary.BigEndian.PutUint16(u16[:], uint16(len(ciphers)*2))
	b.Write(u16[:])
	for _, c := range ciphers {
		binary.BigEndian.PutUint16(u16[:], c)
		b.Write(u16[:])
	}

	b.Write([]byte{0x01, 0x00})

	var extBuf bytes.Buffer
	for _, e := range exts {
		binary.BigEndian.PutUint16(u16[:], e.id)
		extBuf.Write(u16[:])
		binary.BigEndian.PutUint16(u16[:], uint16(len(e.data)))
		extBuf.Write(u16[:])
		extBuf.Write(e.data)
	}
	binary.BigEndian.PutUint16(u16[:], uint16(extBuf.Len()))
	b.Write(u16[:])
	b.Write(extBuf.Bytes())

	return b.Bytes()
}

func wrapHandshakeMessage(msgType byte, body []byte) []byte {
	out := make([]byte, 4+len(body))
	out[0] = msgType
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	copy(out[4:], body)
	return out
}

func wrapTLSRecords(recVer uint16, hs []byte, chunkSize int) []byte {
	var out bytes.Buffer
	for pos := 0; pos < len(hs); pos += chunkSize {
		end := min(pos+chunkSize, len(hs))
		part := hs[pos:end]
		out.WriteByte(tlsRecordTypeHandshake)
		out.WriteByte(byte(recVer >> 8))
		out.WriteByte(byte(recVer))
		out.WriteByte(byte(len(part) >> 8))
		out.WriteByte(byte(len(part)))
		out.Write(part)
	}
	return out.Bytes()
}

func buildSNIExt(host string) []byte {
	n := len(host)
	var b bytes.Buffer
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(n+3))
	b.Write(u16[:])
	b.WriteByte(0x00)
	binary.BigEndian.PutUint16(u16[:], uint16(n))
	b.Write(u16[:])
	b.WriteString(host)
	return b.Bytes()
}

func buildALPNExt(protos ...string) []byte {
	var list bytes.Buffer
	for _, p := range protos {
		list.WriteByte(byte(len(p)))
		list.WriteString(p)
	}
	var out bytes.Buffer
	out.WriteByte(byte(list.Len() >> 8))
	out.WriteByte(byte(list.Len()))
	out.Write(list.Bytes())
	return out.Bytes()
}

func buildSupportedVersionsExt(vers ...uint16) []byte {
	var b bytes.Buffer
	b.WriteByte(byte(len(vers) * 2))
	for _, v := range vers {
		b.WriteByte(byte(v >> 8))
		b.WriteByte(byte(v))
	}
	return b.Bytes()
}

func buildUint16ListExt(vals ...uint16) []byte {
	var b bytes.Buffer
	n := len(vals) * 2
	b.WriteByte(byte(n >> 8))
	b.WriteByte(byte(n))
	for _, v := range vals {
		b.WriteByte(byte(v >> 8))
		b.WriteByte(byte(v))
	}
	return b.Bytes()
}

func buildKeyShareExt(shares map[uint16]int, order []uint16) []byte {
	var inner bytes.Buffer
	for _, grp := range order {
		sz := shares[grp]
		inner.WriteByte(byte(grp >> 8))
		inner.WriteByte(byte(grp))
		inner.WriteByte(byte(sz >> 8))
		inner.WriteByte(byte(sz))
		inner.Write(bytes.Repeat([]byte{0x42}, sz))
	}
	var out bytes.Buffer
	out.WriteByte(byte(inner.Len() >> 8))
	out.WriteByte(byte(inner.Len()))
	out.Write(inner.Bytes())
	return out.Bytes()
}

func buildECHOuterExt(kdf, aead uint16, configID uint8, encLen, payloadLen int) []byte {
	var b bytes.Buffer
	b.WriteByte(0x00)
	b.Write([]byte{byte(kdf >> 8), byte(kdf), byte(aead >> 8), byte(aead), configID})
	b.Write([]byte{byte(encLen >> 8), byte(encLen)})
	b.Write(bytes.Repeat([]byte{0x11}, encLen))
	b.Write([]byte{byte(payloadLen >> 8), byte(payloadLen)})
	b.Write(bytes.Repeat([]byte{0x22}, payloadLen))
	return b.Bytes()
}

func TestGREASEDetectors(t *testing.T) {
	assert.True(t, IsTLSGREASE(0x0a0a))
	assert.True(t, IsTLSGREASE(0xfafa))
	assert.False(t, IsTLSGREASE(0x1301))
	assert.False(t, IsTLSGREASE(0x0a1a))

	assert.True(t, IsQUICTPGREASE(27))
	assert.True(t, IsQUICTPGREASE(27+31*5))
	assert.False(t, IsQUICTPGREASE(0x04))

	assert.True(t, IsQUICVersionGREASE(0x1a2a3a4a))
	assert.False(t, IsQUICVersionGREASE(QUICVersion1))

	assert.True(t, IsH3GREASE(0x21))
	assert.True(t, IsH3GREASE(0x21+0x1f*3))
	assert.False(t, IsH3GREASE(0x01))
}

func TestPostQuantumLargeFragmentedClientHelloAndPermutation(t *testing.T) {
	ciphers := []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f}
	sigAlgs := []uint16{0x0403, 0x0804, 0x0401}
	groups := []uint16{0x1a1a, GroupX25519MLKEM768, 0x001d, 0x0017}

	// Build a post-quantum ClientHello larger than 4096 bytes (simulating ML-KEM + large padding/PSK/ECH).
	extsOrder1 := []extSpec{
		{id: 0x2a2a, data: nil},
		{id: extServerName, data: buildSNIExt("api.example.com")},
		{id: extALPN, data: buildALPNExt("h2", "http/1.1")},
		{id: extSupportedVersions, data: buildSupportedVersionsExt(0x3a3a, 0x0304, 0x0303)},
		{id: extSignatureAlgorithms, data: buildUint16ListExt(sigAlgs...)},
		{id: extSupportedGroups, data: buildUint16ListExt(groups...)},
		{id: extECPointFormats, data: []byte{0x01, 0x00}},
		{id: extKeyShare, data: buildKeyShareExt(map[uint16]int{
			0x1a1a:              1,
			GroupX25519MLKEM768: 1216,
			0x001d:              32,
		}, []uint16{0x1a1a, GroupX25519MLKEM768, 0x001d})},
		{id: extCompressCertificate, data: []byte{0x02, 0x00, 0x02}},
		{id: extALPS, data: []byte{0x00, 0x03, 0x02, 'h', '2'}},
		{id: extDelegatedCredentials, data: []byte{0x00, 0x02, 0x04, 0x03}},
		{id: extPSKKeyExchangeModes, data: []byte{0x01, 0x01}},
		{id: extRecordSizeLimit, data: []byte{0x40, 0x01}},
		{id: extECH, data: buildECHOuterExt(0x0001, 0x0001, 42, 32, 176)},
		{id: extPadding, data: make([]byte, 3200)},
	}

	sessionID := bytes.Repeat([]byte{0xaa}, 32)
	body1 := buildClientHelloBody(0x0303, sessionID, ciphers, extsOrder1)
	require.Greater(t, len(body1), 4500)

	hs1 := wrapHandshakeMessage(tlsHandshakeClient, body1)
	// Fragment across 4 TLS 0x16 records of 1400 bytes each.
	records1 := wrapTLSRecords(0x0301, hs1, 1400)

	fp1 := NewConnData()
	reader := bytes.NewReader(records1)
	err := ReadClientHelloFromRecords(reader.Read, fp1)
	require.NoError(t, err)

	assert.Equal(t, uint16(0x0301), fp1.TLSRecordVersion)
	assert.Equal(t, uint16(0x0303), fp1.TLSHandshakeVersion)
	assert.Equal(t, uint8(4), fp1.TLSRecordFragments)
	assert.Equal(t, uint8(32), fp1.TLSSessionIDLen)
	assert.Equal(t, "api.example.com", fp1.ServerName)
	assert.Equal(t, []string{"h2", "http/1.1"}, fp1.ALPNProtos)
	assert.True(t, HasPostQuantumKeyShare(fp1.TLSKeyShareGroups))
	assert.Equal(t, []uint16{GroupX25519MLKEM768, 0x001d}, fp1.TLSKeyShareGroups)
	assert.Equal(t, []uint16{2}, fp1.TLSCertCompression)
	assert.Equal(t, extALPS, fp1.TLSALPS)
	assert.True(t, fp1.TLSHasDelegatedCred)
	assert.Equal(t, []uint8{1}, fp1.TLSPSKModes)
	assert.Equal(t, uint16(0x4001), fp1.TLSRecordSizeLimit)
	assert.Equal(t, 3200, fp1.TLSPaddingLen)
	assert.Equal(t, "0001-0001_id42_enc32_len176", fp1.TLSECHOuter)
	assert.True(t, strings.HasPrefix(fp1.JA4, "t13d0514h2_"))

	// Verify ComputeJA4FromHelloInfo produces the exact same JA4 string.
	extIDs := make([]uint16, 0, len(extsOrder1))
	for _, e := range extsOrder1 {
		extIDs = append(extIDs, e.id)
	}
	sigSchemes := make([]tls.SignatureScheme, 0, len(sigAlgs))
	for _, s := range sigAlgs {
		sigSchemes = append(sigSchemes, tls.SignatureScheme(s))
	}
	helloInfo := &tls.ClientHelloInfo{
		CipherSuites:      ciphers,
		ServerName:        "api.example.com",
		SupportedProtos:   []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{0x3a3a, 0x0304, 0x0303},
		SignatureSchemes:  sigSchemes,
		Extensions:        extIDs,
	}
	assert.Equal(t, fp1.JA4, ComputeJA4FromHelloInfo(helloInfo, false))

	// Shuffle extension order (Chrome 110+ permutation) and verify JA3 changes while JA3N and JA4 remain invariant.
	extsOrder2 := make([]extSpec, len(extsOrder1))
	copy(extsOrder2, extsOrder1)
	extsOrder2[1], extsOrder2[8] = extsOrder2[8], extsOrder2[1]
	extsOrder2[4], extsOrder2[10] = extsOrder2[10], extsOrder2[4]

	body2 := buildClientHelloBody(0x0303, sessionID, ciphers, extsOrder2)
	records2 := wrapTLSRecords(0x0301, wrapHandshakeMessage(tlsHandshakeClient, body2), 2048)

	fp2 := NewConnData()
	require.NoError(t, ParseClientHelloRecords(records2, fp2))

	assert.NotEqual(t, fp1.JA3, fp2.JA3)
	assert.Equal(t, fp1.JA3N, fp2.JA3N)
	assert.Equal(t, fp1.JA4, fp2.JA4)
}

func TestServerHelloAndHelloRetryRequest(t *testing.T) {
	var shBody bytes.Buffer
	shBody.Write([]byte{0x03, 0x03})
	shBody.Write(helloRetryRequestRandom[:])
	shBody.WriteByte(0x00)
	shBody.Write([]byte{0x13, 0x01})
	shBody.WriteByte(0x00)

	// Extensions: supported_versions (0x0304) and ALPN ("h2").
	var exts bytes.Buffer
	exts.Write([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
	alpn := buildALPNExt("h2")
	exts.Write([]byte{0x00, 0x10, byte(len(alpn) >> 8), byte(len(alpn))})
	exts.Write(alpn)

	shBody.Write([]byte{byte(exts.Len() >> 8), byte(exts.Len())})
	shBody.Write(exts.Bytes())

	rec := wrapTLSRecords(0x0303, wrapHandshakeMessage(tlsHandshakeServer, shBody.Bytes()), 1024)
	sh, isHRR, err := ParseServerHelloRecords(rec, false)
	require.NoError(t, err)
	assert.True(t, isHRR)
	assert.NotEmpty(t, sh.JA3S)
	assert.True(t, strings.HasPrefix(sh.JA4S, "t1302h2_1301_"))
}

func TestTruncatedAndMalformedTLSInputs(t *testing.T) {
	fp := NewConnData()
	assert.ErrorIs(t, ParseClientHelloRecords([]byte{0x16, 0x03}, fp), ErrIncompleteHandshake)
	assert.ErrorIs(t, ParseClientHelloRecords([]byte("GET / HTTP/1.1\r\n\r\n"), fp), ErrNotTLSHandshake)

	// Record declaring oversized length (> 16 KB).
	oversized := []byte{0x16, 0x03, 0x01, 0x50, 0x00}
	assert.ErrorIs(t, ParseClientHelloRecords(oversized, fp), ErrOversizedHandshake)

	// Truncated ClientHello body.
	assert.Error(t, ParseClientHelloBody([]byte{0x03, 0x03, 0x01}, false, fp))
}

func TestX509JA4XAndThumbprints(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			Country:      []string{"BR"},
			Organization: []string{"Traefik Labs"},
			CommonName:   "client.example.com",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	ja4x, certSHA, spkiSHA := ExtractClientCertInfo(cert)
	assert.Len(t, ja4x, 38)
	assert.Len(t, certSHA, 64)
	assert.Len(t, spkiSHA, 64)

	rfc9440 := FormatRFC9440Thumbprint(cert.Raw)
	assert.True(t, len(rfc9440) > 10 && rfc9440[0] == ':' && rfc9440[len(rfc9440)-1] == ':')
}
