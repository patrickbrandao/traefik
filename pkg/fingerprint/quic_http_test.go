package fingerprint

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/quic-go/quic-go"
	http3qlog "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func encryptQUICInitialForTest(t *testing.T, version uint32, dcid, scid []byte, pn uint32, plaintext []byte) []byte {
	t.Helper()

	var (
		salt      []byte
		keyLabel  string
		ivLabel   string
		hpLabel   string
		firstByte byte
	)
	switch version {
	case QUICVersion1:
		salt = quicV1InitialSalt
		keyLabel = "quic key"
		ivLabel = "quic iv"
		hpLabel = "quic hp"
		firstByte = 0xc1 // Long Header, Initial (0x00), 2-byte PN (0x01).
	case QUICVersion2:
		salt = quicV2InitialSalt
		keyLabel = "quicv2 key"
		ivLabel = "quicv2 iv"
		hpLabel = "quicv2 hp"
		firstByte = 0xd1 // Long Header, v2 Initial (0x01), 2-byte PN (0x01).
	default:
		t.Fatalf("unsupported QUIC version: %x", version)
	}

	initSec, err := hkdf.Extract(sha256.New, dcid, salt)
	require.NoError(t, err)
	cliSec, err := hkdfExpandLabel(initSec, "client in", 32)
	require.NoError(t, err)
	key, err := hkdfExpandLabel(cliSec, keyLabel, 16)
	require.NoError(t, err)
	iv, err := hkdfExpandLabel(cliSec, ivLabel, 12)
	require.NoError(t, err)
	hpKey, err := hkdfExpandLabel(cliSec, hpLabel, 16)
	require.NoError(t, err)

	var hdr bytes.Buffer
	hdr.WriteByte(firstByte)
	var vBuf [4]byte
	binary.BigEndian.PutUint32(vBuf[:], version)
	hdr.Write(vBuf[:])
	hdr.WriteByte(byte(len(dcid)))
	hdr.Write(dcid)
	hdr.WriteByte(byte(len(scid)))
	hdr.Write(scid)
	hdr.WriteByte(0x00) // Token length = 0.

	payloadLen := 2 + len(plaintext) + 16
	hdr.Write(encodeQUICVarint2B(uint16(payloadLen)))

	pnOffset := hdr.Len()
	hdr.WriteByte(byte(pn >> 8))
	hdr.WriteByte(byte(pn))

	aad := append([]byte(nil), hdr.Bytes()...)

	var nonce [12]byte
	copy(nonce[:], iv)
	var pnBytes [8]byte
	binary.BigEndian.PutUint64(pnBytes[:], uint64(pn))
	for i := range 8 {
		nonce[4+i] ^= pnBytes[i]
	}

	aesBlock, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(aesBlock)
	require.NoError(t, err)
	ciphertext := gcm.Seal(nil, nonce[:], plaintext, aad)

	pkt := make([]byte, 0, len(aad)+len(ciphertext))
	pkt = append(pkt, aad...)
	pkt = append(pkt, ciphertext...)
	sampleOffset := pnOffset + 4
	hpBlock, err := aes.NewCipher(hpKey)
	require.NoError(t, err)
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[sampleOffset:sampleOffset+16])

	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOffset] ^= mask[1]
	pkt[pnOffset+1] ^= mask[2]
	return pkt
}

func encodeQUICVarint2B(v uint16) []byte {
	return []byte{0x40 | byte(v>>8), byte(v)}
}

func encodeCRYPTOFrame(offset uint16, data []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x06)
	b.Write(encodeQUICVarint2B(offset))
	b.Write(encodeQUICVarint2B(uint16(len(data))))
	b.Write(data)
	return b.Bytes()
}

func TestQUICInitialDecryptFragmentedReassemblyAndQlog(t *testing.T) {
	// Build QUIC Transport Parameters extension (0x0039) with initial_max_data (0x04=1048576) + GREASE TP (27) + disable_active_migration (0x0c).
	var tp bytes.Buffer
	tp.WriteByte(0x04)
	tp.WriteByte(0x04)
	tp.Write([]byte{0x80, 0x10, 0x00, 0x00})
	tp.WriteByte(27)
	tp.WriteByte(0x01)
	tp.WriteByte(0xff)
	tp.WriteByte(0x0c)
	tp.WriteByte(0x00)

	exts := []extSpec{
		{id: extServerName, data: buildSNIExt("quic.example.com")},
		{id: extALPN, data: buildALPNExt("h3")},
		{id: extSupportedVersions, data: buildSupportedVersionsExt(0x0304)},
		{id: extSignatureAlgorithms, data: buildUint16ListExt(0x0403, 0x0804)},
		{id: extKeyShare, data: buildKeyShareExt(map[uint16]int{GroupX25519MLKEM768: 1216, 0x001d: 32}, []uint16{GroupX25519MLKEM768, 0x001d})},
		{id: extQUICTransportParams, data: tp.Bytes()},
	}
	chBody := buildClientHelloBody(0x0303, nil, []uint16{0x1301, 0x1302, 0x1303}, exts)
	chHandshake := wrapHandshakeMessage(tlsHandshakeClient, chBody)
	require.Greater(t, len(chHandshake), 1250)

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x01, 0x02, 0x03, 0x04}

	// Split CRYPTO across 2 UDP datagrams and send them out of order (packet 2 first, packet 1 second)!
	splitAt := 900
	framePart1 := append(encodeCRYPTOFrame(0, chHandshake[:splitAt]), make([]byte, 300)...)
	framePart2 := append([]byte{0x01}, encodeCRYPTOFrame(uint16(splitAt), chHandshake[splitAt:])...)
	framePart2 = append(framePart2, make([]byte, 400)...)

	pkt1 := encryptQUICInitialForTest(t, QUICVersion1, dcid, scid, 1, framePart1)
	pkt2 := encryptQUICInitialForTest(t, QUICVersion1, dcid, scid, 2, framePart2)

	tracker := NewQUICTracker()
	// Simulate Datagram 2 arriving first, quic-go calling Tracer, and Datagram 1 completing reassembly.
	tracker.InspectDatagram(pkt2, 57, 2)
	connID := quic.ConnectionIDFromBytes(dcid)
	tr := tracker.Tracer(t.Context(), false, connID)
	require.NotNil(t, tr)

	tracker.InspectDatagram(pkt1, 57, 2)

	qt, ok := tr.(*QUICTrace)
	require.True(t, ok)
	fp := qt.ConnData()
	require.NotNil(t, fp)

	assert.True(t, fp.IsQUIC)
	assert.Equal(t, QUICVersion1, fp.QUICVersion)
	assert.Equal(t, uint8(8), fp.QUICDCIDLen)
	assert.Equal(t, uint8(57), fp.IPTTL)
	assert.Equal(t, uint8(2), fp.IPECN)
	assert.Equal(t, "PING,CRYPTO,PADDING", fp.QUICInitialFrames)
	assert.True(t, strings.HasPrefix(fp.JA4, "q13d0306h3_"))
	assert.True(t, fp.QUICHasGREASETP)
	assert.True(t, fp.QUICDisableMig)
	assert.Contains(t, fp.QUICTransportParams, "4:1048576")
	assert.True(t, HasPostQuantumKeyShare(fp.TLSKeyShareGroups))

	// Feed HTTP/3 qlog events and confirm traceDone short-circuits afterward.
	rec := tr.AddProducer()
	rec.RecordEvent(http3qlog.StreamTypeSet{
		Initiator:  http3qlog.InitiatorRemote,
		StreamType: http3qlog.StreamTypeControl,
	})
	rec.RecordEvent(http3qlog.StreamTypeSet{
		Initiator:       http3qlog.InitiatorRemote,
		StreamType:      http3qlog.StreamTypeUnknown,
		StreamTypeBytes: 0x21,
	})
	rec.RecordEvent(http3qlog.FrameParsed{
		Frame: http3qlog.Frame{
			Frame: http3qlog.SettingsFrame{
				MaxFieldSectionSize: 65536,
				Datagram:            1,
				ExtendedConnect:     1,
				Other:               map[uint64]uint64{0x01: 16384, 0x21: 999},
			},
		},
	})
	rec.RecordEvent(http3qlog.FrameParsed{
		Frame: http3qlog.Frame{
			Frame: http3qlog.HeadersFrame{
				HeaderFields: []http3qlog.HeaderField{
					{Name: ":method", Value: "GET"},
					{Name: ":authority", Value: "quic.example.com"},
					{Name: ":scheme", Value: "https"},
					{Name: ":path", Value: "/"},
					{Name: "user-agent", Value: "Mozilla/5.0 Chrome/131.0"},
					{Name: "accept-language", Value: "pt-BR"},
				},
			},
		},
	})

	assert.True(t, qt.traceDone.Load())
	assert.Equal(t, "0,grease", fp.H3UniStreams)
	assert.True(t, fp.H3HasGREASE)
	assert.Equal(t, "m,a,s,p", fp.H3PseudoOrder)
	assert.Equal(t, []string{"user-agent", "accept-language"}, fp.H3HeaderOrder)
	assert.Equal(t, "1:16384;6:65536;8:1;33:1", fp.H3Settings)

	// Ensure QUIC v2 Initial decryption also works.
	dcidV2 := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}
	v2Payload := append(encodeCRYPTOFrame(0, chHandshake[:400]), make([]byte, 800)...)
	pktV2 := encryptQUICInitialForTest(t, QUICVersion2, dcidV2, nil, 1, v2Payload)
	tracker.InspectDatagram(pktV2, 64, 0)
	trV2 := tracker.Tracer(t.Context(), false, quic.ConnectionIDFromBytes(dcidV2)).(*QUICTrace)
	assert.Equal(t, QUICVersion2, trV2.ConnData().QUICVersion)

	// Confirm ParametersSet fallback works when Initial did not carry 0x0039.
	freshTrace := NewQUICTrace(nil)
	freshRec := freshTrace.AddProducer()
	freshRec.RecordEvent(qlog.ParametersSet{
		Initiator:              qlog.InitiatorRemote,
		MaxIdleTimeout:         30 * time.Second,
		InitialMaxData:         1048576,
		DisableActiveMigration: true,
	})
	assert.Contains(t, freshTrace.ConnData().QUICTransportParams, "1:30000")
	assert.True(t, freshTrace.ConnData().QUICDisableMig)
}

func TestParseRawSYNIPv4AndIPv6(t *testing.T) {
	// IPv4 header (20B, TTL=54, DF=1, ECN=2) + TCP SYN (Window=65535, Options: MSS=1460, NOP, WScale=8, 2xNOP, TS, SACKPerm, EOL).
	ipv4Hdr := []byte{
		0x45, 0x02, 0x00, 0x3c,
		0x12, 0x34, 0x40, 0x00,
		54, 6, 0x00, 0x00,
		192, 0, 2, 1,
		198, 51, 100, 1,
	}
	tcpOpts := []byte{
		2, 4, 0x05, 0xb4, // MSS 1460
		1,       // NOP
		3, 3, 8, // WScale 8
		1, 1, // NOP, NOP
		8, 10, 0, 0, 0, 1, 0, 0, 0, 0, // Timestamps
		4, 2, // SACK Permitted
		0, 0, // EOL + padding
	}
	dataOff := byte(((20 + len(tcpOpts)) / 4) << 4)
	tcpHdr := make([]byte, 20)
	tcpHdr[12] = dataOff
	tcpHdr[13] = 0x02
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)

	rawSYN := append(append([]byte(nil), ipv4Hdr...), tcpHdr...)
	rawSYN = append(rawSYN, tcpOpts...)

	fp := NewConnData()
	require.True(t, ParseRawSYN(rawSYN, fp))
	assert.Equal(t, uint8(54), fp.IPTTL)
	assert.True(t, fp.IPDontFragment)
	assert.Equal(t, uint8(2), fp.IPECN)
	assert.Equal(t, uint16(1460), fp.TCPMSS)
	assert.Equal(t, uint8(8), fp.TCPWScale)
	assert.Equal(t, "65535_2-1-3-1-1-8-4-0_1460_8", fp.JA4T)

	// IPv6 header (40B) + Hop-by-Hop extension (8B) + TCP SYN.
	ipv6Hdr := make([]byte, 40)
	ipv6Hdr[0] = 0x60
	ipv6Hdr[1] = 0x30 // ECN = 3
	ipv6Hdr[6] = 0    // Hop-by-Hop ext header
	ipv6Hdr[7] = 61   // Hop Limit = 61
	extHdr := []byte{6, 0, 0, 0, 0, 0, 0, 0}

	rawSYNV6 := append(append(ipv6Hdr, extHdr...), tcpHdr...)
	rawSYNV6 = append(rawSYNV6, tcpOpts...)
	fp6 := NewConnData()
	require.True(t, ParseRawSYN(rawSYNV6, fp6))
	assert.Equal(t, uint8(61), fp6.IPTTL)
	assert.Equal(t, uint8(3), fp6.IPECN)
	assert.Equal(t, "65535_2-1-3-1-1-8-4-0_1460_8", fp6.JA4T)
}

func TestCaptureProxyProtoTLVs(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	tlvs := []proxyproto.TLV{
		{Type: proxyproto.PP2_TYPE_ALPN, Value: []byte("h2")},
		{Type: proxyproto.PP2_TYPE_AUTHORITY, Value: []byte("edge.example.com")},
		{Type: proxyproto.PP2Type(TLVTypeCustomJA4T), Value: []byte("65535_2-4-8-1-3_1460_8")},
		{Type: proxyproto.PP2Type(TLVTypeCustomIPTTL), Value: []byte{120}},
	}

	hdr := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr:        &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
		DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443},
	}
	require.NoError(t, hdr.SetTLVs(tlvs))

	go func() {
		_, _ = hdr.WriteTo(c1)
		_, _ = c1.Write([]byte("ping"))
	}()

	ppConn := proxyproto.NewConn(c2)
	fp := NewConnData()
	wrapped := WrapConn(ppConn, fp)

	CaptureProxyProtoTLVs(wrapped, fp)
	assert.Equal(t, []string{"h2"}, fp.ALPNProtos)
	assert.Equal(t, "edge.example.com", fp.ServerName)
	assert.Equal(t, "65535_2-4-8-1-3_1460_8", fp.JA4T)
	assert.Equal(t, uint8(120), fp.IPTTL)
	assert.Len(t, fp.ProxyProtoTLVs, 4)
}

func TestHTTP1ScannerHTTP09AndJA4H(t *testing.T) {
	// HTTP/0.9 bare LF detection.
	fp09 := NewConnData()
	assert.True(t, ScanHTTP1FirstFlight([]byte("GET /legacy\n"), fp09))
	assert.True(t, fp09.HTTP09Raw)
	assert.True(t, fp09.H1BareLF)

	// HTTP/1.1 syntax anomalies (lowercase headers, no space after colon, absolute-form).
	rawH1 := "GET http://example.com/login HTTP/1.1\r\n" +
		"host: example.com\r\n" +
		"sec-ch-ua:\"Chromium\";v=\"131\"\r\n" +
		"user-agent: Mozilla/5.0\r\n" +
		"accept-language: pt-BR,pt;q=0.9\r\n" +
		"cookie: z=2; a=1\r\n\r\n"
	fp1 := NewConnData()
	assert.True(t, ScanHTTP1FirstFlight([]byte(rawH1), fp1))
	assert.False(t, fp1.HTTP09Raw)
	assert.True(t, fp1.H1AbsoluteForm)
	assert.True(t, fp1.H1NoSpaceAfterColon)
	assert.Equal(t, "lower", fp1.H1CasingProfile)
	assert.Equal(t, 5, fp1.H1NonCanonicalCount)
	assert.Equal(t, []string{"host", "sec-ch-ua", "user-agent", "accept-language", "cookie"}, fp1.H1HeaderOrder)

	req := httptest.NewRequest(http.MethodGet, "https://example.com/login", nil)
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="131"`)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9")
	req.Header.Add("Cookie", "z=2; a=1")

	ja4hFull := ComputeJA4H(req, fp1, false, "")
	assert.True(t, strings.HasPrefix(ja4hFull, "ge11cn04ptbr_"))
	assert.NotContains(t, ja4hFull, "_000000000000")

	ja4hRedacted := ComputeJA4H(req, fp1, true, "")
	assert.True(t, strings.HasSuffix(ja4hRedacted, "_000000000000"))
}

func TestH2FirstFlightTapAkamaiFingerprint(t *testing.T) {
	var wire bytes.Buffer
	wire.WriteString(http2.ClientPreface)

	fr := http2.NewFramer(&wire, nil)
	require.NoError(t, fr.WriteSettings(
		http2.Setting{ID: http2.SettingID(0x0a0a), Val: 0},
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	))
	require.NoError(t, fr.WriteWindowUpdate(0, 15663105))

	var hpackBuf bytes.Buffer
	enc := hpack.NewEncoder(&hpackBuf)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/app"},
		{Name: "sec-ch-ua", Value: `"Chromium";v="131"`},
		{Name: "user-agent", Value: "Mozilla/5.0 Chrome/131.0"},
	} {
		require.NoError(t, enc.WriteField(hf))
	}
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hpackBuf.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}))
	wire.WriteString("SUBSEQUENT_STREAM_BYTES")

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	fp := NewConnData()
	tap := WrapFirstFlightConn(c2, fp, true)

	// Write in small fragmented chunks to verify incremental framing assembly and zero byte loss.
	payload := wire.Bytes()
	go func() {
		for pos := 0; pos < len(payload); pos += 19 {
			end := min(pos+19, len(payload))
			_, _ = c1.Write(payload[pos:end])
		}
		_ = c1.Close()
	}()

	var received bytes.Buffer
	buf := make([]byte, 32)
	for {
		n, err := tap.Read(buf)
		if n > 0 {
			received.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	assert.Equal(t, payload, received.Bytes())
	assert.Equal(t, "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", fp.AkamaiH2)
	assert.True(t, fp.H2HasGREASE)
	assert.True(t, fp.H2Indexed)
	assert.True(t, fp.H2Huffman)
	assert.Equal(t, []string{"sec-ch-ua", "user-agent"}, fp.H2HeaderOrder)
}
