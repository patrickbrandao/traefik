package fingerprint

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// Header injection modes shared between static EntryPoints and dynamic Middlewares.
const (
	InjectModeCombined = "combined"
	InjectModeSplit    = "split"
	InjectModeBoth     = "both"
	InjectModeNone     = "none"
)

// Enforcement modes for the dynamic Fingerprint middleware.
const (
	ModeHeadersOnly = "headersOnly"
	ModeShadow      = "shadow"
	ModeEnforce     = "enforce"
)

// Action constants produced by the cross-layer risk evaluator.
const (
	ActionAllow     = "allow"
	ActionChallenge = "challenge"
	ActionBlock     = "block"
)

type (
	connDataKey       struct{}
	riskAssessmentKey struct{}
	upstreamFPKey     struct{}
)

// ConnData stores network, transport, TLS, QUIC, and initial HTTP framing signals for a single client connection.
// Concurrent mutations (such as asynchronous QUIC qlog events or post-TLS handshake timing) must guard access with mu.
type ConnData struct {
	mu sync.RWMutex

	// Per-connection capture toggles configured at EntryPoint acceptance.
	CaptureDeepTLS  bool
	CaptureHTTP2Tap bool

	// L3 / L4 signals from Linux TCP_SAVED_SYN, UDP OOB control messages, or PROXY Protocol v2 TLVs.
	IPTTL          uint8
	IPDontFragment bool
	IPECN          uint8
	JA4T           string
	TCPMSS         uint16
	TCPWScale      uint8
	TCPRTT         time.Duration
	UDPPayloadSize uint16
	ProxyProtoTLVs map[uint8][]byte

	// L4.5 QUIC signals from Initial packet decryption and in-memory qlog tracing.
	IsQUIC              bool
	QUICVersion         uint32
	QUICDCIDLen         uint8
	QUICSCIDLen         uint8
	QUICPacketNumLen    uint8
	QUICCoalesced0RTT   bool
	QUICInitialFrames   string
	QUICTransportParams string
	QUICHasGREASETP     bool
	QUICDisableMig      bool
	gQUICVersion        string

	// L5 TLS & Deep TLS signals.
	JA4                 string
	JA3                 string
	JA3N                string
	ServerName          string
	ALPNProtos          []string
	TLSRecordVersion    uint16
	TLSHandshakeVersion uint16
	TLSSessionIDLen     uint8
	TLSRecordFragments  uint8
	TLSKeyShareGroups   []uint16
	TLSCertCompression  []uint16
	TLSALPS             uint16
	TLSHasDelegatedCred bool
	TLSPSKModes         []uint8
	TLSRecordSizeLimit  uint16
	TLSPaddingLen       int
	TLSECHOuter         string
	TLSECHAccepted      bool
	TLSHandshakeRTT     time.Duration
	TLSHelloRetry       bool

	// L5 mTLS client certificate signals.
	JA4X          string
	ClientCertSHA string
	ClientSPKISHA string

	// L7 initial connection framing signals (HTTP/0.9, HTTP/1.x, HTTP/2, HTTP/3).
	HTTP09Raw           bool
	H1HeaderOrder       []string
	H1CasingProfile     string
	H1NonCanonicalCount int
	H1NoSpaceAfterColon bool
	H1BareLF            bool
	H1AbsoluteForm      bool
	AkamaiH2            string
	H2HasGREASE         bool
	H2Huffman           bool
	H2Indexed           bool
	H2HeaderOrder       []string
	H3UniStreams        string
	H3HasGREASE         bool
	H3Settings          string
	H3PseudoOrder       string
	H3HeaderOrder       []string
	LastJA4H            string
}

// NewConnData allocates a ConnData with default sentinel values.
func NewConnData() *ConnData {
	return &ConnData{
		CaptureDeepTLS:  true,
		CaptureHTTP2Tap: true,
		TLSPaddingLen:   -1,
	}
}

// Lock acquires the write lock for mutating ConnData fields concurrently.
func (d *ConnData) Lock() {
	if d != nil {
		d.mu.Lock()
	}
}

// Unlock releases the write lock on ConnData.
func (d *ConnData) Unlock() {
	if d != nil {
		d.mu.Unlock()
	}
}

// RLock acquires the read lock for reading ConnData fields concurrently.
func (d *ConnData) RLock() {
	if d != nil {
		d.mu.RLock()
	}
}

// RUnlock releases the read lock on ConnData.
func (d *ConnData) RUnlock() {
	if d != nil {
		d.mu.RUnlock()
	}
}

// GQUICVersion returns the detected legacy gQUIC version tag, if any.
func (d *ConnData) GQUICVersion() string {
	if d == nil {
		return ""
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.gQUICVersion
}

// RequestData holds per-request HTTP fingerprint and semantic metadata.
type RequestData struct {
	JA4H                string
	HTTPVersion         string
	IsWebSocket         bool
	IsGRPC              bool
	IsConnect           bool
	WebSocketExtensions string
	GRPCAcceptEncoding  string
}

// RiskAssessment holds the computed cross-layer risk score, triggered rule codes, and recommended action.
type RiskAssessment struct {
	Score   int
	Action  string
	Reasons []string
	RateKey string
}

// ServerHelloData holds passive TLS server fingerprint metadata extracted from an upstream ServerHello.
type ServerHelloData struct {
	Version          uint16
	SupportedVersion uint16
	CipherSuite      uint16
	Extensions       []uint16
	ALPN             string
	JA3S             string
	JA4S             string
}

// UpstreamData stores passive upstream server fingerprints observed during backend connection establishment.
type UpstreamData struct {
	mu   sync.RWMutex
	JA3S string
	JA4S string
}

// Set records the upstream JA3S and JA4S fingerprints in a thread-safe manner.
func (u *UpstreamData) Set(ja3s, ja4s string) {
	if u == nil {
		return
	}
	u.mu.Lock()
	u.JA3S = ja3s
	u.JA4S = ja4s
	u.mu.Unlock()
}

// Get returns the recorded upstream JA3S and JA4S fingerprints.
func (u *UpstreamData) Get() (ja3s, ja4s string) {
	if u == nil {
		return "", ""
	}
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.JA3S, u.JA4S
}

// Carrier is implemented by net.Conn wrappers that carry per-connection ConnData.
type Carrier interface {
	FingerprintData() *ConnData
}

// ConnUnwrapper is implemented by net.Conn wrappers that expose their underlying connection.
type ConnUnwrapper interface {
	UnwrapConn() net.Conn
}

// TLSUnwrapper is implemented by TLS connection wrappers so callers can access the underlying *tls.Conn without losing wrapper methods.
type TLSUnwrapper interface {
	UnwrapTLS() *tls.Conn
}

// ExtractConnData walks a net.Conn wrapper chain to find any attached *ConnData in O(1) without global maps.
func ExtractConnData(conn net.Conn) *ConnData {
	cur := conn
	for cur != nil {
		if carrier, ok := cur.(Carrier); ok {
			if data := carrier.FingerprintData(); data != nil {
				return data
			}
		}
		if tlsUnwrap, ok := cur.(TLSUnwrapper); ok {
			if tc := tlsUnwrap.UnwrapTLS(); tc != nil {
				cur = tc.NetConn()
				continue
			}
		}
		if tc, ok := cur.(*tls.Conn); ok {
			cur = tc.NetConn()
			continue
		}
		if unwrapper, ok := cur.(ConnUnwrapper); ok {
			next := unwrapper.UnwrapConn()
			if next != cur {
				cur = next
				continue
			}
		}
		if netConnGetter, ok := cur.(interface{ NetConn() net.Conn }); ok {
			next := netConnGetter.NetConn()
			if next != cur {
				cur = next
				continue
			}
		}
		break
	}
	return nil
}

// UnwrapTLSConn extracts the underlying *tls.Conn from either a raw *tls.Conn or a TLSUnwrapper.
func UnwrapTLSConn(conn net.Conn) (*tls.Conn, bool) {
	if conn == nil {
		return nil, false
	}
	if tc, ok := conn.(*tls.Conn); ok {
		return tc, true
	}
	if tu, ok := conn.(TLSUnwrapper); ok {
		if tc := tu.UnwrapTLS(); tc != nil {
			return tc, true
		}
	}
	return nil, false
}

// WithConnData attaches ConnData to ctx.
func WithConnData(ctx context.Context, data *ConnData) context.Context {
	if data == nil {
		return ctx
	}
	return context.WithValue(ctx, connDataKey{}, data)
}

// FromContext retrieves ConnData from ctx, returning nil when absent.
func FromContext(ctx context.Context) *ConnData {
	if ctx == nil {
		return nil
	}
	if data, ok := ctx.Value(connDataKey{}).(*ConnData); ok {
		return data
	}
	return nil
}

// WithRiskAssessment attaches a RiskAssessment to ctx.
func WithRiskAssessment(ctx context.Context, risk *RiskAssessment) context.Context {
	if risk == nil {
		return ctx
	}
	return context.WithValue(ctx, riskAssessmentKey{}, risk)
}

// RiskFromContext retrieves the RiskAssessment from ctx, returning nil when absent.
func RiskFromContext(ctx context.Context) *RiskAssessment {
	if ctx == nil {
		return nil
	}
	if risk, ok := ctx.Value(riskAssessmentKey{}).(*RiskAssessment); ok {
		return risk
	}
	return nil
}

// WithUpstreamData attaches an UpstreamData holder to ctx so upstream TLS dialers can report JA3S/JA4S.
func WithUpstreamData(ctx context.Context, data *UpstreamData) context.Context {
	if data == nil {
		return ctx
	}
	return context.WithValue(ctx, upstreamFPKey{}, data)
}

// UpstreamFromContext retrieves UpstreamData from ctx, returning nil when absent.
func UpstreamFromContext(ctx context.Context) *UpstreamData {
	if ctx == nil {
		return nil
	}
	if data, ok := ctx.Value(upstreamFPKey{}).(*UpstreamData); ok {
		return data
	}
	return nil
}
