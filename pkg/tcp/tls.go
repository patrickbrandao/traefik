package tcp

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/traefik/traefik/v3/pkg/fingerprint"
)

// TLSConn is a TLS connection that also carries the name of the TLS config used.
type TLSConn struct {
	WriteCloser

	TLSOptionsName string
}

// UnwrapConn exposes the underlying net.Conn so fingerprint metadata can be walked without global maps.
func (c TLSConn) UnwrapConn() net.Conn {
	return c.WriteCloser
}

// TLSHandler handles TLS connections.
type TLSHandler struct {
	Next           Handler
	Config         *tls.Config
	TLSOptionsName string
}

// ServeTCP terminates the TLS connection and attaches post-TLS handshake timing and framing taps when enabled.
func (t *TLSHandler) ServeTCP(conn WriteCloser) {
	rawTLS := tls.Server(TLSConn{WriteCloser: conn, TLSOptionsName: t.TLSOptionsName}, t.Config)
	fpData := fingerprint.ExtractConnData(conn)
	if fpData == nil {
		t.Next.ServeTCP(rawTLS)
		return
	}

	fpData.RLock()
	enableH2Tap := fpData.CaptureHTTP2Tap
	fpData.RUnlock()

	t.Next.ServeTCP(newFPTLSConn(rawTLS, fpData, enableH2Tap))
}

// fpTLSConn wraps *tls.Conn while satisfying net/http's structural TLS interfaces (ConnectionState and HandshakeContext)
// so HTTP/2 ALPN negotiation, post-TLS framing taps, and TLSOptionsName context propagation all work seamlessly.
type fpTLSConn struct {
	tlsConn *tls.Conn
	tapConn net.Conn
	fpData  *fingerprint.ConnData

	handshakeOnce sync.Once
	handshakeErr  error
}

func newFPTLSConn(tlsConn *tls.Conn, fpData *fingerprint.ConnData, enableH2Tap bool) *fpTLSConn {
	return &fpTLSConn{
		tlsConn: tlsConn,
		tapConn: fingerprint.WrapFirstFlightConn(tlsConn, fpData, enableH2Tap),
		fpData:  fpData,
	}
}

func (c *fpTLSConn) Read(b []byte) (int, error) {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return 0, err
	}
	return c.tapConn.Read(b)
}

func (c *fpTLSConn) Write(b []byte) (int, error) {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return 0, err
	}
	return c.tlsConn.Write(b)
}

func (c *fpTLSConn) Close() error {
	return c.tlsConn.Close()
}

func (c *fpTLSConn) CloseWrite() error {
	return c.tlsConn.CloseWrite()
}

func (c *fpTLSConn) LocalAddr() net.Addr {
	return c.tlsConn.LocalAddr()
}

func (c *fpTLSConn) RemoteAddr() net.Addr {
	return c.tlsConn.RemoteAddr()
}

func (c *fpTLSConn) SetDeadline(t time.Time) error {
	return c.tlsConn.SetDeadline(t)
}

func (c *fpTLSConn) SetReadDeadline(t time.Time) error {
	return c.tlsConn.SetReadDeadline(t)
}

func (c *fpTLSConn) SetWriteDeadline(t time.Time) error {
	return c.tlsConn.SetWriteDeadline(t)
}

func (c *fpTLSConn) ConnectionState() tls.ConnectionState {
	return c.tlsConn.ConnectionState()
}

func (c *fpTLSConn) HandshakeContext(ctx context.Context) error {
	c.handshakeOnce.Do(func() {
		start := time.Now()
		c.handshakeErr = c.tlsConn.HandshakeContext(ctx)
		elapsed := time.Since(start)
		if c.handshakeErr == nil && c.fpData != nil {
			state := c.tlsConn.ConnectionState()
			c.fpData.Lock()
			c.fpData.TLSHandshakeRTT = elapsed
			if state.ECHAccepted {
				c.fpData.TLSECHAccepted = true
			}
			c.fpData.Unlock()

			if tcpConn := findUnderlyingTCPConn(c.tlsConn.NetConn()); tcpConn != nil {
				fingerprint.CaptureTCPInfoRTT(tcpConn, c.fpData)
			}
		}
	})
	return c.handshakeErr
}

func (c *fpTLSConn) UnwrapTLS() *tls.Conn {
	return c.tlsConn
}

func (c *fpTLSConn) NetConn() net.Conn {
	return c.tlsConn.NetConn()
}

func (c *fpTLSConn) FingerprintData() *fingerprint.ConnData {
	return c.fpData
}

func (c *fpTLSConn) UnwrapConn() net.Conn {
	return c.tlsConn.NetConn()
}

func findUnderlyingTCPConn(conn net.Conn) *net.TCPConn {
	cur := conn
	for cur != nil {
		if tc, ok := cur.(*net.TCPConn); ok {
			return tc
		}
		if cu, ok := cur.(fingerprint.ConnUnwrapper); ok {
			next := cu.UnwrapConn()
			if next != cur {
				cur = next
				continue
			}
		}
		break
	}
	return nil
}

type tlsOptionsNameKey struct{}

func AddTLSOptionsNameInContext(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, tlsOptionsNameKey{}, name)
}

func GetTLSOptionsName(ctx context.Context) string {
	if name, ok := ctx.Value(tlsOptionsNameKey{}).(string); ok {
		return name
	}

	return ""
}
