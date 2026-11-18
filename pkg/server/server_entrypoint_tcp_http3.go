package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/fingerprint"
	tcpmuxer "github.com/traefik/traefik/v3/pkg/muxer/tcp"
	"github.com/traefik/traefik/v3/pkg/proxy/fast"
	tcprouter "github.com/traefik/traefik/v3/pkg/server/router/tcp"
	"github.com/traefik/traefik/v3/pkg/server/service/kerberos"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

type http3server struct {
	*http3.Server

	http3conn   net.PacketConn
	quicTracker *fingerprint.QUICTracker

	lock   sync.RWMutex
	getter func(data tcpmuxer.ConnData) (*tls.Config, string, error)
}

func newHTTP3Server(ctx context.Context, name string, config *static.EntryPoint, httpsServer *httpServer) (*http3server, error) {
	var conn net.PacketConn
	var err error

	if config.HTTP3 == nil {
		return nil, nil
	}

	if config.HTTP3.AdvertisedPort < 0 {
		return nil, errors.New("advertised port must be greater than or equal to zero")
	}

	// if we have predefined connections from socket activation
	if socketActivation.isEnabled() {
		conn, err = socketActivation.getConn(name)
		if err != nil {
			log.Ctx(ctx).Warn().Err(err).Str("name", name).Msg("Unable to use socket activation for entrypoint")
		}
	}

	if conn == nil {
		listenConfig := newListenConfig(config)
		conn, err = listenConfig.ListenPacket(ctx, "udp", config.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("starting listener: %w", err)
		}
	}

	var quicTracker *fingerprint.QUICTracker
	quicCfg := &quic.Config{
		Allow0RTT: false,
	}
	if config.Fingerprint != nil && config.Fingerprint.Enabled {
		quicTracker = fingerprint.NewQUICTracker()
		if config.Fingerprint.QUICInitialTapEnabled() {
			conn = quicTracker.WrapPacketConn(conn)
			quicCfg.Tracer = quicTracker.Tracer
		}
	}

	h3 := &http3server{
		http3conn:   conn,
		quicTracker: quicTracker,
		getter: func(data tcpmuxer.ConnData) (*tls.Config, string, error) {
			return nil, "", errors.New("no TLS config")
		},
	}

	handler := httpsServer.Server.(*http.Server).Handler
	if readTimeout := time.Duration(config.Transport.RespondingTimeouts.ReadTimeout); readTimeout != 0 {
		handler = withReadTimeout(ctx, handler, readTimeout)
	}

	h3.Server = &http3.Server{
		Addr:           config.GetAddress(),
		Port:           config.HTTP3.AdvertisedPort,
		Handler:        handler,
		TLSConfig:      &tls.Config{GetConfigForClient: h3.getTLSConfigForClient},
		MaxHeaderBytes: config.HTTP.MaxHeaderBytes,
		IdleTimeout:    time.Duration(config.Transport.RespondingTimeouts.IdleTimeout),
		QUICConfig:     quicCfg,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			// This adds an empty struct in order to store a RoundTripper in the ConnContext in case of Kerberos or NTLM.
			ctx = kerberos.AddTransportOnContext(ctx)
			// Same as above for the FastProxy connection pools, storing a dedicated pool in case of Kerberos or NTLM.
			ctx = fast.AddConnPoolsOnContext(ctx)

			// The dedicated round trippers and connection pools have to be released with the connection, whose context
			// is canceled on close.
			context.AfterFunc(c.Context(), func() {
				kerberos.ReleaseTransportOnContext(ctx)
				fast.ReleaseConnPoolsOnContext(ctx)
			})

			if trace, ok := c.QlogTrace().(*fingerprint.QUICTrace); ok {
				fpData := trace.ConnData()
				if fpData != nil {
					h3.populateQUICFallbackJA4(c, fpData)
					ctx = fingerprint.WithConnData(ctx, fpData)
				}
			} else if h3.quicTracker != nil {
				fpData := fingerprint.NewConnData()
				fpData.IsQUIC = true
				h3.populateQUICFallbackJA4(c, fpData)
				ctx = fingerprint.WithConnData(ctx, fpData)
			}

			tlsOptionsName, err := h3.getTLSOptionsName(c)
			if err != nil {
				log.Error().Msgf("Error getting TLS options name for client: %v", err)
				return ctx
			}

			return tcp.AddTLSOptionsNameInContext(ctx, tlsOptionsName)
		},
	}

	previousHandler := httpsServer.Server.(*http.Server).Handler

	httpsServer.Server.(*http.Server).Handler = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if err := h3.Server.SetQUICHeaders(rw.Header()); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("Failed to set HTTP3 headers")
		}

		previousHandler.ServeHTTP(rw, req)
	})

	return h3, nil
}

func withReadTimeout(ctx context.Context, next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// quic-go never leaves req.Body nil or equal to http.NoBody, so neither can be used to detect
		// an absent body. ContentLength is 0 only when the client declared no body, and -1 when the
		// length is unknown (no Content-Length header), both of which may still carry a body that
		// needs bounding.
		if req.ContentLength != 0 {
			deadline := time.Now().Add(timeout)
			if err := http.NewResponseController(rw).SetReadDeadline(deadline); err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("Failed to set HTTP3 read timeout")
			}
		}
		next.ServeHTTP(rw, req)
	})
}

func (e *http3server) Start() error {
	return e.Serve(e.http3conn)
}

func (e *http3server) Switch(rt *tcprouter.Router) {
	e.lock.Lock()
	defer e.lock.Unlock()

	e.getter = rt.HTTP3TLSConfigMatcherFunc()
}

func (e *http3server) Shutdown(_ context.Context) error {
	// TODO: use e.Server.CloseGracefully() when available.
	return e.Server.Close()
}

func (e *http3server) getTLSConfigForClient(info *tls.ClientHelloInfo) (*tls.Config, error) {
	if e.quicTracker != nil && info != nil && info.Conn != nil && info.Conn.RemoteAddr() != nil {
		ja4 := fingerprint.ComputeJA4FromHelloInfo(info, true)
		e.quicTracker.StoreFallbackJA4(info.Conn.RemoteAddr().String(), ja4)
	}

	e.lock.RLock()
	defer e.lock.RUnlock()

	connData, err := tcpmuxer.NewConnData(info.ServerName, info.Conn.RemoteAddr(), info.SupportedProtos)
	if err != nil {
		return nil, fmt.Errorf("creating ConnData from client hello: %w", err)
	}

	conf, _, err := e.getter(connData)
	return conf, err
}

func (e *http3server) getTLSOptionsName(c *quic.Conn) (string, error) {
	e.lock.RLock()
	defer e.lock.RUnlock()

	connData, err := tcpmuxer.NewConnData(c.ConnectionState().TLS.ServerName, c.RemoteAddr(), []string{c.ConnectionState().TLS.NegotiatedProtocol})
	if err != nil {
		return "", fmt.Errorf("creating ConnData from quic Conn: %w", err)
	}

	_, name, err := e.getter(connData)
	return name, err
}

func (e *http3server) populateQUICFallbackJA4(c *quic.Conn, fpData *fingerprint.ConnData) {
	if e.quicTracker == nil || c == nil || fpData == nil || c.RemoteAddr() == nil {
		return
	}
	remoteKey := c.RemoteAddr().String()
	fallbackJA4 := e.quicTracker.LoadFallbackJA4(remoteKey)
	if fallbackJA4 == "" {
		return
	}
	tlsState := c.ConnectionState().TLS
	fpData.Lock()
	if fpData.JA4 == "" {
		fpData.JA4 = fallbackJA4
	}
	if fpData.ServerName == "" {
		fpData.ServerName = tlsState.ServerName
	}
	if len(fpData.ALPNProtos) == 0 && tlsState.NegotiatedProtocol != "" {
		fpData.ALPNProtos = slices.Clone([]string{tlsState.NegotiatedProtocol})
	}
	fpData.Unlock()
}
