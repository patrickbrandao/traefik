package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/fingerprint"
	"github.com/traefik/traefik/v3/pkg/middlewares/accesslog"
	"github.com/traefik/traefik/v3/pkg/middlewares/capture"
	"github.com/traefik/traefik/v3/pkg/middlewares/observability"
	otypes "github.com/traefik/traefik/v3/pkg/observability/types"
	tcprouter "github.com/traefik/traefik/v3/pkg/server/router/tcp"
	"github.com/traefik/traefik/v3/pkg/server/service"
	"github.com/traefik/traefik/v3/pkg/tcp"
	"github.com/traefik/traefik/v3/pkg/types"
)

func TestEntryPointEndToEndFingerprintingH1H2H3(t *testing.T) {
	certContent, err := localhostCert.Read()
	require.NoError(t, err)

	keyContent, err := localhostKey.Read()
	require.NoError(t, err)

	tlsCert, err := tls.X509KeyPair(certContent, keyContent)
	require.NoError(t, err)

	epTransport := &static.EntryPointsTransport{}
	epTransport.SetDefaults()

	fpCfg := &static.FingerprintConfig{
		Enabled:           true,
		InjectHeadersMode: fingerprint.InjectModeBoth,
		HMACSecretURN:     "ep-hmac-secret",
	}
	fpCfg.SetDefaults()
	fpCfg.InjectHeadersMode = fingerprint.InjectModeBoth

	epCfg := &static.EntryPoint{
		Address:          "127.0.0.1:0",
		Transport:        epTransport,
		ForwardedHeaders: &static.ForwardedHeaders{},
		HTTP: static.HTTPConfig{
			AliasHeadersStrategy: static.AliasHeadersStrategyReject,
		},
		HTTP2:       &static.HTTP2Config{},
		HTTP3:       &static.HTTP3Config{},
		Fingerprint: fpCfg,
	}
	epCfg.HTTP.SetDefaults()
	epCfg.HTTP2.SetDefaults()

	// Bind an ephemeral TCP port first so UDP HTTP/3 shares the exact same port.
	lc := newListenConfig(epCfg)
	tmpLn, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	boundAddr := tmpLn.Addr().String()
	_ = tmpLn.Close()
	epCfg.Address = boundAddr

	entryPoint, err := NewTCPEntryPoint(t.Context(), "websecure", epCfg, nil, nil)
	require.NoError(t, err)

	var (
		mu          sync.Mutex
		lastHeaders http.Header
		lastTLSOpt  string
		lastHasTLS  bool
	)

	echoHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		mu.Lock()
		lastHeaders = req.Header.Clone()
		lastTLSOpt = tcp.GetTLSOptionsName(req.Context())
		lastHasTLS = req.TLS != nil
		mu.Unlock()
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok"))
	})

	router, err := tcprouter.NewRouter(nil)
	require.NoError(t, err)

	router.AddHTTPTLSConfig("example.com", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
	}, "custom-tls-opt")
	router.SetHTTPHandler(echoHandler)
	router.SetHTTPSHandler(echoHandler, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
	})

	ctx := t.Context()
	go entryPoint.Start(ctx)
	entryPoint.SwitchRouter(router)
	t.Cleanup(func() {
		entryPoint.Shutdown(ctx)
	})

	time.Sleep(300 * time.Millisecond)

	// 1. Cleartext HTTP/1.1: verify anti-spoofing, JA4H, and HMAC signature.
	reqH1, err := http.NewRequest(http.MethodGet, "http://"+boundAddr+"/hello", nil)
	require.NoError(t, err)
	reqH1.Host = "example.com"
	reqH1.Header.Set(fingerprint.HeaderJA4, "spoofed-ja4")
	reqH1.Header.Set("Accept-Language", "en-US,en;q=0.9")

	respH1, err := http.DefaultClient.Do(reqH1)
	require.NoError(t, err)
	_ = respH1.Body.Close()
	assert.Equal(t, http.StatusOK, respH1.StatusCode)

	mu.Lock()
	h1Headers := lastHeaders.Clone()
	mu.Unlock()
	assert.Empty(t, h1Headers.Get(fingerprint.HeaderJA4))
	assert.True(t, strings.HasPrefix(h1Headers.Get(fingerprint.HeaderJA4H), "ge11nn"))
	assert.NotEmpty(t, h1Headers.Get(fingerprint.HeaderClientFP))
	assert.NotEmpty(t, h1Headers.Get(fingerprint.HeaderSignature))

	// 2. HTTPS HTTP/2: verify fpTLSConn, TLSOptionsName, JA4 (t13...), JA3N, Deep TLS, and Akamai H2.
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certContent)

	h2Transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    certPool,
			ServerName: "example.com",
			NextProtos: []string{"h2"},
		},
		ForceAttemptHTTP2: true,
	}
	defer h2Transport.CloseIdleConnections()

	h2Client := &http.Client{Transport: h2Transport}
	reqH2, err := http.NewRequest(http.MethodGet, "https://"+boundAddr+"/h2-check", nil)
	require.NoError(t, err)
	reqH2.Host = "example.com"

	respH2, err := h2Client.Do(reqH2)
	require.NoError(t, err)
	_ = respH2.Body.Close()
	assert.Equal(t, http.StatusOK, respH2.StatusCode)
	assert.Equal(t, 2, respH2.ProtoMajor)

	mu.Lock()
	h2Headers := lastHeaders.Clone()
	h2TLSOpt := lastTLSOpt
	h2HasTLS := lastHasTLS
	mu.Unlock()

	assert.True(t, h2HasTLS)
	assert.Equal(t, "custom-tls-opt", h2TLSOpt)
	assert.True(t, strings.HasPrefix(h2Headers.Get(fingerprint.HeaderJA4), "t13d"))
	assert.Len(t, h2Headers.Get(fingerprint.HeaderJA3N), 32)
	assert.NotEmpty(t, h2Headers.Get(fingerprint.HeaderTLSDeep))
	assert.NotEmpty(t, h2Headers.Get(fingerprint.HeaderH2))
	assert.True(t, strings.HasPrefix(h2Headers.Get(fingerprint.HeaderJA4H), "ge20"))

	// 3. HTTP/3 over QUIC: verify PacketConn Initial decrypt + qlog Tracer + JA4 (q13...h3) + H3 framing.
	h3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    certPool,
			ServerName: "example.com",
			NextProtos: []string{"h3"},
		},
	}
	defer func() { _ = h3Transport.Close() }()

	h3Client := &http.Client{Transport: h3Transport}
	reqH3, err := http.NewRequest(http.MethodGet, "https://"+boundAddr+"/h3-check", nil)
	require.NoError(t, err)
	reqH3.Host = "example.com"

	respH3, err := h3Client.Do(reqH3)
	require.NoError(t, err)
	_ = respH3.Body.Close()
	assert.Equal(t, http.StatusOK, respH3.StatusCode)
	assert.Equal(t, 3, respH3.ProtoMajor)

	mu.Lock()
	h3Headers := lastHeaders.Clone()
	h3TLSOpt := lastTLSOpt
	mu.Unlock()

	assert.Equal(t, "custom-tls-opt", h3TLSOpt)
	assert.True(t, strings.HasPrefix(h3Headers.Get(fingerprint.HeaderJA4), "q13d"))
	assert.NotEmpty(t, h3Headers.Get(fingerprint.HeaderQUIC))
	assert.NotEmpty(t, h3Headers.Get(fingerprint.HeaderH3))
	assert.True(t, strings.HasPrefix(h3Headers.Get(fingerprint.HeaderJA4H), "ge30"))
}

func TestAccessLogAndUpstreamServerHelloFingerprinting(t *testing.T) {
	certContent, err := localhostCert.Read()
	require.NoError(t, err)
	keyContent, err := localhostKey.Read()
	require.NoError(t, err)
	tlsCert, err := tls.X509KeyPair(certContent, keyContent)
	require.NoError(t, err)

	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("upstream-ok"))
	}))
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	backend.StartTLS()
	defer backend.Close()

	tm := service.NewTransportManager(nil)
	tm.Update(map[string]*dynamic.ServersTransport{
		"fp-upstream": {
			InsecureSkipVerify:       true,
			RootCAs:                  []types.FileOrContent{localhostCert},
			CaptureServerFingerprint: true,
		},
	})
	rt, err := tm.GetRoundTripper("fp-upstream")
	require.NoError(t, err)

	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	proxy.Transport = rt

	logPath := filepath.Join(t.TempDir(), "access.json")
	alCfg := &otypes.AccessLog{
		FilePath: logPath,
		Format:   accesslog.JSONFormat,
	}
	alCfg.SetDefaults()
	alCfg.FilePath = logPath
	alCfg.Format = accesslog.JSONFormat

	alHandler, err := accesslog.NewHandler(t.Context(), alCfg)
	require.NoError(t, err)
	defer func() { _ = alHandler.Close() }()

	chainHandler, err := capture.Wrap(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		alHandler.ServeHTTP(rw, req, proxy)
	}))
	require.NoError(t, err)

	fpData := fingerprint.NewConnData()
	fpData.JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	fpData.JA3N = "0123456789abcdef0123456789abcdef"
	fpData.AkamaiH2 = "1:65536|15663105|0|m,a,s,p"

	req := httptest.NewRequest(http.MethodGet, "https://example.com/proxy-test", nil)
	ctx := observability.WithObservability(req.Context(), observability.Observability{AccessLogsEnabled: true})
	ctx = fingerprint.WithConnData(ctx, fpData)
	ctx = fingerprint.WithRiskAssessment(ctx, &fingerprint.RiskAssessment{Score: 12, Action: fingerprint.ActionAllow})
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	chainHandler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	logBytes, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.NotEmpty(t, bytes.TrimSpace(logBytes))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(logBytes), &parsed))
	assert.Equal(t, fpData.JA4, parsed[accesslog.ClientJA4])
	assert.Equal(t, fpData.JA3N, parsed[accesslog.ClientJA3N])
	assert.Equal(t, fpData.AkamaiH2, parsed[accesslog.ClientH2FP])
	assert.NotEmpty(t, parsed[accesslog.ClientJA4H])
	assert.InDelta(t, 12.0, parsed[accesslog.ClientRiskScore], 0.001)
	assert.NotEmpty(t, parsed[accesslog.UpstreamJA3S])
	assert.NotEmpty(t, parsed[accesslog.UpstreamJA4S])
}
