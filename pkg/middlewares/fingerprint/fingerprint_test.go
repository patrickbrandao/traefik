package fingerprint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	fp "github.com/traefik/traefik/v3/pkg/fingerprint"
)

func TestMiddlewareHeadersOnlyAndSpoofingProtection(t *testing.T) {
	var capturedHeader http.Header
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		capturedHeader = req.Header.Clone()
		rw.WriteHeader(http.StatusOK)
	})

	cfg := dynamic.Fingerprint{
		InjectHeadersMode: fp.InjectModeBoth,
		HMACSecret:        "test-hmac-key",
		Mode:              fp.ModeHeadersOnly,
	}
	mw, err := New(t.Context(), next, cfg, "fp-test")
	require.NoError(t, err)

	connData := fp.NewConnData()
	connData.JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	connData.AkamaiH2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(77),
		Subject:      pkix.Name{CommonName: "mtls-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1/profile", nil)
	req.ProtoMajor = 2
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	req.Header.Set(fp.HeaderJA4, "evil-spoofed-ja4")
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/131.0.0.0")
	req = req.WithContext(fp.WithConnData(req.Context(), connData))

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, connData.JA4, capturedHeader.Get(fp.HeaderJA4))
	assert.NotEmpty(t, capturedHeader.Get(fp.HeaderClientFP))
	assert.NotEmpty(t, capturedHeader.Get(fp.HeaderJA4X))
	assert.NotEmpty(t, capturedHeader.Get(fp.HeaderJA4H))
	assert.NotEmpty(t, capturedHeader.Get(fp.HeaderSignature))
}

func TestMiddlewareEnforceBlockChallengeAndSessionBinding(t *testing.T) {
	backendCalled := 0
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		backendCalled++
		_, _ = rw.Write([]byte("ok"))
	})

	cfg := dynamic.Fingerprint{
		InjectHeadersMode:    fp.InjectModeCombined,
		HMACSecret:           "enforce-secret",
		Mode:                 fp.ModeEnforce,
		BlockThreshold:       80,
		ChallengeThreshold:   40,
		SessionBindingCookie: "__Host-tfk_fp",
		PoWDifficultyBits:    6,
	}
	mw, err := New(t.Context(), next, cfg, "bot-shield")
	require.NoError(t, err)

	// 1. Impersonated Chrome over Go HTTP/2 -> Risk >= 85 -> Blocked 403!
	botConn := fp.NewConnData()
	botConn.JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	botConn.AkamaiH2 = "4:4194304|1073741824|0|m,s,a,p"
	reqBlock := httptest.NewRequest(http.MethodGet, "https://shop.example.com/login", nil)
	reqBlock.ProtoMajor = 2
	reqBlock.Header.Set("User-Agent", "Mozilla/5.0 Chrome/131.0.0.0")
	reqBlock = reqBlock.WithContext(fp.WithConnData(reqBlock.Context(), botConn))

	rrBlock := httptest.NewRecorder()
	mw.ServeHTTP(rrBlock, reqBlock)
	assert.Equal(t, http.StatusForbidden, rrBlock.Code)
	assert.Equal(t, 0, backendCalled)

	// 2. Medium risk (Windows UA with Linux TTL=54 -> +45 pts, between 40 and 80) -> PoW Challenge!
	medConn := fp.NewConnData()
	medConn.JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	medConn.TLSHandshakeVersion = 0x0303
	medConn.TLSALPS = 0x44cd
	medConn.AkamaiH2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	medConn.IPTTL = 54

	reqChal := httptest.NewRequest(http.MethodGet, "https://shop.example.com/login?next=/home", nil)
	reqChal.ProtoMajor = 2
	reqChal.TLS = &tls.ConnectionState{}
	reqChal.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0")
	reqChal = reqChal.WithContext(fp.WithConnData(reqChal.Context(), medConn))

	rrChal := httptest.NewRecorder()
	mw.ServeHTTP(rrChal, reqChal)
	assert.Equal(t, http.StatusForbidden, rrChal.Code)
	assert.Contains(t, rrChal.Body.String(), "data-nonce=")

	reNonce := regexp.MustCompile(`data-nonce="([^"]+)"`)
	matches := reNonce.FindStringSubmatch(rrChal.Body.String())
	require.Len(t, matches, 2)
	nonce := matches[1]
	sol := fp.SolvePoWChallenge(nonce)
	require.NotEmpty(t, sol)

	// 3. Submit PoW solution -> 303 redirect + signed __Host-tfk_fp cookie!
	solveURL := "https://shop.example.com/login?next=/home&" + fp.QueryParamPoWNonce + "=" + nonce + "&" + fp.QueryParamPoWSol + "=" + sol
	reqSolve := httptest.NewRequest(http.MethodGet, solveURL, nil)
	reqSolve.ProtoMajor = 2
	reqSolve.TLS = &tls.ConnectionState{}
	reqSolve.Header.Set("User-Agent", reqChal.Header.Get("User-Agent"))
	reqSolve = reqSolve.WithContext(fp.WithConnData(reqSolve.Context(), medConn))

	rrSolve := httptest.NewRecorder()
	mw.ServeHTTP(rrSolve, reqSolve)
	assert.Equal(t, http.StatusSeeOther, rrSolve.Code)
	assert.Equal(t, "/login?next=%2Fhome", rrSolve.Header().Get("Location"))
	cookies := rrSolve.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "__Host-tfk_fp", cookies[0].Name)

	// 4. Subsequent request with the PoW-cleared session binding cookie passes directly to backend!
	reqPass := httptest.NewRequest(http.MethodGet, "https://shop.example.com/login?next=/home", nil)
	reqPass.ProtoMajor = 2
	reqPass.TLS = &tls.ConnectionState{}
	reqPass.Header.Set("User-Agent", reqChal.Header.Get("User-Agent"))
	reqPass.AddCookie(cookies[0])
	reqPass = reqPass.WithContext(fp.WithConnData(reqPass.Context(), medConn))

	rrPass := httptest.NewRecorder()
	mw.ServeHTTP(rrPass, reqPass)
	assert.Equal(t, http.StatusOK, rrPass.Code)
	assert.Equal(t, 1, backendCalled)
}

func TestResponseWriterUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapped := &sessionBindingResponseWriter{
		ResponseWriter: rec,
		cookie:         &http.Cookie{Name: "test", Value: "1"},
	}
	assert.Equal(t, rec, wrapped.Unwrap())
}
