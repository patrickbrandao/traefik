package fingerprint

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReservedHeadersAntiSpoofingAndHMACSignature(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/checkout?item=1", nil)
	req.Header.Set("X-Client-Fp", `ja4="spoofed"`)
	req.Header.Set("X-Fp-Ja4", "spoofed")
	aliasRiskKey := "X_Fp_Risk_Score"
	aliasClientKey := "X.Client.Fp"
	req.Header[aliasRiskKey] = []string{"0"}
	req.Header[aliasClientKey] = []string{"spoofed"}
	req.Header.Set("X-Request-ID", "req-99")

	StripReservedHeaders(req.Header)
	assert.Empty(t, req.Header.Get(HeaderClientFP))
	assert.Empty(t, req.Header.Get(HeaderJA4))
	assert.Empty(t, req.Header[aliasRiskKey])
	assert.Empty(t, req.Header[aliasClientKey])

	fp := NewConnData()
	fp.JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	fp.JA3N = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	fp.AkamaiH2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	fp.JA4T = "65535_2-1-3-1-1-8-4-0_1460_8"
	fp.IPTTL = 54
	fp.TLSKeyShareGroups = []uint16{GroupX25519MLKEM768, 0x001d}
	fp.TCPRTT = 10 * time.Millisecond
	fp.TLSHandshakeRTT = 15 * time.Millisecond

	reqData := InspectRequest(req, fp, false, "super-secret")
	risk := &RiskAssessment{Score: 0, Action: ActionAllow, RateKey: "abcdef012345"}

	now := time.Unix(1760000000, 0)
	InjectHeaders(req, InjectModeBoth, "super-secret", fp, reqData, risk, now)

	combined := req.Header.Get(HeaderClientFP)
	assert.Contains(t, combined, `ja4="t13d1516h2_8daaf6152771_02713d6af862"`)
	assert.Contains(t, combined, "pq=1")
	assert.Contains(t, combined, "ttl=54")
	assert.Equal(t, fp.JA4, req.Header.Get(HeaderJA4))
	assert.Equal(t, fp.AkamaiH2, req.Header.Get(HeaderH2))
	assert.Equal(t, "5ms", req.Header.Get(HeaderRTTDiff))

	sig := req.Header.Get(HeaderSignature)
	require.NotEmpty(t, sig)
	assert.True(t, VerifyHeaderSignature(sig, "super-secret", req.Method, req.Host, req.URL.RequestURI(), combined, "req-99", now.Add(10*time.Second), time.Minute))
	assert.False(t, VerifyHeaderSignature(sig, "wrong-secret", req.Method, req.Host, req.URL.RequestURI(), combined, "req-99", now, time.Minute))
}

func TestCrossLayerRiskContradictions(t *testing.T) {
	now := time.Now()
	policy := RiskPolicy{
		BlockThreshold:               80,
		ChallengeThreshold:           50,
		RequireCrossLayerConsistency: true,
		SessionBindingCookie:         "__Host-tfk_fp",
		HMACSecret:                   "secret-key",
	}

	// 1. Legitimate Chrome over H2 on Windows (TTL=118) -> 0 risk!
	chromeFP := NewConnData()
	chromeFP.JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	chromeFP.TLSHandshakeVersion = 0x0303
	chromeFP.TLSALPS = extALPS
	chromeFP.TLSCertCompression = []uint16{2}
	chromeFP.AkamaiH2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	chromeFP.IPTTL = 118
	chromeFP.TCPMSS = 1460

	reqOK := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	reqOK.ProtoMajor = 2
	reqOK.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36")
	resOK := EvaluateCrossLayerRisk(reqOK, chromeFP, InspectRequest(reqOK, chromeFP, false, ""), policy, now)
	assert.Equal(t, 0, resOK.Score)
	assert.Equal(t, ActionAllow, resOK.Action)

	// 2. uTLS impersonating Chrome TLS JA4, but using Go x/net/http2 (WINDOW_UPDATE=1073741824, m,s,a,p) + Linux container TTL=54 claiming Windows.
	botFP := NewConnData()
	botFP.JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	botFP.TLSHandshakeVersion = 0x0303
	botFP.TLSALPS = extALPS
	botFP.AkamaiH2 = "4:4194304|1073741824|0|m,s,a,p"
	botFP.IPTTL = 54

	resBot := EvaluateCrossLayerRisk(reqOK, botFP, InspectRequest(reqOK, botFP, false, ""), policy, now)
	assert.Equal(t, 100, resBot.Score)
	assert.Equal(t, ActionBlock, resBot.Action)
	assert.Contains(t, resBot.Reasons, ReasonH2ImpersonationMismatch)
	assert.Contains(t, resBot.Reasons, ReasonOSTTLMismatch)

	// 3. HTTP/1.1 Go net/http lexicographically sorted headers spoofing Chrome User-Agent.
	h1BotFP := NewConnData()
	h1BotFP.H1HeaderOrder = []string{"Host", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language", "Sec-Ch-Ua"}
	reqH1 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	reqH1.ProtoMajor = 1
	reqH1.Header.Set("User-Agent", "Mozilla/5.0 Chrome/131.0.0.0")
	resH1 := EvaluateCrossLayerRisk(reqH1, h1BotFP, InspectRequest(reqH1, h1BotFP, false, ""), policy, now)
	assert.GreaterOrEqual(t, resH1.Score, 70)
	assert.Contains(t, resH1.Reasons, ReasonH1GoStdlibHeaderSort)

	// 4. HTTP/3 bot without GREASE transport params or GREASE uni streams.
	h3BotFP := NewConnData()
	h3BotFP.IsQUIC = true
	h3BotFP.JA4 = "q13d0312h3_55b375c5d22e_cd85d2d88918"
	h3BotFP.QUICTransportParams = "4:1048576;8:100"
	h3BotFP.QUICHasGREASETP = false
	h3BotFP.H3UniStreams = "0"
	reqH3 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	reqH3.ProtoMajor = 3
	reqH3.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 15) Chrome/131.0.0.0 Mobile")
	resH3 := EvaluateCrossLayerRisk(reqH3, h3BotFP, InspectRequest(reqH3, h3BotFP, false, ""), policy, now)
	assert.GreaterOrEqual(t, resH3.Score, 80)
	assert.Contains(t, resH3.Reasons, ReasonH3QUICImpersonation)

	// 5. Residential SOCKS5 proxy RTT differential (L4 TCP RTT 2ms vs TLS Handshake RTT 220ms).
	proxyFP := NewConnData()
	proxyFP.TCPRTT = 2 * time.Millisecond
	proxyFP.TLSHandshakeRTT = 220 * time.Millisecond
	proxyFP.TCPMSS = 1360
	reqPlain := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	reqPlain.Header.Set("User-Agent", "CustomSDK/1.0")
	resProxy := EvaluateCrossLayerRisk(reqPlain, proxyFP, InspectRequest(reqPlain, proxyFP, false, ""), policy, now)
	assert.Equal(t, 40, resProxy.Score)
	assert.Contains(t, resProxy.Reasons, ReasonRTTProxyTunnelAnomaly)
}

func TestSessionBindingAltSvcMigrationAndPoWChallenge(t *testing.T) {
	now := time.Now()
	secret := "edge-hmac-secret"

	// Client connects initially over TCP H2 (Wi-Fi IP 198.51.100.10).
	tcpFP := NewConnData()
	tcpFP.JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	tcpFP.AkamaiH2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

	reqH2 := httptest.NewRequest(http.MethodGet, "https://shop.example.com/cart", nil)
	reqH2.ProtoMajor = 2
	reqH2.RemoteAddr = "198.51.100.10:51111"
	reqH2.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) CriOS/131.0.0.0 Mobile/15E148")

	idH2 := ComputeStackIdentity(reqH2, tcpFP, secret)
	cookieVal := IssueSessionBindingToken(idH2, secret, true, now)

	// Client switches from Wi-Fi to 5G (new IP 203.0.113.99) AND upgrades to QUIC H3 via Alt-Svc!
	quicFP := NewConnData()
	quicFP.IsQUIC = true
	quicFP.JA4 = "q13d0312h3_55b375c5d22e_cd85d2d88918"
	quicFP.QUICHasGREASETP = true
	quicFP.H3HasGREASE = true
	quicFP.H3PseudoOrder = "m,a,s,p"

	reqH3 := httptest.NewRequest(http.MethodGet, "https://shop.example.com/checkout", nil)
	reqH3.ProtoMajor = 3
	reqH3.RemoteAddr = "203.0.113.99:62222"
	reqH3.Header.Set("User-Agent", reqH2.Header.Get("User-Agent"))
	reqH3.AddCookie(&http.Cookie{Name: "__Host-tfk_fp", Value: cookieVal})

	idH3 := ComputeStackIdentity(reqH3, quicFP, secret)
	auth, consistent, cleared := ValidateSessionBindingToken(cookieVal, secret, idH3, quicFP, now.Add(time.Minute))
	assert.True(t, auth)
	assert.True(t, consistent)
	assert.True(t, cleared)

	// Attacker steals __Host-tfk_fp cookie and replays it from curl/Python!
	curlFP := NewConnData()
	curlFP.JA4 = "t13d0310h2_55b375c5d22e_aabbccddeeff"
	curlFP.AkamaiH2 = "3:100;4:65535|00|0|m,s,a,p"
	reqCurl := httptest.NewRequest(http.MethodGet, "https://shop.example.com/checkout", nil)
	reqCurl.ProtoMajor = 2
	reqCurl.Header.Set("User-Agent", "curl/8.9.1")
	reqCurl.AddCookie(&http.Cookie{Name: "__Host-tfk_fp", Value: cookieVal})

	policy := RiskPolicy{
		BlockThreshold:               80,
		ChallengeThreshold:           50,
		RequireCrossLayerConsistency: true,
		SessionBindingCookie:         "__Host-tfk_fp",
		HMACSecret:                   secret,
	}
	resReplay := EvaluateCrossLayerRisk(reqCurl, curlFP, InspectRequest(reqCurl, curlFP, false, ""), policy, now.Add(time.Minute))
	assert.GreaterOrEqual(t, resReplay.Score, 90)
	assert.Equal(t, ActionBlock, resReplay.Action)
	assert.Contains(t, resReplay.Reasons, ReasonSessionBindingViolation)

	// Verify PoW challenge generation, HTML output, and solution verification.
	nonce := IssuePoWChallengeNonce(secret, idH2, reqH2.Host, 8, now)
	sol := SolvePoWChallenge(nonce)
	require.NotEmpty(t, sol)
	assert.True(t, VerifyPoWChallengeSolution(nonce, sol, secret, idH2, reqH2.Host, now.Add(5*time.Second)))
	assert.False(t, VerifyPoWChallengeSolution(nonce, "invalid-sol", secret, idH2, reqH2.Host, now))

	rr := httptest.NewRecorder()
	ServePoWChallengePage(rr, reqH2, nonce)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), `crypto.subtle.digest("SHA-256"`)
}

func TestConcurrentRaceSafety(t *testing.T) {
	tracker := NewQUICTracker()
	sharedFP := NewConnData()
	sharedFP.JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	sharedFP.AkamaiH2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

	policy := RiskPolicy{
		BlockThreshold:               80,
		ChallengeThreshold:           50,
		RequireCrossLayerConsistency: true,
		HMACSecret:                   "race-secret",
	}

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			addr := fmt.Sprintf("192.0.2.%d:4000", worker)
			tracker.StoreFallbackJA4(addr, sharedFP.JA4)
			_ = tracker.LoadFallbackJA4(addr)

			sharedFP.Lock()
			sharedFP.TLSHandshakeRTT = time.Duration(worker+1) * time.Millisecond
			sharedFP.Unlock()

			req := httptest.NewRequest(http.MethodGet, "https://example.com/api", nil)
			req.ProtoMajor = 2
			req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/131.0.0.0")
			req.Header.Set("Accept-Language", "en-US")
			rd := InspectRequest(req, sharedFP, false, "race-secret")
			risk := EvaluateCrossLayerRisk(req, sharedFP, rd, policy, time.Now())
			InjectHeaders(req, InjectModeBoth, "race-secret", sharedFP, rd, risk, time.Now())
		}(i)
	}
	wg.Wait()
}
