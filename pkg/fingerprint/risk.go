package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"math/bits"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Cross-layer contradiction rule identifiers.
const (
	ReasonUATLSMismatch           = "UA_TLS_MISMATCH"
	ReasonH2ImpersonationMismatch = "H2_IMPERSONATION_MISMATCH"
	ReasonH3QUICImpersonation     = "H3_QUIC_IMPERSONATION_MISMATCH"
	ReasonH1GoStdlibHeaderSort    = "H1_GO_STDLIB_HEADER_SORT"
	ReasonHTTP09RawProbe          = "HTTP09_RAW_PROBE"
	ReasonOSTTLMismatch           = "OS_TTL_MISMATCH"
	ReasonRTTProxyTunnelAnomaly   = "RTT_PROXY_TUNNEL_ANOMALY"
	ReasonSessionBindingViolation = "SESSION_BINDING_VIOLATION"

	defaultBlockThreshold     = 80
	defaultChallengeThreshold = 50
	defaultPoWDifficultyBits  = 14
	defaultSessionCookieMaxAg = 86400
	powChallengeWindow        = 5 * time.Minute

	engineChromium = "chromium"
	engineFirefox  = "firefox"
	engineSafari   = "safari"

	QueryParamPoWNonce = "__tfk_pow_nonce"
	QueryParamPoWSol   = "__tfk_pow_sol"
)

// RiskPolicy configures thresholds, cross-layer checks, and session-binding enforcement.
type RiskPolicy struct {
	BlockThreshold               int
	ChallengeThreshold           int
	RequireCrossLayerConsistency bool
	SessionBindingCookie         string
	HMACSecret                   string
	PoWDifficultyBits            int
}

// EffectiveThresholds returns normalized block and challenge score thresholds.
func (p RiskPolicy) EffectiveThresholds() (block, challenge int) {
	block = p.BlockThreshold
	if block <= 0 {
		block = defaultBlockThreshold
	}
	challenge = p.ChallengeThreshold
	if challenge <= 0 {
		challenge = defaultChallengeThreshold
	}
	if challenge > block {
		challenge = block
	}
	return block, challenge
}

// StackIdentity captures transport-tolerant client stack traits for session binding across IP changes and Alt-Svc H2<->H3 migration.
type StackIdentity struct {
	ProtoChar        byte
	TLSVersion       string
	JA4B             string
	EnginePseudoHash string
}

// ComputeStackIdentity extracts client stack traits without binding to client IP or TCP/QUIC transport choice.
func ComputeStackIdentity(req *http.Request, connData *ConnData, secret string) StackIdentity {
	var (
		ja4      string
		akamaiH2 string
		h3Pseudo string
		isQUIC   bool
	)
	if connData != nil {
		connData.RLock()
		ja4 = connData.JA4
		akamaiH2 = connData.AkamaiH2
		h3Pseudo = connData.H3PseudoOrder
		isQUIC = connData.IsQUIC
		connData.RUnlock()
	}

	id := StackIdentity{
		ProtoChar:  'c',
		TLSVersion: "00",
		JA4B:       emptyHash12,
	}
	if isQUIC {
		id.ProtoChar = 'q'
	} else if ja4 != "" {
		id.ProtoChar = ja4[0]
	}

	if len(ja4) >= 23 && ja4[10] == '_' {
		id.TLSVersion = ja4[1:3]
		id.JA4B = ja4[11:23]
	}

	ua := ""
	if req != nil {
		ua = req.Header.Get("User-Agent")
	}
	engine := classifyBrowserEngine(ua)
	pseudo := extractPseudoOrder(req, akamaiH2, h3Pseudo)

	rawFamily := engine + "|" + id.TLSVersion + "|" + pseudo
	if secret != "" {
		id.EnginePseudoHash = hmacSHA256Hex12(secret, rawFamily)
	} else {
		id.EnginePseudoHash = sha256Hex12(rawFamily)
	}
	return id
}

// IssueSessionBindingToken creates an HMAC-signed token bound to the client's cryptographic/engine family.
func IssueSessionBindingToken(id StackIdentity, secret string, powCleared bool, now time.Time) string {
	if secret == "" {
		return ""
	}
	powBit := "0"
	if powCleared {
		powBit = "1"
	}
	payload := strconv.FormatInt(now.Unix(), 10) + "." +
		string(id.ProtoChar) + "." +
		id.JA4B + "." +
		id.EnginePseudoHash + "." +
		powBit
	sig := computeTokenHMAC(secret, payload)
	return payload + "." + sig
}

// ValidateSessionBindingToken checks HMAC authenticity, TTL, and stack consistency (allowing IP changes and Alt-Svc H2<->H3 upgrades).
func ValidateSessionBindingToken(token, secret string, current StackIdentity, connData *ConnData, now time.Time) (authentic, consistent, powCleared bool) {
	if token == "" || secret == "" {
		return false, true, false
	}
	lastDot := strings.LastIndexByte(token, '.')
	if lastDot <= 0 || lastDot+1 >= len(token) {
		return false, true, false
	}
	payload := token[:lastDot]
	sig := token[lastDot+1:]
	expectedSig := computeTokenHMAC(secret, payload)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return false, true, false
	}

	parts := strings.Split(payload, ".")
	if len(parts) != 5 {
		return false, true, false
	}
	issuedUnix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || now.Unix()-issuedUnix > defaultSessionCookieMaxAg || issuedUnix-now.Unix() > 300 {
		return false, true, false
	}

	powCleared = parts[4] == "1"

	tokenProto := byte('c')
	if len(parts[1]) == 1 {
		tokenProto = parts[1][0]
	}
	tokenJA4B := parts[2]
	tokenFamily := parts[3]

	if current.EnginePseudoHash != tokenFamily {
		return true, false, powCleared
	}

	// Same transport protocol requires identical cipher suite hash (JA4_b).
	if current.ProtoChar == tokenProto {
		return true, current.JA4B == tokenJA4B, powCleared
	}

	// Cross-transport migration (TCP t <-> QUIC q via Alt-Svc) is valid only over TLS 1.3 with matching engine+pseudo-headers.
	if (tokenProto == 't' && current.ProtoChar == 'q') || (tokenProto == 'q' && current.ProtoChar == 't') {
		if current.TLSVersion != "13" {
			return true, false, powCleared
		}
		if current.ProtoChar == 'q' && connData != nil {
			connData.RLock()
			validQUIC := connData.QUICHasGREASETP || connData.H3HasGREASE || connData.H3PseudoOrder != "" || connData.QUICTransportParams == ""
			connData.RUnlock()
			if !validQUIC {
				return true, false, powCleared
			}
		}
		return true, true, powCleared
	}

	return true, false, powCleared
}

// EvaluateCrossLayerRisk evaluates impossible multi-layer contradictions and session-binding integrity.
func EvaluateCrossLayerRisk(req *http.Request, connData *ConnData, reqData RequestData, policy RiskPolicy, now time.Time) *RiskAssessment {
	blockThresh, challengeThresh := policy.EffectiveThresholds()
	score := 0
	var reasons []string

	ua := ""
	platformHdr := ""
	if req != nil {
		ua = req.Header.Get("User-Agent")
		platformHdr = req.Header.Get("Sec-Ch-Ua-Platform")
	}
	engine := classifyBrowserEngine(ua)
	claimsModernBrowser := engine == engineChromium || engine == engineFirefox || engine == engineSafari

	var (
		ja4              string
		akamaiH2         string
		h3Uni            string
		h3HasGREASE      bool
		h3Pseudo         string
		isQUIC           bool
		quicTP           string
		quicGREASE       bool
		quicDisableMig   bool
		tlsHandshakeVer  uint16
		tlsALPS          uint16
		tlsCertCompCount int
		http09           bool
		h1Order          []string
		ipTTL            uint8
		tcpMSS           uint16
		tcpRTT           time.Duration
		tlsRTT           time.Duration
	)

	if connData != nil {
		connData.RLock()
		ja4 = connData.JA4
		akamaiH2 = connData.AkamaiH2
		h3Uni = connData.H3UniStreams
		h3HasGREASE = connData.H3HasGREASE
		h3Pseudo = connData.H3PseudoOrder
		isQUIC = connData.IsQUIC
		quicTP = connData.QUICTransportParams
		quicGREASE = connData.QUICHasGREASETP
		quicDisableMig = connData.QUICDisableMig
		tlsHandshakeVer = connData.TLSHandshakeVersion
		tlsALPS = connData.TLSALPS
		tlsCertCompCount = len(connData.TLSCertCompression)
		http09 = connData.HTTP09Raw
		h1Order = connData.H1HeaderOrder
		ipTTL = connData.IPTTL
		tcpMSS = connData.TCPMSS
		tcpRTT = connData.TCPRTT
		tlsRTT = connData.TLSHandshakeRTT
		connData.RUnlock()
	}

	if http09 {
		score += 60
		reasons = append(reasons, ReasonHTTP09RawProbe)
	}

	if policy.RequireCrossLayerConsistency {
		if claimsModernBrowser && len(ja4) >= 10 {
			ver := ja4[1:3]
			extCount, _ := strconv.Atoi(ja4[6:8])
			alpn := ja4[8:10]
			missingChromiumTLS := engine == engineChromium && !isQUIC && tlsHandshakeVer != 0 && tlsALPS == 0 && tlsCertCompCount == 0
			if ver != "13" || extCount <= 8 || alpn == "00" || missingChromiumTLS {
				score += 75
				reasons = append(reasons, ReasonUATLSMismatch)
			}
		}

		if req != nil && req.ProtoMajor == 2 && akamaiH2 != "" && claimsModernBrowser {
			if checkH2ImpersonationMismatch(engine, akamaiH2) {
				score += 85
				reasons = append(reasons, ReasonH2ImpersonationMismatch)
			}
		}

		if ((req != nil && req.ProtoMajor == 3) || isQUIC) && claimsModernBrowser {
			missingTPGREASE := quicTP != "" && !quicGREASE
			missingH3GREASE := h3Uni != "" && !h3HasGREASE && !strings.Contains(h3Uni, "grease")
			mobileDisableMig := quicDisableMig && isMobileUserAgent(ua)
			if missingTPGREASE || missingH3GREASE || mobileDisableMig {
				score += 80
				reasons = append(reasons, ReasonH3QUICImpersonation)
			}
		}

		if req != nil && req.ProtoMajor == 1 && claimsModernBrowser && isGoStdlibSortedH1(h1Order) {
			score += 70
			reasons = append(reasons, ReasonH1GoStdlibHeaderSort)
		}

		if claimsWindowsOS(ua, platformHdr) && ipTTL > 0 && ipTTL <= 64 {
			score += 45
			reasons = append(reasons, ReasonOSTTLMismatch)
		}

		rttDiffAnomaly := tcpRTT > 0 && tlsRTT > 8*tcpRTT && (tlsRTT-tcpRTT) > 80*time.Millisecond
		vpnMSSAnomaly := tcpMSS > 0 && tcpMSS < 1400
		if rttDiffAnomaly || vpnMSSAnomaly {
			score += 40
			reasons = append(reasons, ReasonRTTProxyTunnelAnomaly)
		}
	}

	bindingViolation := false
	powCleared := false
	if policy.SessionBindingCookie != "" && policy.HMACSecret != "" && req != nil {
		if c, err := req.Cookie(policy.SessionBindingCookie); err == nil && c.Value != "" {
			currentID := ComputeStackIdentity(req, connData, policy.HMACSecret)
			auth, consistent, cleared := ValidateSessionBindingToken(c.Value, policy.HMACSecret, currentID, connData, now)
			if auth && !consistent {
				score += 90
				bindingViolation = true
				reasons = append(reasons, ReasonSessionBindingViolation)
			} else if auth && consistent && cleared {
				powCleared = true
			}
		}
	}

	score = min(score, 100)

	// A verified PoW clearance bound to the same client stack satisfies step-up challenges below the hard block threshold.
	if powCleared && !bindingViolation && score >= challengeThresh && score < blockThresh {
		score = challengeThresh - 1
	}

	action := ActionAllow
	switch {
	case score >= blockThresh:
		action = ActionBlock
	case score >= challengeThresh:
		action = ActionChallenge
	}

	pseudo := extractPseudoOrder(req, akamaiH2, h3Pseudo)
	cookieHash := extractJA4HCookieHash(reqData.JA4H)
	rateKey := sha256Hex12(ja4 + "|" + pseudo + "|" + cookieHash)

	return &RiskAssessment{
		Score:   score,
		Action:  action,
		Reasons: reasons,
		RateKey: rateKey,
	}
}

// IssuePoWChallengeNonce generates a stateless HMAC-signed Proof-of-Work challenge nonce.
func IssuePoWChallengeNonce(secret string, id StackIdentity, host string, difficulty int, now time.Time) string {
	if difficulty <= 0 || difficulty > 24 {
		difficulty = defaultPoWDifficultyBits
	}
	payload := strconv.FormatInt(now.Unix(), 10) + "." + strconv.Itoa(difficulty)
	mac := computeTokenHMAC(secret, payload+"|"+id.EnginePseudoHash+"|"+host)
	return payload + "." + mac
}

// VerifyPoWChallengeSolution validates an incoming Proof-of-Work nonce and SHA-256 leading-zero-bit solution.
func VerifyPoWChallengeSolution(nonce, solution, secret string, id StackIdentity, host string, now time.Time) bool {
	if nonce == "" || solution == "" || secret == "" || len(solution) > 64 {
		return false
	}
	parts := strings.Split(nonce, ".")
	if len(parts) != 3 {
		return false
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	age := now.Sub(time.Unix(ts, 0))
	if age < -time.Minute || age > powChallengeWindow {
		return false
	}
	diff, err := strconv.Atoi(parts[1])
	if err != nil || diff <= 0 || diff > 24 {
		return false
	}

	expectedMAC := computeTokenHMAC(secret, parts[0]+"."+parts[1]+"|"+id.EnginePseudoHash+"|"+host)
	if !hmac.Equal([]byte(parts[2]), []byte(expectedMAC)) {
		return false
	}

	sum := sha256.Sum256([]byte(nonce + ":" + solution))
	return hasLeadingZeroBits(sum[:], diff)
}

// SolvePoWChallenge finds a valid Proof-of-Work solution string (useful in tests and headless verification).
func SolvePoWChallenge(nonce string) string {
	parts := strings.Split(nonce, ".")
	if len(parts) != 3 {
		return ""
	}
	diff, err := strconv.Atoi(parts[1])
	if err != nil || diff <= 0 {
		return ""
	}
	for i := range 1 << 24 {
		cand := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(nonce + ":" + cand))
		if hasLeadingZeroBits(sum[:], diff) {
			return cand
		}
	}
	return ""
}

// CleanPoWQueryURL strips internal Proof-of-Work query parameters after successful verification.
func CleanPoWQueryURL(u *url.URL) string {
	if u == nil {
		return "/"
	}
	cp := *u
	q := cp.Query()
	q.Del(QueryParamPoWNonce)
	q.Del(QueryParamPoWSol)
	cp.RawQuery = q.Encode()
	res := cp.RequestURI()
	if res == "" {
		return "/"
	}
	return res
}

// ServePoWChallengePage writes a self-contained HTML5 + WebCrypto SHA-256 Proof-of-Work challenge response.
func ServePoWChallengePage(rw http.ResponseWriter, req *http.Request, nonce string) {
	parts := strings.Split(nonce, ".")
	diff := defaultPoWDifficultyBits
	if len(parts) == 3 {
		if d, err := strconv.Atoi(parts[1]); err == nil && d > 0 {
			diff = d
		}
	}

	targetURI := "/"
	if req != nil && req.URL != nil {
		targetURI = CleanPoWQueryURL(req.URL)
	}
	escapedNonce := html.EscapeString(nonce)
	escapedURI := html.EscapeString(targetURI)

	body := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verifying Connection</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#0f172a;color:#e2e8f0}.card{padding:2rem;border-radius:12px;background:#1e293b;max-width:420px;text-align:center;box-shadow:0 10px 25px rgba(0,0,0,.3)}</style>
</head>
<body>
<div class="card" data-nonce="%s" data-bits="%d" data-target="%s">
<h2>Verifying your browser</h2>
<p id="status">Completing a lightweight cryptographic check...</p>
</div>
<script>
(async () => {
  const el = document.querySelector(".card");
  const nonce = el.dataset.nonce;
  const bits = parseInt(el.dataset.bits, 10);
  const target = el.dataset.target;
  const enc = new TextEncoder();
  const hasZeroBits = (buf, n) => {
    const arr = new Uint8Array(buf);
    let rem = n;
    for (let i = 0; i < arr.length && rem > 0; i++) {
      if (rem >= 8) {
        if (arr[i] !== 0) return false;
        rem -= 8;
      } else {
        const mask = 0xff << (8 - rem);
        return (arr[i] & mask) === 0;
      }
    }
    return true;
  };
  for (let i = 0; i < 16777216; i++) {
    const sol = i.toString(10);
    const digest = await crypto.subtle.digest("SHA-256", enc.encode(nonce + ":" + sol));
    if (hasZeroBits(digest, bits)) {
      const u = new URL(target, window.location.origin);
      u.searchParams.set(%q, nonce);
      u.searchParams.set(%q, sol);
      window.location.replace(u.toString());
      return;
    }
  }
})();
</script>
</body>
</html>`, escapedNonce, diff, escapedURI, QueryParamPoWNonce, QueryParamPoWSol)

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	rw.WriteHeader(http.StatusForbidden)
	_, _ = rw.Write([]byte(body))
}

func hasLeadingZeroBits(digest []byte, zeroBits int) bool {
	rem := zeroBits
	for _, b := range digest {
		if rem <= 0 {
			return true
		}
		if rem >= 8 {
			if b != 0 {
				return false
			}
			rem -= 8
			continue
		}
		return bits.LeadingZeros8(b) >= rem
	}
	return rem <= 0
}

func computeTokenHMAC(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

func classifyBrowserEngine(ua string) string {
	if ua == "" {
		return "empty"
	}
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "firefox/"):
		return engineFirefox
	case strings.Contains(lower, "chrome/") || strings.Contains(lower, "crios/") || strings.Contains(lower, "edg/"):
		return engineChromium
	case strings.Contains(lower, "safari/") && strings.Contains(lower, "version/"):
		return engineSafari
	case strings.Contains(lower, "curl/"):
		return "curl"
	case strings.Contains(lower, "go-http-client"):
		return "go"
	default:
		return "other"
	}
}

func isMobileUserAgent(ua string) bool {
	lower := strings.ToLower(ua)
	return strings.Contains(lower, "android") ||
		strings.Contains(lower, "iphone") ||
		strings.Contains(lower, "ipad") ||
		strings.Contains(lower, "mobile")
}

func claimsWindowsOS(ua, secPlatform string) bool {
	if strings.Contains(strings.ToLower(secPlatform), "windows") {
		return true
	}
	return strings.Contains(strings.ToLower(ua), "windows nt")
}

func checkH2ImpersonationMismatch(engine, akamaiH2 string) bool {
	parts := strings.Split(akamaiH2, "|")
	if len(parts) != 4 {
		return false
	}
	settings, wu, _, pseudo := parts[0], parts[1], parts[2], parts[3]

	// Go x/net/http2 sends a hardcoded 1 GiB (1073741824) connection WINDOW_UPDATE.
	if wu == "1073741824" {
		return true
	}

	switch engine {
	case engineChromium:
		if pseudo != "" && pseudo != "m,a,s,p" && pseudo != "m,a,s,p,pr" {
			return true
		}
		if strings.Contains(settings, "4:4194304") && !strings.Contains(settings, "4:6291456") && wu == "00" {
			return true
		}
	case engineFirefox:
		if pseudo != "" && pseudo != "m,p,a,s" && pseudo != "m,p,a,s,pr" {
			return true
		}
		if wu == "15663105" {
			return true
		}
	}
	return false
}

// isGoStdlibSortedH1 detects Go net/http's signature HTTP/1.1 serialization:
// Host first, User-Agent second, followed by >= 3 strictly sorted CanonicalMIMEHeaderKey headers.
func isGoStdlibSortedH1(order []string) bool {
	if len(order) < 5 {
		return false
	}
	if order[0] != "Host" || order[1] != "User-Agent" {
		return false
	}
	for i := 2; i < len(order); i++ {
		if order[i] != textproto.CanonicalMIMEHeaderKey(order[i]) {
			return false
		}
		if i > 2 && order[i-1] > order[i] {
			return false
		}
	}
	return true
}

func extractPseudoOrder(req *http.Request, akamaiH2, h3Pseudo string) string {
	if req != nil && req.ProtoMajor == 3 && h3Pseudo != "" {
		return h3Pseudo
	}
	if akamaiH2 != "" {
		if idx := strings.LastIndexByte(akamaiH2, '|'); idx >= 0 && idx+1 < len(akamaiH2) {
			return akamaiH2[idx+1:]
		}
	}
	if h3Pseudo != "" {
		return h3Pseudo
	}
	return "h1"
}

func extractJA4HCookieHash(ja4h string) string {
	if ja4h == "" {
		return emptyHash12
	}
	lastUnderscore := strings.LastIndexByte(ja4h, '_')
	if lastUnderscore >= 0 && lastUnderscore+1 < len(ja4h) {
		return ja4h[lastUnderscore+1:]
	}
	return emptyHash12
}
