package fingerprint

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	fp "github.com/traefik/traefik/v3/pkg/fingerprint"
	"github.com/traefik/traefik/v3/pkg/middlewares"
	"github.com/traefik/traefik/v3/pkg/middlewares/accesslog"
)

const (
	typeName          = "Fingerprint"
	defaultPoWCookie  = "__tfk_fp"
	sessionMaxAgeSecs = 86400
)

type middleware struct {
	next                 http.Handler
	name                 string
	injectMode           string
	mode                 string
	headerSecret         string
	tokenSecret          string
	sessionBindingCookie string
	redactCookieValues   bool
	policy               fp.RiskPolicy
}

// New constructs a dynamic Fingerprint middleware instance.
func New(ctx context.Context, next http.Handler, config dynamic.Fingerprint, name string) (http.Handler, error) {
	middlewares.GetLogger(ctx, name, typeName).Debug().Msg("Creating middleware")

	injectMode := config.InjectHeadersMode
	if injectMode == "" {
		injectMode = fp.InjectModeCombined
	}
	switch injectMode {
	case fp.InjectModeCombined, fp.InjectModeSplit, fp.InjectModeBoth, fp.InjectModeNone:
	default:
		return nil, fmt.Errorf("invalid injectHeadersMode %q", injectMode)
	}

	mode := config.Mode
	if mode == "" {
		mode = fp.ModeHeadersOnly
	}
	switch mode {
	case fp.ModeHeadersOnly, fp.ModeShadow, fp.ModeEnforce:
	default:
		return nil, fmt.Errorf("invalid fingerprint mode %q", mode)
	}

	if config.BlockThreshold < 0 || config.BlockThreshold > 100 {
		return nil, fmt.Errorf("blockThreshold must be between 0 and 100, got %d", config.BlockThreshold)
	}
	if config.ChallengeThreshold < 0 || config.ChallengeThreshold > 100 {
		return nil, fmt.Errorf("challengeThreshold must be between 0 and 100, got %d", config.ChallengeThreshold)
	}

	headerSecret := resolveSecret(config.HMACSecret)
	tokenSecret := headerSecret
	if tokenSecret == "" {
		var rnd [32]byte
		_, _ = rand.Read(rnd[:])
		tokenSecret = hex.EncodeToString(rnd[:])
	}

	requireConsistency := config.RequireCrossLayerConsistency == nil || *config.RequireCrossLayerConsistency

	cookieName := config.SessionBindingCookie
	effectiveCookieForPolicy := cookieName
	if effectiveCookieForPolicy == "" && mode == fp.ModeEnforce {
		effectiveCookieForPolicy = defaultPoWCookie
	}

	return &middleware{
		next:                 next,
		name:                 name,
		injectMode:           injectMode,
		mode:                 mode,
		headerSecret:         headerSecret,
		tokenSecret:          tokenSecret,
		sessionBindingCookie: cookieName,
		redactCookieValues:   config.RedactCookieValues,
		policy: fp.RiskPolicy{
			BlockThreshold:               config.BlockThreshold,
			ChallengeThreshold:           config.ChallengeThreshold,
			RequireCrossLayerConsistency: requireConsistency,
			SessionBindingCookie:         effectiveCookieForPolicy,
			HMACSecret:                   tokenSecret,
			PoWDifficultyBits:            config.PoWDifficultyBits,
		},
	}, nil
}

func (m *middleware) GetTracingInformation() (string, string) {
	return m.name, typeName
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := middlewares.GetLogger(req.Context(), m.name, typeName)
	now := time.Now()

	fp.StripReservedHeaders(req.Header)

	connData := fp.FromContext(req.Context())
	if connData == nil {
		connData = fp.NewConnData()
		req = req.WithContext(fp.WithConnData(req.Context(), connData))
	}

	fp.PopulateClientCertFromRequest(req, connData)

	if m.mode == fp.ModeEnforce && req.URL != nil && strings.Contains(req.URL.RawQuery, fp.QueryParamPoWNonce) {
		q := req.URL.Query()
		nonce := q.Get(fp.QueryParamPoWNonce)
		sol := q.Get(fp.QueryParamPoWSol)
		stackID := fp.ComputeStackIdentity(req, connData, m.tokenSecret)
		if fp.VerifyPoWChallengeSolution(nonce, sol, m.tokenSecret, stackID, req.Host, now) {
			cookieName := m.policy.SessionBindingCookie
			token := fp.IssueSessionBindingToken(stackID, m.tokenSecret, true, now)
			http.SetCookie(rw, buildBindingCookie(req, cookieName, token))
			http.Redirect(rw, req, fp.CleanPoWQueryURL(req.URL), http.StatusSeeOther)
			return
		}
	}

	reqData := fp.InspectRequest(req, connData, m.redactCookieValues, m.headerSecret)
	connData.Lock()
	connData.LastJA4H = reqData.JA4H
	connData.Unlock()

	var risk *fp.RiskAssessment
	if m.mode == fp.ModeShadow || m.mode == fp.ModeEnforce {
		risk = fp.EvaluateCrossLayerRisk(req, connData, reqData, m.policy, now)
		req = req.WithContext(fp.WithRiskAssessment(req.Context(), risk))
		if ld := accesslog.GetLogData(req); ld != nil && ld.Core != nil {
			ld.Core[accesslog.ClientRiskScore] = risk.Score
		}

		if risk.Score > 0 {
			logger.Debug().
				Int("riskScore", risk.Score).
				Str("action", risk.Action).
				Strs("reasons", risk.Reasons).
				Str("mode", m.mode).
				Msg("Evaluated cross-layer client fingerprint risk")
		}

		if m.mode == fp.ModeEnforce {
			switch risk.Action {
			case fp.ActionBlock:
				rw.WriteHeader(http.StatusForbidden)
				return
			case fp.ActionChallenge:
				stackID := fp.ComputeStackIdentity(req, connData, m.tokenSecret)
				nonce := fp.IssuePoWChallengeNonce(m.tokenSecret, stackID, req.Host, m.policy.PoWDifficultyBits, now)
				fp.ServePoWChallengePage(rw, req, nonce)
				return
			}
		}
	}

	fp.InjectHeaders(req, m.injectMode, m.headerSecret, connData, reqData, risk, now)

	targetRW := rw
	if m.sessionBindingCookie != "" && !m.hasValidBindingCookie(req, connData, now) {
		stackID := fp.ComputeStackIdentity(req, connData, m.tokenSecret)
		token := fp.IssueSessionBindingToken(stackID, m.tokenSecret, false, now)
		targetRW = &sessionBindingResponseWriter{
			ResponseWriter: rw,
			cookie:         buildBindingCookie(req, m.sessionBindingCookie, token),
		}
	}

	m.next.ServeHTTP(targetRW, req)
}

func (m *middleware) hasValidBindingCookie(req *http.Request, connData *fp.ConnData, now time.Time) bool {
	c, err := req.Cookie(m.sessionBindingCookie)
	if err != nil || c.Value == "" {
		return false
	}
	stackID := fp.ComputeStackIdentity(req, connData, m.tokenSecret)
	auth, consistent, _ := fp.ValidateSessionBindingToken(c.Value, m.tokenSecret, stackID, connData, now)
	return auth && consistent
}

func buildBindingCookie(req *http.Request, name, value string) *http.Cookie {
	secure := (req != nil && req.TLS != nil) ||
		strings.HasPrefix(name, "__Host-") ||
		strings.HasPrefix(name, "__Secure-")
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   sessionMaxAgeSecs,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func resolveSecret(raw string) string {
	if raw == "" {
		return ""
	}
	if envName, ok := strings.CutPrefix(raw, "env:"); ok && envName != "" {
		return os.Getenv(envName)
	}
	return raw
}

// sessionBindingResponseWriter injects the session-binding Set-Cookie header before committing non-5xx responses.
type sessionBindingResponseWriter struct {
	http.ResponseWriter

	cookie      *http.Cookie
	wroteHeader bool
}

// Unwrap exposes the underlying http.ResponseWriter so http.ResponseController reaches connection controls.
func (w *sessionBindingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *sessionBindingResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		if statusCode < http.StatusInternalServerError && w.cookie != nil {
			http.SetCookie(w.ResponseWriter, w.cookie)
		}
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *sessionBindingResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
