package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Canonical HTTP header names used for downstream fingerprint propagation.
const (
	HeaderClientFP      = "X-Client-Fp"
	HeaderJA4           = "X-Fp-Ja4"
	HeaderJA3           = "X-Fp-Ja3"
	HeaderJA3N          = "X-Fp-Ja3n"
	HeaderTLSDeep       = "X-Fp-Tls-Deep"
	HeaderJA4X          = "X-Fp-Ja4x"
	HeaderClientCertSHA = "X-Fp-Cert-Sha256"
	HeaderClientSPKISHA = "X-Fp-Spki-Sha256"
	HeaderH2            = "X-Fp-H2"
	HeaderH3            = "X-Fp-H3"
	HeaderQUIC          = "X-Fp-Quic"
	HeaderJA4H          = "X-Fp-Ja4h"
	HeaderJA4T          = "X-Fp-Ja4t"
	HeaderIPTTL         = "X-Fp-Ip-Ttl"
	HeaderRTTDiff       = "X-Fp-Rtt-Diff"
	HeaderRiskScore     = "X-Fp-Risk-Score"
	HeaderRiskAction    = "X-Fp-Risk-Action"
	HeaderRiskReasons   = "X-Fp-Risk-Reasons"
	HeaderRateKey       = "X-Fp-Rate-Key"
	HeaderSignature     = "X-Fp-Signature"
)

// IsReservedHeaderName reports whether name matches X-Client-Fp or the X-Fp-* namespace,
// including underscore or dot aliasing variants.
func IsReservedHeaderName(name string) bool {
	if len(name) < 5 {
		return false
	}
	if len(name) == len(HeaderClientFP) && equalFoldAliased(name, HeaderClientFP) {
		return true
	}
	return equalFoldAliased(name[:5], "X-Fp-")
}

func equalFoldAliased(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca := asciiLower(a[i])
		cb := asciiLower(b[i])
		if ca == '_' || ca == '.' {
			ca = '-'
		}
		if cb == '_' || cb == '.' {
			cb = '-'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// StripReservedHeaders unconditionally removes any client-supplied X-Client-Fp or X-Fp-* headers to prevent spoofing.
func StripReservedHeaders(h http.Header) {
	for k := range h {
		if IsReservedHeaderName(k) {
			delete(h, k)
		}
	}
}

// PopulateClientCertFromRequest extracts JA4X and RFC 9440 SHA-256 thumbprints from req.TLS.PeerCertificates when present.
func PopulateClientCertFromRequest(req *http.Request, connData *ConnData) {
	if req == nil || req.TLS == nil || len(req.TLS.PeerCertificates) == 0 || connData == nil {
		return
	}
	connData.RLock()
	already := connData.JA4X != ""
	connData.RUnlock()
	if already {
		return
	}

	ja4x, certSHA, spkiSHA := ExtractClientCertInfo(req.TLS.PeerCertificates[0])
	connData.Lock()
	if connData.JA4X == "" {
		connData.JA4X = ja4x
		connData.ClientCertSHA = certSHA
		connData.ClientSPKISHA = spkiSHA
	}
	connData.Unlock()
}

// FormatCombinedHeader formats collected connection, request, and risk signals as an RFC 8941 Structured Field Dictionary.
func FormatCombinedHeader(connData *ConnData, reqData RequestData, risk *RiskAssessment) string {
	var parts []string

	if connData != nil {
		connData.RLock()
		if connData.JA4 != "" {
			parts = append(parts, "ja4="+sfString(connData.JA4))
		}
		if connData.JA3N != "" {
			parts = append(parts, "ja3n="+sfString(connData.JA3N))
		}
		if connData.AkamaiH2 != "" {
			parts = append(parts, "h2="+sfString(connData.AkamaiH2))
		}
		if h3 := formatH3Locked(connData); h3 != "" {
			parts = append(parts, "h3="+sfString(h3))
		}
		if connData.IsQUIC && connData.QUICTransportParams != "" {
			parts = append(parts, "quic="+sfString(connData.QUICTransportParams))
		}
		if reqData.JA4H != "" {
			parts = append(parts, "ja4h="+sfString(reqData.JA4H))
		}
		if connData.JA4T != "" {
			parts = append(parts, "ja4t="+sfString(connData.JA4T))
		}
		if connData.JA4X != "" {
			parts = append(parts, "ja4x="+sfString(connData.JA4X))
		}
		if connData.IPTTL > 0 {
			parts = append(parts, "ttl="+strconv.FormatUint(uint64(connData.IPTTL), 10))
		}
		if connData.UDPPayloadSize > 0 {
			parts = append(parts, "udp="+strconv.FormatUint(uint64(connData.UDPPayloadSize), 10))
		}
		if HasPostQuantumKeyShare(connData.TLSKeyShareGroups) {
			parts = append(parts, "pq=1")
		}
		connData.RUnlock()
	} else if reqData.JA4H != "" {
		parts = append(parts, "ja4h="+sfString(reqData.JA4H))
	}

	if risk != nil {
		parts = append(parts, "risk="+strconv.Itoa(risk.Score))
	}

	return strings.Join(parts, ", ")
}

// FormatTLSDeepSummary formats Deep TLS / PeetPrint extension internals into a compact key-value summary.
func FormatTLSDeepSummary(connData *ConnData) string {
	if connData == nil {
		return ""
	}
	connData.RLock()
	defer connData.RUnlock()

	if connData.TLSHandshakeVersion == 0 && len(connData.TLSKeyShareGroups) == 0 && connData.TLSECHOuter == "" {
		return ""
	}

	var parts []string
	if connData.TLSRecordVersion != 0 {
		var hexBuf [4]byte
		putUint16Hex(&hexBuf, connData.TLSRecordVersion)
		parts = append(parts, "rec="+string(hexBuf[:]))
	}
	if connData.TLSRecordFragments > 0 {
		parts = append(parts, "frag="+strconv.FormatUint(uint64(connData.TLSRecordFragments), 10))
	}
	parts = append(parts, "sid="+strconv.FormatUint(uint64(connData.TLSSessionIDLen), 10))

	if len(connData.TLSKeyShareGroups) > 0 {
		var ks []string
		for _, g := range connData.TLSKeyShareGroups {
			var hexBuf [4]byte
			putUint16Hex(&hexBuf, g)
			ks = append(ks, string(hexBuf[:]))
		}
		parts = append(parts, "ks="+strings.Join(ks, "-"))
	}
	if len(connData.TLSCertCompression) > 0 {
		parts = append(parts, "cc="+joinUint16Dash(connData.TLSCertCompression))
	}
	if connData.TLSALPS != 0 {
		var hexBuf [4]byte
		putUint16Hex(&hexBuf, connData.TLSALPS)
		parts = append(parts, "alps="+string(hexBuf[:]))
	}
	if connData.TLSHasDelegatedCred {
		parts = append(parts, "dc=1")
	}
	if connData.TLSRecordSizeLimit > 0 {
		parts = append(parts, "rsl="+strconv.FormatUint(uint64(connData.TLSRecordSizeLimit), 10))
	}
	if connData.TLSPaddingLen >= 0 {
		parts = append(parts, "pad="+strconv.Itoa(connData.TLSPaddingLen))
	}
	if connData.TLSECHOuter != "" {
		parts = append(parts, "ech="+connData.TLSECHOuter)
	}
	return strings.Join(parts, ";")
}

// FormatQUICSummary formats QUIC Initial header and transport parameter metadata.
func FormatQUICSummary(connData *ConnData) string {
	if connData == nil {
		return ""
	}
	connData.RLock()
	defer connData.RUnlock()

	if !connData.IsQUIC {
		return ""
	}
	var parts []string
	if connData.QUICVersion != 0 {
		parts = append(parts, "v="+strconv.FormatUint(uint64(connData.QUICVersion), 16))
	}
	if connData.QUICDCIDLen > 0 {
		parts = append(parts, "dcid="+strconv.FormatUint(uint64(connData.QUICDCIDLen), 10))
	}
	if connData.UDPPayloadSize > 0 {
		parts = append(parts, "udp="+strconv.FormatUint(uint64(connData.UDPPayloadSize), 10))
	}
	if connData.QUICInitialFrames != "" {
		parts = append(parts, "frames="+connData.QUICInitialFrames)
	}
	if connData.QUICHasGREASETP {
		parts = append(parts, "grease=1")
	}
	if connData.QUICTransportParams != "" {
		parts = append(parts, "tp="+connData.QUICTransportParams)
	}
	return strings.Join(parts, ";")
}

// FormatH3Summary formats HTTP/3 unidirectional streams, settings, and pseudo-header order.
func FormatH3Summary(connData *ConnData) string {
	if connData == nil {
		return ""
	}
	connData.RLock()
	defer connData.RUnlock()
	return formatH3Locked(connData)
}

func formatH3Locked(connData *ConnData) string {
	if connData.H3UniStreams == "" && connData.H3Settings == "" && connData.H3PseudoOrder == "" {
		return ""
	}
	var parts []string
	if connData.H3UniStreams != "" {
		parts = append(parts, "uni="+connData.H3UniStreams)
	}
	if connData.H3Settings != "" {
		parts = append(parts, "s="+connData.H3Settings)
	}
	if connData.H3PseudoOrder != "" {
		parts = append(parts, "p="+connData.H3PseudoOrder)
	}
	return strings.Join(parts, "|")
}

// InjectHeaders writes fingerprint headers onto req.Header according to mode ("combined", "split", "both", "none")
// and optionally signs them with HMAC-SHA256 in X-Fp-Signature.
func InjectHeaders(req *http.Request, mode, hmacSecret string, connData *ConnData, reqData RequestData, risk *RiskAssessment, now time.Time) {
	if req == nil || mode == InjectModeNone {
		return
	}
	if mode == "" {
		mode = InjectModeCombined
	}

	combined := FormatCombinedHeader(connData, reqData, risk)

	if mode == InjectModeCombined || mode == InjectModeBoth {
		if combined != "" {
			req.Header.Set(HeaderClientFP, combined)
		}
	}

	if mode == InjectModeSplit || mode == InjectModeBoth {
		injectSplitHeaders(req.Header, connData, reqData, risk)
	}

	if hmacSecret != "" && combined != "" {
		ts := now.Unix()
		sig := ComputeHeaderSignature(hmacSecret, ts, req.Method, req.Host, req.URL.RequestURI(), combined, req.Header.Get("X-Request-ID"))
		req.Header.Set(HeaderSignature, sig)
	}
}

func injectSplitHeaders(h http.Header, connData *ConnData, reqData RequestData, risk *RiskAssessment) {
	if reqData.JA4H != "" {
		h.Set(HeaderJA4H, reqData.JA4H)
	}

	if connData != nil {
		tlsDeep := FormatTLSDeepSummary(connData)
		quicSum := FormatQUICSummary(connData)
		h3Sum := FormatH3Summary(connData)

		connData.RLock()
		ja4 := connData.JA4
		ja3 := connData.JA3
		ja3n := connData.JA3N
		ja4x := connData.JA4X
		certSHA := connData.ClientCertSHA
		spkiSHA := connData.ClientSPKISHA
		h2 := connData.AkamaiH2
		ja4t := connData.JA4T
		ttl := connData.IPTTL
		tcpRTT := connData.TCPRTT
		tlsRTT := connData.TLSHandshakeRTT
		connData.RUnlock()

		if ja4 != "" {
			h.Set(HeaderJA4, ja4)
		}
		if ja3 != "" {
			h.Set(HeaderJA3, ja3)
		}
		if ja3n != "" {
			h.Set(HeaderJA3N, ja3n)
		}
		if tlsDeep != "" {
			h.Set(HeaderTLSDeep, tlsDeep)
		}
		if ja4x != "" {
			h.Set(HeaderJA4X, ja4x)
		}
		if certSHA != "" {
			h.Set(HeaderClientCertSHA, certSHA)
		}
		if spkiSHA != "" {
			h.Set(HeaderClientSPKISHA, spkiSHA)
		}
		if h2 != "" {
			h.Set(HeaderH2, h2)
		}
		if h3Sum != "" {
			h.Set(HeaderH3, h3Sum)
		}
		if quicSum != "" {
			h.Set(HeaderQUIC, quicSum)
		}
		if ja4t != "" {
			h.Set(HeaderJA4T, ja4t)
		}
		if ttl > 0 {
			h.Set(HeaderIPTTL, strconv.FormatUint(uint64(ttl), 10))
		}
		if tcpRTT > 0 && tlsRTT > 0 {
			diffMs := (tlsRTT - tcpRTT).Milliseconds()
			h.Set(HeaderRTTDiff, strconv.FormatInt(diffMs, 10)+"ms")
		}
	}

	if risk != nil {
		h.Set(HeaderRiskScore, strconv.Itoa(risk.Score))
		if risk.Action != "" {
			h.Set(HeaderRiskAction, risk.Action)
		}
		if len(risk.Reasons) > 0 {
			h.Set(HeaderRiskReasons, strings.Join(risk.Reasons, ","))
		}
		if risk.RateKey != "" {
			h.Set(HeaderRateKey, risk.RateKey)
		}
	}
}

// ComputeHeaderSignature generates an HMAC-SHA256 signature header value ("t=<unix>,v1=<hex>").
func ComputeHeaderSignature(secret string, unixSec int64, method, host, reqURI, combinedFP, requestID string) string {
	tsStr := strconv.FormatInt(unixSec, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(tsStr))
	_, _ = mac.Write([]byte{'|'})
	_, _ = mac.Write([]byte(method))
	_, _ = mac.Write([]byte{'|'})
	_, _ = mac.Write([]byte(host))
	_, _ = mac.Write([]byte{'|'})
	_, _ = mac.Write([]byte(reqURI))
	_, _ = mac.Write([]byte{'|'})
	_, _ = mac.Write([]byte(combinedFP))
	_, _ = mac.Write([]byte{'|'})
	_, _ = mac.Write([]byte(requestID))
	sum := mac.Sum(nil)
	return "t=" + tsStr + ",v1=" + hex.EncodeToString(sum)
}

// VerifyHeaderSignature verifies an X-Fp-Signature header against secret within maxSkew.
func VerifyHeaderSignature(sigHeader, secret, method, host, reqURI, combinedFP, requestID string, now time.Time, maxSkew time.Duration) bool {
	if sigHeader == "" || secret == "" {
		return false
	}
	var tsPart, v1Part string
	for part := range strings.SplitSeq(sigHeader, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "t="):
			tsPart = strings.TrimPrefix(part, "t=")
		case strings.HasPrefix(part, "v1="):
			v1Part = strings.TrimPrefix(part, "v1=")
		}
	}
	if tsPart == "" || v1Part == "" {
		return false
	}
	ts, err := strconv.ParseInt(tsPart, 10, 64)
	if err != nil {
		return false
	}
	if maxSkew > 0 {
		skew := math.Abs(float64(now.Unix() - ts))
		if skew > maxSkew.Seconds() {
			return false
		}
	}
	expected := ComputeHeaderSignature(secret, ts, method, host, reqURI, combinedFP, requestID)
	return hmac.Equal([]byte(sigHeader), []byte(expected))
}

func sfString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := range len(s) {
		c := s[i]
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		if c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
