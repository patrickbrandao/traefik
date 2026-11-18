package fingerprint

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/textproto"
	"slices"
	"strings"
)

// ScanHTTP1FirstFlight inspects initial cleartext or post-TLS bytes for HTTP/0.9 or HTTP/1.x syntax signals.
// It returns complete=true once the full first request header block (or single HTTP/0.9 line) has been observed.
func ScanHTTP1FirstFlight(buf []byte, out *ConnData) bool {
	if len(buf) == 0 {
		return false
	}

	firstNL := bytes.IndexByte(buf, '\n')
	if firstNL < 0 {
		return len(buf) >= MaxTLSHandshakeBytes
	}

	bareLF := firstNL == 0 || buf[firstNL-1] != '\r'
	reqLine := buf[:firstNL]
	if !bareLF {
		reqLine = reqLine[:len(reqLine)-1]
	}

	sp1 := bytes.IndexByte(reqLine, ' ')
	if sp1 <= 0 {
		return true
	}
	method := reqLine[:sp1]
	if !isHTTPToken(method) {
		return true
	}

	rest := bytes.TrimLeft(reqLine[sp1+1:], " ")
	if len(rest) == 0 {
		return true
	}

	target, afterTarget, hasSpace := bytes.Cut(rest, []byte{' '})
	if !hasSpace {
		// No HTTP/x.y version token on the request line indicates raw HTTP/0.9.
		if out != nil {
			out.Lock()
			out.HTTP09Raw = true
			out.H1BareLF = bareLF
			out.Unlock()
		}
		return true
	}

	versionPart := bytes.TrimSpace(afterTarget)
	if !bytes.HasPrefix(versionPart, []byte("HTTP/")) {
		if out != nil {
			out.Lock()
			out.HTTP09Raw = true
			out.H1BareLF = bareLF
			out.Unlock()
		}
		return true
	}

	absForm := !bytes.EqualFold(method, []byte(http.MethodConnect)) &&
		(hasCaseInsensitivePrefix(target, "http://") || hasCaseInsensitivePrefix(target, "https://"))

	// Locate the end of the HTTP/1.x header block (\r\n\r\n or \n\n).
	headerEnd := findHTTP1HeaderEnd(buf, firstNL+1)
	if headerEnd < 0 {
		return len(buf) >= MaxTLSHandshakeBytes
	}

	var (
		order        []string
		nonCanonical int
		noSpaceColon bool
		allLower     = true
		allCanonical = true
		pos          = firstNL + 1
	)

	for pos < headerEnd {
		nlRel := bytes.IndexByte(buf[pos:headerEnd], '\n')
		if nlRel < 0 {
			break
		}
		lineEnd := pos + nlRel
		lineBareLF := lineEnd == pos || buf[lineEnd-1] != '\r'
		if lineBareLF {
			bareLF = true
		}
		line := buf[pos:lineEnd]
		if !lineBareLF {
			line = line[:len(line)-1]
		}
		pos = lineEnd + 1

		if len(line) == 0 {
			break
		}
		// Skip obsolete line folding continuations.
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}

		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		rawName := string(line[:colon])
		order = append(order, rawName)

		canonical := textproto.CanonicalMIMEHeaderKey(rawName)
		if rawName != canonical {
			nonCanonical++
			allCanonical = false
		}
		if rawName != strings.ToLower(rawName) {
			allLower = false
		}
		if colon+1 < len(line) && line[colon+1] != ' ' && line[colon+1] != '\t' {
			noSpaceColon = true
		}
	}

	casingProfile := "canonical"
	switch {
	case len(order) == 0:
		casingProfile = ""
	case allLower && nonCanonical > 0:
		casingProfile = "lower"
	case !allCanonical && !allLower:
		casingProfile = "mixed"
	}

	if out != nil {
		out.Lock()
		out.H1HeaderOrder = order
		out.H1CasingProfile = casingProfile
		out.H1NonCanonicalCount = nonCanonical
		out.H1NoSpaceAfterColon = noSpaceColon
		out.H1BareLF = bareLF
		out.H1AbsoluteForm = absForm
		out.Unlock()
	}

	return true
}

// ComputeJA4H computes the JA4H HTTP request fingerprint (a_b_c_d) across HTTP/0.9, 1.0, 1.1, 2, and 3.
func ComputeJA4H(req *http.Request, connData *ConnData, redactCookieValues bool, hmacSecret string) string {
	if req == nil {
		return ""
	}

	var b strings.Builder
	b.Grow(52)

	writeMethod2(&b, req.Method)
	b.WriteString(httpVersionCode(req, connData))

	cookieHeaders := req.Header.Values("Cookie")
	hasCookie := len(cookieHeaders) > 0
	hasReferer := req.Header.Get("Referer") != ""
	if hasCookie {
		b.WriteByte('c')
	} else {
		b.WriteByte('n')
	}
	if hasReferer {
		b.WriteByte('r')
	} else {
		b.WriteByte('n')
	}

	orderedHeaders := resolveOrderedHeaderNames(req, connData)
	writeTwoDigits(&b, min(len(orderedHeaders), 99))

	var lang [4]byte
	extractPrimaryLang4(req.Header.Get("Accept-Language"), &lang)
	b.Write(lang[:])
	b.WriteByte('_')

	if len(orderedHeaders) == 0 {
		b.WriteString(emptyHash12)
	} else {
		b.WriteString(sha256Hex12(strings.Join(orderedHeaders, ",")))
	}
	b.WriteByte('_')

	cookieNames, cookiePairs := parseSortedCookies(cookieHeaders)
	if len(cookieNames) == 0 {
		b.WriteString(emptyHash12)
		b.WriteByte('_')
		b.WriteString(emptyHash12)
		return b.String()
	}

	b.WriteString(sha256Hex12(strings.Join(cookieNames, ",")))
	b.WriteByte('_')

	if redactCookieValues {
		if hmacSecret != "" {
			b.WriteString(hmacSHA256Hex12(hmacSecret, strings.Join(cookiePairs, ",")))
		} else {
			b.WriteString(emptyHash12)
		}
	} else {
		b.WriteString(sha256Hex12(strings.Join(cookiePairs, ",")))
	}

	return b.String()
}

// InspectRequest extracts per-request JA4H and tunnel/subprotocol metadata.
func InspectRequest(req *http.Request, connData *ConnData, redactCookieValues bool, hmacSecret string) RequestData {
	if req == nil {
		return RequestData{}
	}

	wsExt := req.Header.Get("Sec-WebSocket-Extensions")
	isWS := strings.EqualFold(req.Header.Get("Upgrade"), "websocket") || wsExt != ""
	ct := req.Header.Get("Content-Type")
	grpcEnc := req.Header.Get("Grpc-Accept-Encoding")
	isGRPC := strings.HasPrefix(strings.ToLower(ct), "application/grpc") || grpcEnc != ""

	return RequestData{
		JA4H:                ComputeJA4H(req, connData, redactCookieValues, hmacSecret),
		HTTPVersion:         httpVersionCode(req, connData),
		IsWebSocket:         isWS,
		IsGRPC:              isGRPC,
		IsConnect:           req.Method == http.MethodConnect,
		WebSocketExtensions: wsExt,
		GRPCAcceptEncoding:  grpcEnc,
	}
}

func resolveOrderedHeaderNames(req *http.Request, connData *ConnData) []string {
	var captured []string
	preserveCase := false

	if connData != nil {
		connData.RLock()
		switch req.ProtoMajor {
		case 3:
			if len(connData.H3HeaderOrder) > 0 {
				captured = slices.Clone(connData.H3HeaderOrder)
			}
		case 2:
			if len(connData.H2HeaderOrder) > 0 {
				captured = slices.Clone(connData.H2HeaderOrder)
			}
		default:
			if len(connData.H1HeaderOrder) > 0 {
				captured = slices.Clone(connData.H1HeaderOrder)
				preserveCase = true
			}
		}
		connData.RUnlock()
	}

	if len(captured) > 0 {
		seen := make(map[string]struct{}, len(captured))
		out := make([]string, 0, len(captured))
		for _, name := range captured {
			if isIgnoredJA4HHeader(name) {
				continue
			}
			canon := textproto.CanonicalMIMEHeaderKey(name)
			// Host is moved from req.Header to req.Host by net/http, so keep Host when req.Host is non-empty.
			if canon != "Host" {
				if _, exists := req.Header[canon]; !exists {
					continue
				}
			} else if req.Host == "" {
				continue
			}
			seen[canon] = struct{}{}
			if preserveCase {
				out = append(out, name)
			} else {
				out = append(out, strings.ToLower(name))
			}
		}

		// Append any extra headers added on subsequent keep-alive requests in deterministic order.
		var extras []string
		for k := range req.Header {
			if isIgnoredJA4HHeader(k) {
				continue
			}
			if _, ok := seen[k]; !ok {
				if preserveCase {
					extras = append(extras, k)
				} else {
					extras = append(extras, strings.ToLower(k))
				}
			}
		}
		if len(extras) > 0 {
			slices.Sort(extras)
			out = append(out, extras...)
		}
		return out
	}

	// Fallback when wire order was not tapped (e.g. synthetic in-memory requests).
	var names []string
	if req.Host != "" && req.ProtoMajor < 2 {
		names = append(names, "Host")
	}
	var rest []string
	for k := range req.Header {
		if isIgnoredJA4HHeader(k) {
			continue
		}
		if req.ProtoMajor >= 2 {
			rest = append(rest, strings.ToLower(k))
		} else {
			rest = append(rest, k)
		}
	}
	slices.Sort(rest)
	return append(names, rest...)
}

func isIgnoredJA4HHeader(name string) bool {
	if strings.HasPrefix(name, ":") {
		return true
	}
	return strings.EqualFold(name, "Cookie") ||
		strings.EqualFold(name, "Referer") ||
		IsReservedHeaderName(name)
}

func writeMethod2(b *strings.Builder, method string) {
	if len(method) == 0 {
		b.WriteString("00")
		return
	}
	b.WriteByte(asciiLower(method[0]))
	if len(method) >= 2 {
		b.WriteByte(asciiLower(method[1]))
	} else {
		b.WriteByte('0')
	}
}

func httpVersionCode(req *http.Request, connData *ConnData) string {
	if connData != nil {
		connData.RLock()
		is09 := connData.HTTP09Raw
		connData.RUnlock()
		if is09 {
			return "09"
		}
	}
	switch req.ProtoMajor {
	case 3:
		return "30"
	case 2:
		return "20"
	case 1:
		if req.ProtoMinor == 0 {
			return "10"
		}
		return "11"
	default:
		return "00"
	}
}

func extractPrimaryLang4(acceptLang string, dst *[4]byte) {
	*dst = [4]byte{'0', '0', '0', '0'}
	if acceptLang == "" {
		return
	}
	primary, _, _ := strings.Cut(acceptLang, ",")
	primary, _, _ = strings.Cut(primary, ";")
	idx := 0
	for i := 0; i < len(primary) && idx < 4; i++ {
		c := primary[i]
		if isASCIIAlphaNum(c) {
			dst[idx] = asciiLower(c)
			idx++
		}
	}
}

func parseSortedCookies(cookieHeaders []string) (names, pairs []string) {
	if len(cookieHeaders) == 0 {
		return nil, nil
	}
	for _, hdr := range cookieHeaders {
		for part := range strings.SplitSeq(hdr, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, val, hasEq := strings.Cut(part, "=")
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			names = append(names, name)
			if hasEq {
				pairs = append(pairs, name+"="+strings.TrimSpace(val))
			} else {
				pairs = append(pairs, name+"=")
			}
		}
	}
	slices.Sort(names)
	slices.Sort(pairs)
	return names, pairs
}

func sha256Hex12(s string) string {
	sum := sha256.Sum256([]byte(s))
	var out [12]byte
	hex.Encode(out[:], sum[:6])
	return string(out[:])
}

func hmacSHA256Hex12(secret, s string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(s))
	sum := mac.Sum(nil)
	var out [12]byte
	hex.Encode(out[:], sum[:6])
	return string(out[:])
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func isHTTPToken(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !isASCIIAlphaNum(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func hasCaseInsensitivePrefix(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range len(prefix) {
		if asciiLower(b[i]) != prefix[i] {
			return false
		}
	}
	return true
}

func findHTTP1HeaderEnd(buf []byte, start int) int {
	for i := start; i < len(buf); i++ {
		if buf[i] == '\n' {
			if i == start {
				return i + 1
			}
			if i == start+1 && buf[start] == '\r' {
				return i + 1
			}
			// Check whether the next line is empty (\r\n or \n).
			if i+1 < len(buf) && buf[i+1] == '\n' {
				return i + 2
			}
			if i+2 < len(buf) && buf[i+1] == '\r' && buf[i+2] == '\n' {
				return i + 3
			}
		}
	}
	return -1
}
