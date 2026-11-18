package fingerprint

import (
	"net"
	"unicode/utf8"

	"github.com/pires/go-proxyproto"
)

// Custom PROXY Protocol v2 application TLV type codes (0xE0..0xEF) for edge-forwarded fingerprints.
const (
	TLVTypeCustomJA4    uint8 = 0xE0
	TLVTypeCustomJA4T   uint8 = 0xE1
	TLVTypeCustomIPTTL  uint8 = 0xE2
	TLVTypeCustomRawSYN uint8 = 0xE3
)

// CaptureProxyProtoTLVs extracts PROXY Protocol v2 TLVs from conn into out.
// Callers must only invoke this inside the connection goroutine after read deadlines are set,
// because ProxyHeader() performs network I/O on the first read.
func CaptureProxyProtoTLVs(conn net.Conn, out *ConnData) {
	if conn == nil || out == nil {
		return
	}

	ppConn := findProxyProtoConn(conn)
	if ppConn == nil {
		return
	}

	hdr := ppConn.ProxyHeader()
	if hdr == nil || hdr.Command != proxyproto.PROXY {
		return
	}

	tlvs, err := hdr.TLVs()
	if err != nil || len(tlvs) == 0 {
		return
	}

	tlvMap := make(map[uint8][]byte, len(tlvs))
	var (
		alpn      string
		authority string
		ja4       string
		ja4t      string
		ttl       uint8
		rawSYN    []byte
	)

	for _, tlv := range tlvs {
		cp := make([]byte, len(tlv.Value))
		copy(cp, tlv.Value)
		tCode := uint8(tlv.Type)
		tlvMap[tCode] = cp

		switch tlv.Type {
		case proxyproto.PP2_TYPE_ALPN:
			if utf8.Valid(cp) && len(cp) > 0 {
				alpn = string(cp)
			}
		case proxyproto.PP2_TYPE_AUTHORITY:
			if utf8.Valid(cp) && len(cp) > 0 {
				authority = string(cp)
			}
		default:
			switch tCode {
			case TLVTypeCustomJA4:
				if isSafeASCIIValue(cp) {
					ja4 = string(cp)
				}
			case TLVTypeCustomJA4T:
				if isSafeASCIIValue(cp) {
					ja4t = string(cp)
				}
			case TLVTypeCustomIPTTL:
				if len(cp) == 1 {
					ttl = cp[0]
				}
			case TLVTypeCustomRawSYN:
				rawSYN = cp
			}
		}
	}

	if len(rawSYN) > 0 {
		out.RLock()
		emptySYN := out.JA4T == ""
		out.RUnlock()
		if emptySYN {
			ParseRawSYN(rawSYN, out)
		}
	}

	out.Lock()
	out.ProxyProtoTLVs = tlvMap
	if alpn != "" && len(out.ALPNProtos) == 0 {
		out.ALPNProtos = []string{alpn}
	}
	if authority != "" && out.ServerName == "" {
		out.ServerName = authority
	}
	if ja4 != "" && out.JA4 == "" {
		out.JA4 = ja4
	}
	if ja4t != "" && out.JA4T == "" {
		out.JA4T = ja4t
	}
	if ttl > 0 && out.IPTTL == 0 {
		out.IPTTL = ttl
	}
	out.Unlock()
}

func findProxyProtoConn(conn net.Conn) *proxyproto.Conn {
	cur := conn
	for cur != nil {
		if pp, ok := cur.(*proxyproto.Conn); ok {
			return pp
		}
		if unwrapper, ok := cur.(ConnUnwrapper); ok {
			next := unwrapper.UnwrapConn()
			if next != cur {
				cur = next
				continue
			}
		}
		break
	}
	return nil
}

func isSafeASCIIValue(b []byte) bool {
	if len(b) == 0 || len(b) > 128 {
		return false
	}
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
