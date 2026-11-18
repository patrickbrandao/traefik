package fingerprint

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

const (
	ipProtoTCP = 6

	ipv6ExtHopByHop  = 0
	ipv6ExtRouting   = 43
	ipv6ExtFragment  = 44
	ipv6ExtDestOpts  = 60
	maxIPv6ExtWalked = 8
)

// WrapConn attaches ConnData to an accepted net.Conn while preserving underlying connection unwrapping.
func WrapConn(conn net.Conn, data *ConnData) net.Conn {
	if conn == nil || data == nil {
		return conn
	}
	return &fpNetConn{
		Conn: conn,
		data: data,
	}
}

type fpNetConn struct {
	net.Conn

	data *ConnData
}

func (c *fpNetConn) FingerprintData() *ConnData {
	return c.data
}

func (c *fpNetConn) UnwrapConn() net.Conn {
	return c.Conn
}

// ParseRawSYN parses a raw IPv4 or IPv6 TCP SYN packet (as returned by Linux TCP_SAVED_SYN)
// and populates JA4T, IPTTL, IPDontFragment, IPECN, TCPMSS, and TCPWScale on out.
func ParseRawSYN(rawSYN []byte, out *ConnData) bool {
	if len(rawSYN) < 40 || out == nil {
		return false
	}

	var (
		ttl    uint8
		df     bool
		ecn    uint8
		tcpHdr []byte
	)

	version := rawSYN[0] >> 4
	switch version {
	case 4:
		ihl := int(rawSYN[0]&0x0f) * 4
		if ihl < 20 || len(rawSYN) < ihl+20 || rawSYN[9] != ipProtoTCP {
			return false
		}
		ttl = rawSYN[8]
		df = (rawSYN[6] & 0x40) != 0
		ecn = rawSYN[1] & 0x03
		tcpHdr = rawSYN[ihl:]

	case 6:
		ttl = rawSYN[7]
		ecn = (rawSYN[1] >> 4) & 0x03
		nextHdr := rawSYN[6]
		offset := 40
		for range maxIPv6ExtWalked {
			if nextHdr == ipProtoTCP {
				break
			}
			if len(rawSYN) < offset+8 {
				return false
			}
			switch nextHdr {
			case ipv6ExtHopByHop, ipv6ExtRouting, ipv6ExtDestOpts:
				nextHdr = rawSYN[offset]
				hdrLen := (int(rawSYN[offset+1]) + 1) * 8
				offset += hdrLen
			case ipv6ExtFragment:
				nextHdr = rawSYN[offset]
				offset += 8
			default:
				return false
			}
		}
		if nextHdr != ipProtoTCP || len(rawSYN) < offset+20 {
			return false
		}
		tcpHdr = rawSYN[offset:]

	default:
		return false
	}

	dataOffset := int(tcpHdr[12]>>4) * 4
	if dataOffset < 20 || len(tcpHdr) < dataOffset {
		return false
	}

	windowSize := binary.BigEndian.Uint16(tcpHdr[14:16])
	opts := tcpHdr[20:dataOffset]

	var (
		kindsBuf [32]uint8
		kinds    = kindsBuf[:0]
		mss      uint16
		wscale   uint8
	)

	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 {
			kinds = append(kinds, 0)
			break
		}
		if kind == 1 {
			kinds = append(kinds, 1)
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			break
		}
		kinds = append(kinds, kind)
		switch {
		case kind == 2 && optLen == 4:
			mss = binary.BigEndian.Uint16(opts[i+2 : i+4])
		case kind == 3 && optLen == 3:
			wscale = opts[i+2]
		}
		i += optLen
	}

	optsStr := "00"
	if len(kinds) > 0 {
		optsStr = joinUint8Dec(kinds, '-')
	}

	var b strings.Builder
	b.Grow(32)
	var numBuf [8]byte
	b.Write(strconv.AppendUint(numBuf[:0], uint64(windowSize), 10))
	b.WriteByte('_')
	b.WriteString(optsStr)
	b.WriteByte('_')
	b.Write(strconv.AppendUint(numBuf[:0], uint64(mss), 10))
	b.WriteByte('_')
	b.Write(strconv.AppendUint(numBuf[:0], uint64(wscale), 10))

	out.Lock()
	out.IPTTL = ttl
	out.IPDontFragment = df
	out.IPECN = ecn
	out.JA4T = b.String()
	out.TCPMSS = mss
	out.TCPWScale = wscale
	out.Unlock()
	return true
}
