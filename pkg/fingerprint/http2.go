package fingerprint

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	h2ClientPreface = http2.ClientPreface
	h2FrameHeaders  = 0x01
	h2FrameCont     = 0x09

	h2FlagEndHeaders = 0x04
	h2FlagPadded     = 0x08
	h2FlagPriority   = 0x20
)

type pooledH2Parser struct {
	reader *bytes.Reader
	framer *http2.Framer
}

var h2ParserPool = sync.Pool{
	New: func() any {
		r := bytes.NewReader(nil)
		fr := http2.NewFramer(io.Discard, r)
		return &pooledH2Parser{
			reader: r,
			framer: fr,
		}
	},
}

// WrapFirstFlightConn wraps a cleartext or decrypted TLS connection to passively extract
// either the Akamai HTTP/2 fingerprint (S|WU|P|pseudo) or HTTP/1.x / HTTP/0.9 syntax signals
// on the first flight, switching permanently to a direct Read passthrough immediately afterward.
func WrapFirstFlightConn(conn net.Conn, data *ConnData, enableH2Tap bool) net.Conn {
	if conn == nil || data == nil {
		return conn
	}
	return &FirstFlightTapConn{
		Conn:        conn,
		data:        data,
		enableH2Tap: enableH2Tap,
	}
}

// FirstFlightTapConn inspects initial application bytes on a net.Conn and self-detaches once the first request headers arrive.
type FirstFlightTapConn struct {
	net.Conn

	data        *ConnData
	enableH2Tap bool
	tapDone     atomic.Bool
	mu          sync.Mutex
	buf         []byte
}

// FingerprintData implements Carrier.
func (c *FirstFlightTapConn) FingerprintData() *ConnData {
	return c.data
}

// UnwrapConn implements ConnUnwrapper.
func (c *FirstFlightTapConn) UnwrapConn() net.Conn {
	return c.Conn
}

// CloseWrite forwards half-close when supported by the underlying connection.
func (c *FirstFlightTapConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Read forwards reads directly once the first flight has been parsed.
func (c *FirstFlightTapConn) Read(p []byte) (int, error) {
	if c.tapDone.Load() {
		return c.Conn.Read(p)
	}

	n, err := c.Conn.Read(p)
	if n > 0 {
		c.inspectChunk(p[:n])
	}
	return n, err
}

func (c *FirstFlightTapConn) inspectChunk(chunk []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tapDone.Load() {
		return
	}

	remainingCap := MaxTLSHandshakeBytes - len(c.buf)
	if remainingCap > 0 {
		toCopy := min(len(chunk), remainingCap)
		c.buf = append(c.buf, chunk[:toCopy]...)
	}

	prefaceLen := len(h2ClientPreface)
	if len(c.buf) < prefaceLen {
		if !strings.HasPrefix(h2ClientPreface, string(c.buf)) {
			// Definitely not HTTP/2; try HTTP/1.x or HTTP/0.9 immediately.
			if ScanHTTP1FirstFlight(c.buf, c.data) || len(c.buf) >= MaxTLSHandshakeBytes {
				c.finishTapLocked()
			}
		}
		return
	}

	if string(c.buf[:prefaceLen]) == h2ClientPreface {
		if !c.enableH2Tap {
			c.finishTapLocked()
			return
		}
		complete, endOffset := hasCompleteH2FirstHeaders(c.buf[prefaceLen:])
		if complete {
			ParseH2FirstFlight(c.buf[:prefaceLen+endOffset], c.data)
			c.finishTapLocked()
			return
		}
		if len(c.buf) >= MaxTLSHandshakeBytes {
			ParseH2FirstFlight(c.buf, c.data)
			c.finishTapLocked()
		}
		return
	}

	if ScanHTTP1FirstFlight(c.buf, c.data) || len(c.buf) >= MaxTLSHandshakeBytes {
		c.finishTapLocked()
	}
}

func (c *FirstFlightTapConn) finishTapLocked() {
	c.buf = nil
	c.tapDone.Store(true)
}

// hasCompleteH2FirstHeaders walks 9-byte RFC 9113 frame headers after the 24-byte client preface
// and reports whether a complete HEADERS (+ optional CONTINUATION) block on a client stream is buffered.
func hasCompleteH2FirstHeaders(frames []byte) (complete bool, endOffset int) {
	pos := 0
	inHeadersStream := uint32(0)
	for pos+9 <= len(frames) {
		fLen := int(frames[pos])<<16 | int(frames[pos+1])<<8 | int(frames[pos+2])
		fType := frames[pos+3]
		fFlags := frames[pos+4]
		streamID := binary.BigEndian.Uint32(frames[pos+5:pos+9]) & 0x7fffffff
		nextPos := pos + 9 + fLen
		if nextPos > len(frames) {
			return false, 0
		}

		if fType == h2FrameHeaders && streamID > 0 {
			if fFlags&h2FlagEndHeaders != 0 {
				return true, nextPos
			}
			inHeadersStream = streamID
		} else if fType == h2FrameCont && inHeadersStream != 0 && streamID == inHeadersStream {
			if fFlags&h2FlagEndHeaders != 0 {
				return true, nextPos
			}
		}

		pos = nextPos
	}
	return false, 0
}

// ParseH2FirstFlight parses an HTTP/2 client preface and initial frames into AkamaiH2 (S|WU|P|pseudo) and H2HeaderOrder.
func ParseH2FirstFlight(raw []byte, out *ConnData) bool {
	if len(raw) < len(h2ClientPreface) || string(raw[:len(h2ClientPreface)]) != h2ClientPreface || out == nil {
		return false
	}

	frameBytes := raw[len(h2ClientPreface):]
	h2Indexed, h2Huffman := inspectRawHPACKSignals(frameBytes)

	p := h2ParserPool.Get().(*pooledH2Parser)
	defer func() {
		p.reader.Reset(nil)
		h2ParserPool.Put(p)
	}()

	p.reader.Reset(frameBytes)

	var (
		gotSettings   bool
		settingsParts []string
		hasGREASE     bool
		windowUpdate  uint64
		priorities    []string
		pseudos       []string
		regularNames  []string
		gotHeaders    bool
	)

	for !gotHeaders {
		fr, err := p.framer.ReadFrame()
		if err != nil {
			break
		}

		switch f := fr.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() || gotSettings {
				continue
			}
			gotSettings = true
			_ = f.ForeachSetting(func(s http2.Setting) error {
				if IsTLSGREASE(uint16(s.ID)) {
					hasGREASE = true
					return nil
				}
				settingsParts = append(settingsParts, strconv.FormatUint(uint64(uint16(s.ID)), 10)+":"+strconv.FormatUint(uint64(s.Val), 10))
				return nil
			})

		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				windowUpdate += uint64(f.Increment)
			}

		case *http2.PriorityFrame:
			priorities = append(priorities, formatAkamaiPriority(f.StreamID, f.PriorityParam))

		case *http2.HeadersFrame:
			if f.StreamID == 0 {
				continue
			}
			if f.HasPriority() {
				priorities = append(priorities, formatAkamaiPriority(f.StreamID, f.Priority))
			}

			var hbf bytes.Buffer
			hbf.Write(f.HeaderBlockFragment())
			endHeaders := f.HeadersEnded()
			for !endHeaders {
				nextFr, contErr := p.framer.ReadFrame()
				if contErr != nil {
					break
				}
				cf, ok := nextFr.(*http2.ContinuationFrame)
				if !ok || cf.StreamID != f.StreamID {
					break
				}
				hbf.Write(cf.HeaderBlockFragment())
				endHeaders = cf.HeadersEnded()
			}

			dec := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {
				if strings.HasPrefix(hf.Name, ":") {
					if tok := mapPseudoHeader(hf.Name); tok != "" {
						pseudos = append(pseudos, tok)
					}
					return
				}
				regularNames = append(regularNames, strings.ToLower(hf.Name))
			})
			_, _ = dec.Write(hbf.Bytes())
			_ = dec.Close()
			gotHeaders = true
		}
	}

	if !gotSettings && !gotHeaders && windowUpdate == 0 && len(priorities) == 0 {
		return false
	}

	wuStr := "00"
	if windowUpdate > 0 {
		wuStr = strconv.FormatUint(windowUpdate, 10)
	}
	prioStr := "0"
	if len(priorities) > 0 {
		prioStr = strings.Join(priorities, ",")
	}

	akamai := strings.Join(settingsParts, ";") + "|" + wuStr + "|" + prioStr + "|" + strings.Join(pseudos, ",")

	out.Lock()
	out.AkamaiH2 = akamai
	out.H2HasGREASE = hasGREASE
	out.H2Indexed = h2Indexed
	out.H2Huffman = h2Huffman
	if len(regularNames) > 0 {
		out.H2HeaderOrder = regularNames
	}
	out.Unlock()
	return true
}

func formatAkamaiPriority(streamID uint32, param http2.PriorityParam) string {
	excl := 0
	if param.Exclusive {
		excl = 1
	}
	weight := int(param.Weight) + 1
	return strconv.FormatUint(uint64(streamID), 10) + ":" +
		strconv.Itoa(excl) + ":" +
		strconv.FormatUint(uint64(param.StreamDep), 10) + ":" +
		strconv.Itoa(weight)
}

func inspectRawHPACKSignals(frames []byte) (indexed, huffman bool) {
	pos := 0
	for pos+9 <= len(frames) {
		fLen := int(frames[pos])<<16 | int(frames[pos+1])<<8 | int(frames[pos+2])
		fType := frames[pos+3]
		fFlags := frames[pos+4]
		nextPos := pos + 9 + fLen
		if nextPos > len(frames) {
			break
		}
		if fType == h2FrameHeaders && fLen > 0 {
			payload := frames[pos+9 : nextPos]
			offset := 0
			padLen := 0
			if fFlags&h2FlagPadded != 0 && offset < len(payload) {
				padLen = int(payload[offset])
				offset++
			}
			if fFlags&h2FlagPriority != 0 {
				offset += 5
			}
			if offset < len(payload)-padLen {
				block := payload[offset : len(payload)-padLen]
				return scanHPACKFirstBlock(block)
			}
			break
		}
		pos = nextPos
	}
	return false, false
}

func scanHPACKFirstBlock(block []byte) (indexed, huffman bool) {
	pos := 0
	steps := 0
	for pos < len(block) && steps < 32 {
		steps++
		b := block[pos]
		switch {
		case b&0x80 != 0:
			// Indexed Header Field Representation (RFC 7541 Section 6.1).
			_, n, ok := readHPACKInt(block[pos:], 7)
			if !ok {
				return indexed, huffman
			}
			pos += n
		case b&0xc0 == 0x40:
			// Literal Header Field with Incremental Indexing (RFC 7541 Section 6.2.1).
			indexed = true
			nameIdx, n, ok := readHPACKInt(block[pos:], 6)
			if !ok {
				return indexed, huffman
			}
			pos += n
			if nameIdx == 0 {
				h, sn, sok := skipHPACKString(block[pos:])
				if !sok {
					return indexed, huffman
				}
				huffman = huffman || h
				pos += sn
			}
			h, sn, sok := skipHPACKString(block[pos:])
			if !sok {
				return indexed, huffman
			}
			huffman = huffman || h
			pos += sn
		case b&0xe0 == 0x20:
			// Dynamic Table Size Update (RFC 7541 Section 6.3).
			_, n, ok := readHPACKInt(block[pos:], 5)
			if !ok {
				return indexed, huffman
			}
			pos += n
		default:
			// Literal Header Field without Indexing / Never Indexed (RFC 7541 Sections 6.2.2 & 6.2.3).
			nameIdx, n, ok := readHPACKInt(block[pos:], 4)
			if !ok {
				return indexed, huffman
			}
			pos += n
			if nameIdx == 0 {
				h, sn, sok := skipHPACKString(block[pos:])
				if !sok {
					return indexed, huffman
				}
				huffman = huffman || h
				pos += sn
			}
			h, sn, sok := skipHPACKString(block[pos:])
			if !sok {
				return indexed, huffman
			}
			huffman = huffman || h
			pos += sn
		}
	}
	return indexed, huffman
}

func readHPACKInt(b []byte, prefixBits uint8) (val uint64, consumed int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	mask := byte((1 << prefixBits) - 1)
	val = uint64(b[0] & mask)
	if val < uint64(mask) {
		return val, 1, true
	}
	shift := uint(0)
	for i := 1; i < len(b) && i < 10; i++ {
		val += uint64(b[i]&0x7f) << shift
		if b[i]&0x80 == 0 {
			return val, i + 1, true
		}
		shift += 7
	}
	return 0, 0, false
}

func skipHPACKString(b []byte) (isHuffman bool, consumed int, ok bool) {
	if len(b) == 0 {
		return false, 0, false
	}
	isHuffman = b[0]&0x80 != 0
	strLen, n, ok := readHPACKInt(b, 7)
	if !ok || strLen > uint64(len(b)-n) {
		return isHuffman, 0, false
	}
	return isHuffman, n + int(strLen), true
}
