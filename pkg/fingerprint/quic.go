package fingerprint

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"hash/fnv"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	http3qlog "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

const (
	// QUICVersion1 is IETF QUIC v1 (RFC 9000).
	QUICVersion1 uint32 = 0x00000001
	// QUICVersion2 is IETF QUIC v2 (RFC 9369).
	QUICVersion2 uint32 = 0x6b3343cf

	quicShardsCount     = 32
	quicMaxPerShard     = 256
	quicEntryTTL        = 5 * time.Second
	maxQUICTraceEvents  = 64
	maxUniStreamsLogged = 8
)

// Public Initial packet salts defined in RFC 9001 Section 5.2 (v1) and RFC 9369 Section 3.2 (v2).
var (
	quicV1InitialSalt = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
	quicV2InitialSalt = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
	}
)

type byteSpan struct {
	start int
	end   int
}

type cryptoReassembler struct {
	buf   []byte
	spans []byteSpan
}

func (r *cryptoReassembler) insert(offset int, data []byte) ([]byte, bool) {
	if len(data) == 0 || offset < 0 || offset >= MaxTLSHandshakeBytes {
		return nil, false
	}
	end := min(offset+len(data), MaxTLSHandshakeBytes)
	data = data[:end-offset]

	if len(r.buf) < end {
		grown := make([]byte, end, max(end, 2048))
		copy(grown, r.buf)
		r.buf = grown
	}
	copy(r.buf[offset:end], data)

	r.spans = append(r.spans, byteSpan{start: offset, end: end})
	slices.SortFunc(r.spans, func(a, b byteSpan) int {
		return a.start - b.start
	})

	merged := r.spans[:0]
	for _, sp := range r.spans {
		if len(merged) == 0 || sp.start > merged[len(merged)-1].end {
			merged = append(merged, sp)
		} else if sp.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = sp.end
		}
	}
	r.spans = merged

	if len(r.spans) == 0 || r.spans[0].start != 0 || r.spans[0].end < 4 {
		return nil, false
	}
	if r.buf[0] != tlsHandshakeClient {
		return nil, false
	}
	msgLen := int(r.buf[1])<<16 | int(r.buf[2])<<8 | int(r.buf[3])
	totalNeeded := 4 + msgLen
	if totalNeeded > MaxTLSHandshakeBytes {
		return nil, false
	}
	if r.spans[0].end >= totalNeeded {
		return r.buf[:totalNeeded], true
	}
	return nil, false
}

type quicInitialEntry struct {
	key        string
	createdAt  time.Time
	connData   *ConnData
	reassemble cryptoReassembler
	parsedCH   bool
	claimed    bool
}

type quicShard struct {
	mu      sync.Mutex
	entries map[string]*quicInitialEntry
	order   []string
	ja4Map  map[string]fallbackJA4Entry
}

type fallbackJA4Entry struct {
	ja4       string
	createdAt time.Time
}

// QUICTracker coordinates UDP Initial packet inspection and qlog connection tracing without global locks.
type QUICTracker struct {
	shards [quicShardsCount]quicShard
}

// NewQUICTracker initializes a sharded bounded tracker for QUIC Initial decryption and qlog correlation.
func NewQUICTracker() *QUICTracker {
	t := &QUICTracker{}
	for i := range t.shards {
		t.shards[i].entries = make(map[string]*quicInitialEntry)
		t.shards[i].ja4Map = make(map[string]fallbackJA4Entry)
	}
	return t
}

// WrapPacketConn wraps conn so incoming QUIC Initial datagrams are measured and decrypted before quic-go processes them.
func (t *QUICTracker) WrapPacketConn(conn net.PacketConn) net.PacketConn {
	if conn == nil || t == nil {
		return conn
	}
	return &fpPacketConn{
		PacketConn: conn,
		udpConn:    extractUDPConn(conn),
		tracker:    t,
	}
}

func extractUDPConn(conn net.PacketConn) *net.UDPConn {
	if uc, ok := conn.(*net.UDPConn); ok {
		return uc
	}
	return nil
}

type fpPacketConn struct {
	net.PacketConn

	udpConn *net.UDPConn
	tracker *QUICTracker
}

func (c *fpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.udpConn != nil {
		n, addr, ttl, ecn, err := ReadPacketUDPWithOOB(c.udpConn, p)
		if err == nil && n > 0 {
			c.tracker.InspectDatagram(p[:n], ttl, ecn)
		}
		return n, addr, err
	}

	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil && n > 0 {
		c.tracker.InspectDatagram(p[:n], 0, 0)
	}
	return n, addr, err
}

func (c *fpPacketConn) SetReadBuffer(size int) error {
	if setter, ok := c.PacketConn.(interface{ SetReadBuffer(size int) error }); ok {
		return setter.SetReadBuffer(size)
	}
	return nil
}

func (c *fpPacketConn) SetWriteBuffer(size int) error {
	if setter, ok := c.PacketConn.(interface{ SetWriteBuffer(size int) error }); ok {
		return setter.SetWriteBuffer(size)
	}
	return nil
}

func (c *fpPacketConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.PacketConn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		return sc.SyscallConn()
	}
	return nil, syscall.EINVAL
}

// InspectDatagram inspects a raw UDP payload for IETF QUIC v1/v2 Initial packets or legacy gQUIC headers.
func (t *QUICTracker) InspectDatagram(datagram []byte, ttl, ecn uint8) {
	if len(datagram) < 7 {
		return
	}

	firstByte := datagram[0]
	if firstByte&0x80 == 0 {
		// Short header (1-RTT data packet) requires zero inspection work.
		return
	}

	version := binary.BigEndian.Uint32(datagram[1:5])
	if version == 0 {
		// Version Negotiation packet.
		return
	}

	dcidLen := int(datagram[5])
	if dcidLen == 0 || dcidLen > 20 || len(datagram) < 6+dcidLen+1 {
		return
	}
	dcid := datagram[6 : 6+dcidLen]

	if isLegacyGQUICVersion(version) {
		dcidKey := string(dcid)
		entry := t.getOrCreateEntry(dcidKey, time.Now())
		entry.connData.Lock()
		entry.connData.IsQUIC = true
		entry.connData.gQUICVersion = string(datagram[1:5])
		if entry.connData.UDPPayloadSize == 0 && len(datagram) <= 65535 {
			entry.connData.UDPPayloadSize = uint16(len(datagram))
		}
		entry.connData.Unlock()
		return
	}

	if !isInitialPacket(firstByte, version) {
		return
	}

	pos := 6 + dcidLen
	scidLen := int(datagram[pos])
	pos++
	if scidLen > 20 || len(datagram) < pos+scidLen {
		return
	}
	pos += scidLen

	tokenLen, nTok, ok := readQUICVarint(datagram[pos:])
	if !ok || tokenLen > uint64(len(datagram)-pos-nTok) {
		return
	}
	pos += nTok + int(tokenLen)

	payloadLen, nLen, ok := readQUICVarint(datagram[pos:])
	if !ok {
		return
	}
	pos += nLen
	pnOffset := pos

	if payloadLen < 20 || payloadLen > uint64(len(datagram)-pnOffset) {
		return
	}
	totalPktLen := pnOffset + int(payloadLen)

	coalesced0RTT := false
	if len(datagram) > totalPktLen {
		rem := datagram[totalPktLen:]
		if len(rem) >= 5 && rem[0]&0x80 != 0 && is0RTTPacket(rem[0], version) {
			coalesced0RTT = true
		}
	}

	plaintext, pnLen, ok := decryptQUICInitialPacket(datagram[:totalPktLen], pnOffset, version, dcid)
	if !ok {
		return
	}

	now := time.Now()
	dcidKey := string(dcid)
	sh := t.shardFor(dcidKey)
	sh.mu.Lock()
	entry := t.getOrCreateEntryLocked(sh, dcidKey, now)

	entry.connData.Lock()
	entry.connData.IsQUIC = true
	if entry.connData.UDPPayloadSize == 0 && len(datagram) <= 65535 {
		entry.connData.UDPPayloadSize = uint16(len(datagram))
	}
	if ttl > 0 && entry.connData.IPTTL == 0 {
		entry.connData.IPTTL = ttl
	}
	if ecn > 0 && entry.connData.IPECN == 0 {
		entry.connData.IPECN = ecn
	}
	if entry.connData.QUICVersion == 0 {
		entry.connData.QUICVersion = version
		entry.connData.QUICDCIDLen = uint8(dcidLen)
		entry.connData.QUICSCIDLen = uint8(scidLen)
		entry.connData.QUICPacketNumLen = pnLen
	}
	if coalesced0RTT {
		entry.connData.QUICCoalesced0RTT = true
	}
	entry.connData.Unlock()

	var chBytes []byte
	if !entry.parsedCH {
		framesLayout, completedCH := parseQUICInitialFrames(plaintext, &entry.reassemble)
		if framesLayout != "" {
			entry.connData.Lock()
			if entry.connData.QUICInitialFrames == "" {
				entry.connData.QUICInitialFrames = framesLayout
			}
			entry.connData.Unlock()
		}
		if len(completedCH) > 0 {
			entry.parsedCH = true
			chBytes = make([]byte, len(completedCH))
			copy(chBytes, completedCH)
			if entry.claimed {
				delete(sh.entries, dcidKey)
			}
		}
	}
	sh.mu.Unlock()

	if len(chBytes) > 0 {
		_ = ParseClientHelloHandshake(chBytes, true, entry.connData)
	}
}

// StoreFallbackJA4 stores a JA4 string keyed by remote address for short-lived fallback correlation.
func (t *QUICTracker) StoreFallbackJA4(remoteAddr, ja4 string) {
	if t == nil || remoteAddr == "" || ja4 == "" {
		return
	}
	now := time.Now()
	sh := t.shardFor(remoteAddr)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if len(sh.ja4Map) >= quicMaxPerShard {
		for k, v := range sh.ja4Map {
			if now.Sub(v.createdAt) > quicEntryTTL {
				delete(sh.ja4Map, k)
			}
		}
		if len(sh.ja4Map) >= quicMaxPerShard {
			clear(sh.ja4Map)
		}
	}
	sh.ja4Map[remoteAddr] = fallbackJA4Entry{ja4: ja4, createdAt: now}
}

// LoadFallbackJA4 retrieves and removes a fallback JA4 entry for remoteAddr if still fresh.
func (t *QUICTracker) LoadFallbackJA4(remoteAddr string) string {
	if t == nil || remoteAddr == "" {
		return ""
	}
	sh := t.shardFor(remoteAddr)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	entry, ok := sh.ja4Map[remoteAddr]
	if !ok {
		return ""
	}
	delete(sh.ja4Map, remoteAddr)
	if time.Since(entry.createdAt) > quicEntryTTL {
		return ""
	}
	return entry.ja4
}

// Tracer returns a quic.Config.Tracer callback that binds Initial packet data to the QUIC connection qlog trace.
func (t *QUICTracker) Tracer(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	if isClient || t == nil {
		return nil
	}
	dcidKey := string(connID.Bytes())
	sh := t.shardFor(dcidKey)
	sh.mu.Lock()
	var data *ConnData
	if entry, ok := sh.entries[dcidKey]; ok {
		data = entry.connData
		entry.claimed = true
		if entry.parsedCH {
			delete(sh.entries, dcidKey)
		}
	} else {
		data = NewConnData()
		data.IsQUIC = true
	}
	sh.mu.Unlock()

	return NewQUICTrace(data)
}

func (t *QUICTracker) shardFor(key string) *quicShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &t.shards[h.Sum32()%quicShardsCount]
}

func (t *QUICTracker) getOrCreateEntry(dcidKey string, now time.Time) *quicInitialEntry {
	sh := t.shardFor(dcidKey)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return t.getOrCreateEntryLocked(sh, dcidKey, now)
}

func (t *QUICTracker) getOrCreateEntryLocked(sh *quicShard, dcidKey string, now time.Time) *quicInitialEntry {
	if existing, ok := sh.entries[dcidKey]; ok {
		return existing
	}

	if len(sh.entries) >= quicMaxPerShard {
		evictExpiredOrOldest(sh, now)
	}

	entry := &quicInitialEntry{
		key:       dcidKey,
		createdAt: now,
		connData:  NewConnData(),
	}
	entry.connData.IsQUIC = true
	sh.entries[dcidKey] = entry
	sh.order = append(sh.order, dcidKey)
	return entry
}

func evictExpiredOrOldest(sh *quicShard, now time.Time) {
	kept := sh.order[:0]
	evicted := false
	for _, k := range sh.order {
		e, ok := sh.entries[k]
		if !ok {
			continue
		}
		if now.Sub(e.createdAt) > quicEntryTTL {
			delete(sh.entries, k)
			evicted = true
			continue
		}
		kept = append(kept, k)
	}
	sh.order = kept

	if !evicted && len(sh.order) > 0 {
		oldestKey := sh.order[0]
		sh.order = sh.order[1:]
		delete(sh.entries, oldestKey)
	}
}

// QUICTrace implements qlogwriter.Trace in memory and stops recording once the HTTP/3 handshake and first request headers arrive.
type QUICTrace struct {
	data       *ConnData
	traceDone  atomic.Bool
	eventCount atomic.Int32

	mu          sync.Mutex
	uniStreams  []string
	gotSettings bool
	gotHeaders  bool
}

// NewQUICTrace creates an in-memory qlogwriter.Trace backed by data.
func NewQUICTrace(data *ConnData) *QUICTrace {
	if data == nil {
		data = NewConnData()
		data.IsQUIC = true
	}
	return &QUICTrace{data: data}
}

// ConnData returns the ConnData populated by this QUIC trace.
func (qt *QUICTrace) ConnData() *ConnData {
	if qt == nil {
		return nil
	}
	return qt.data
}

// AddProducer implements qlogwriter.Trace.
func (qt *QUICTrace) AddProducer() qlogwriter.Recorder {
	return &quicRecorder{trace: qt}
}

type quicRecorder struct {
	trace *QUICTrace
}

func (r *quicRecorder) Close() error {
	return nil
}

func (r *quicRecorder) RecordEvent(ev qlogwriter.Event) {
	qt := r.trace
	if qt == nil || qt.traceDone.Load() {
		return
	}

	switch e := ev.(type) {
	case qlog.ParametersSet:
		if e.Initiator == qlog.InitiatorRemote {
			qt.handleParametersSet(&e)
		}

	case qlog.MetricsUpdated:
		rtt := e.MinRTT
		if rtt <= 0 {
			rtt = e.LatestRTT
		}
		if rtt > 0 {
			qt.data.Lock()
			if qt.data.TCPRTT == 0 {
				qt.data.TCPRTT = rtt
			}
			qt.data.Unlock()
		}

	case http3qlog.StreamTypeSet:
		if e.Initiator == http3qlog.InitiatorRemote {
			qt.handleStreamTypeSet(e)
		}

	case http3qlog.FrameParsed:
		qt.handleH3FrameParsed(e)

	default:
		// High-frequency data-plane events (PacketSent, PacketReceived) do not count toward the control budget,
		// avoiding premature trace shutdown before the first HTTP/3 request stream arrives.
		return
	}

	if qt.eventCount.Add(1) >= maxQUICTraceEvents {
		qt.traceDone.Store(true)
	}
}

func (qt *QUICTrace) handleParametersSet(e *qlog.ParametersSet) {
	qt.data.Lock()
	defer qt.data.Unlock()

	if e.DisableActiveMigration {
		qt.data.QUICDisableMig = true
	}
	if qt.data.QUICTransportParams == "" {
		var parts []string
		if e.MaxIdleTimeout > 0 {
			parts = append(parts, "1:"+strconv.FormatInt(e.MaxIdleTimeout.Milliseconds(), 10))
		}
		if e.MaxUDPPayloadSize > 0 {
			parts = append(parts, "3:"+strconv.FormatInt(int64(e.MaxUDPPayloadSize), 10))
		}
		if e.InitialMaxData > 0 {
			parts = append(parts, "4:"+strconv.FormatInt(int64(e.InitialMaxData), 10))
		}
		if e.InitialMaxStreamDataBidiLocal > 0 {
			parts = append(parts, "5:"+strconv.FormatInt(int64(e.InitialMaxStreamDataBidiLocal), 10))
		}
		if e.InitialMaxStreamDataBidiRemote > 0 {
			parts = append(parts, "6:"+strconv.FormatInt(int64(e.InitialMaxStreamDataBidiRemote), 10))
		}
		if e.InitialMaxStreamDataUni > 0 {
			parts = append(parts, "7:"+strconv.FormatInt(int64(e.InitialMaxStreamDataUni), 10))
		}
		if e.InitialMaxStreamsBidi > 0 {
			parts = append(parts, "8:"+strconv.FormatInt(e.InitialMaxStreamsBidi, 10))
		}
		if e.InitialMaxStreamsUni > 0 {
			parts = append(parts, "9:"+strconv.FormatInt(e.InitialMaxStreamsUni, 10))
		}
		if e.DisableActiveMigration {
			parts = append(parts, "c")
		}
		if e.ActiveConnectionIDLimit > 0 {
			parts = append(parts, "e:"+strconv.FormatUint(e.ActiveConnectionIDLimit, 10))
		}
		qt.data.QUICTransportParams = strings.Join(parts, ";")
	}
}

func (qt *QUICTrace) handleStreamTypeSet(e http3qlog.StreamTypeSet) {
	var token string
	var isGREASE bool
	switch e.StreamType {
	case http3qlog.StreamTypeControl:
		token = "0"
	case http3qlog.StreamTypePush:
		token = "1"
	case http3qlog.StreamTypeQPACKEncode:
		token = "2"
	case http3qlog.StreamTypeQPACKDecode:
		token = "3"
	default:
		if IsH3GREASE(e.StreamTypeBytes) {
			token = "grease"
			isGREASE = true
		} else {
			token = strconv.FormatUint(e.StreamTypeBytes, 16)
		}
	}

	qt.mu.Lock()
	if len(qt.uniStreams) < maxUniStreamsLogged {
		qt.uniStreams = append(qt.uniStreams, token)
	}
	joined := strings.Join(qt.uniStreams, ",")
	qt.mu.Unlock()

	qt.data.Lock()
	qt.data.H3UniStreams = joined
	if isGREASE {
		qt.data.H3HasGREASE = true
	}
	qt.data.Unlock()
}

func (qt *QUICTrace) handleH3FrameParsed(e http3qlog.FrameParsed) {
	switch f := e.Frame.Frame.(type) {
	case http3qlog.SettingsFrame:
		settingsStr, hasGREASE := formatH3Settings(f)
		qt.mu.Lock()
		qt.gotSettings = true
		done := qt.gotSettings && qt.gotHeaders
		qt.mu.Unlock()

		qt.data.Lock()
		if qt.data.H3Settings == "" {
			qt.data.H3Settings = settingsStr
		}
		if hasGREASE {
			qt.data.H3HasGREASE = true
		}
		qt.data.Unlock()

		if done {
			qt.traceDone.Store(true)
		}

	case http3qlog.ReservedFrame:
		qt.data.Lock()
		qt.data.H3HasGREASE = true
		qt.data.Unlock()

	case http3qlog.HeadersFrame:
		qt.mu.Lock()
		already := qt.gotHeaders
		qt.gotHeaders = true
		done := qt.gotSettings && qt.gotHeaders
		qt.mu.Unlock()

		if !already {
			pseudo, regular := extractH3HeaderOrder(f.HeaderFields)
			qt.data.Lock()
			qt.data.H3PseudoOrder = pseudo
			qt.data.H3HeaderOrder = regular
			qt.data.Unlock()
		}
		if done {
			qt.traceDone.Store(true)
		}
	}
}

func formatH3Settings(f http3qlog.SettingsFrame) (string, bool) {
	type kv struct {
		id  uint64
		val uint64
	}
	var items []kv
	hasGREASE := false

	if f.MaxFieldSectionSize >= 0 {
		items = append(items, kv{id: 0x06, val: uint64(f.MaxFieldSectionSize)})
	}
	if f.ExtendedConnect >= 0 {
		items = append(items, kv{id: 0x08, val: uint64(f.ExtendedConnect)})
	}
	if f.Datagram >= 0 {
		items = append(items, kv{id: 0x33, val: uint64(f.Datagram)})
	}
	for id, val := range f.Other {
		if IsH3GREASE(id) {
			hasGREASE = true
			continue
		}
		items = append(items, kv{id: id, val: val})
	}

	slices.SortFunc(items, func(a, b kv) int {
		if a.id < b.id {
			return -1
		}
		if a.id > b.id {
			return 1
		}
		return 0
	})

	var b strings.Builder
	for i, it := range items {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(strconv.FormatUint(it.id, 16))
		b.WriteByte(':')
		b.WriteString(strconv.FormatUint(it.val, 10))
	}
	return b.String(), hasGREASE
}

func extractH3HeaderOrder(fields []http3qlog.HeaderField) (pseudo string, regular []string) {
	var pseudos []string
	for _, hf := range fields {
		if strings.HasPrefix(hf.Name, ":") {
			if tok := mapPseudoHeader(hf.Name); tok != "" {
				pseudos = append(pseudos, tok)
			}
			continue
		}
		regular = append(regular, strings.ToLower(hf.Name))
	}
	return strings.Join(pseudos, ","), regular
}

func mapPseudoHeader(name string) string {
	switch name {
	case ":method":
		return "m"
	case ":authority":
		return "a"
	case ":scheme":
		return "s"
	case ":path":
		return "p"
	case ":protocol":
		return "pr"
	default:
		return ""
	}
}

func isLegacyGQUICVersion(ver uint32) bool {
	return (ver>>16) == 0x5130 && ((ver>>8)&0xff) >= '3' && ((ver>>8)&0xff) <= '5'
}

func isInitialPacket(firstByte byte, version uint32) bool {
	pktType := (firstByte & 0x30) >> 4
	switch version {
	case QUICVersion1:
		return pktType == 0x00
	case QUICVersion2:
		return pktType == 0x01
	default:
		return false
	}
}

func is0RTTPacket(firstByte byte, version uint32) bool {
	pktType := (firstByte & 0x30) >> 4
	switch version {
	case QUICVersion1:
		return pktType == 0x01
	case QUICVersion2:
		return pktType == 0x02
	default:
		return false
	}
}

// decryptQUICInitialPacket removes header protection and opens AES-128-GCM for QUIC v1 and v2 Initial packets.
func decryptQUICInitialPacket(pkt []byte, pnOffset int, version uint32, dcid []byte) (plaintext []byte, pnLen uint8, ok bool) {
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(pkt) {
		return nil, 0, false
	}

	var (
		salt     []byte
		keyLabel string
		ivLabel  string
		hpLabel  string
	)
	switch version {
	case QUICVersion1:
		salt = quicV1InitialSalt
		keyLabel = "quic key"
		ivLabel = "quic iv"
		hpLabel = "quic hp"
	case QUICVersion2:
		salt = quicV2InitialSalt
		keyLabel = "quicv2 key"
		ivLabel = "quicv2 iv"
		hpLabel = "quicv2 hp"
	default:
		return nil, 0, false
	}

	initialSecret, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, 0, false
	}
	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", 32)
	if err != nil {
		return nil, 0, false
	}
	key, err := hkdfExpandLabel(clientSecret, keyLabel, 16)
	if err != nil {
		return nil, 0, false
	}
	iv, err := hkdfExpandLabel(clientSecret, ivLabel, 12)
	if err != nil {
		return nil, 0, false
	}
	hpKey, err := hkdfExpandLabel(clientSecret, hpLabel, 16)
	if err != nil {
		return nil, 0, false
	}

	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, 0, false
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[sampleOffset:sampleOffset+16])

	// Unmask into a copy so the caller's UDP receive buffer remains untouched for quic-go.
	hdrCopy := make([]byte, pnOffset+4)
	copy(hdrCopy, pkt[:pnOffset+4])
	hdrCopy[0] ^= mask[0] & 0x0f
	decodedPNLen := int(hdrCopy[0]&0x03) + 1

	var pn uint64
	for i := range decodedPNLen {
		hdrCopy[pnOffset+i] ^= mask[1+i]
		pn = (pn << 8) | uint64(hdrCopy[pnOffset+i])
	}

	var nonce [12]byte
	copy(nonce[:], iv)
	var pnBytes [8]byte
	binary.BigEndian.PutUint64(pnBytes[:], pn)
	for i := range 8 {
		nonce[4+i] ^= pnBytes[i]
	}

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, false
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, 0, false
	}

	aad := hdrCopy[:pnOffset+decodedPNLen]
	ciphertext := pkt[pnOffset+decodedPNLen:]
	opened, err := gcm.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, 0, false
	}
	return opened, uint8(decodedPNLen), true
}

func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	const prefix = "tls13 "
	fullLen := len(prefix) + len(label)
	var info [32]byte
	info[0] = byte(length >> 8)
	info[1] = byte(length)
	info[2] = byte(fullLen)
	n := copy(info[3:], prefix)
	n += copy(info[3+n:], label)
	info[3+n] = 0
	return hkdf.Expand(sha256.New, secret, string(info[:4+n]), length)
}

func parseQUICInitialFrames(plaintext []byte, reasm *cryptoReassembler) (layout string, completedCH []byte) {
	var frameTypes []string
	appendFrame := func(name string) {
		if len(frameTypes) == 0 || frameTypes[len(frameTypes)-1] != name {
			frameTypes = append(frameTypes, name)
		}
	}

	pos := 0
	for pos < len(plaintext) {
		ft, n, ok := readQUICVarint(plaintext[pos:])
		if !ok {
			break
		}
		pos += n

		switch ft {
		case 0x00:
			appendFrame("PADDING")
			for pos < len(plaintext) && plaintext[pos] == 0x00 {
				pos++
			}
		case 0x01:
			appendFrame("PING")
		case 0x02, 0x03:
			appendFrame("ACK")
			nextPos, ackOK := skipQUICACKFrame(plaintext, pos, ft == 0x03)
			if !ackOK {
				pos = len(plaintext)
			} else {
				pos = nextPos
			}
		case 0x06:
			appendFrame("CRYPTO")
			cryptoOff, n1, ok1 := readQUICVarint(plaintext[pos:])
			if !ok1 {
				return strings.Join(frameTypes, ","), completedCH
			}
			pos += n1
			cryptoLen, n2, ok2 := readQUICVarint(plaintext[pos:])
			if !ok2 || cryptoLen > uint64(len(plaintext)-pos-n2) {
				return strings.Join(frameTypes, ","), completedCH
			}
			pos += n2
			data := plaintext[pos : pos+int(cryptoLen)]
			pos += int(cryptoLen)
			if ch, done := reasm.insert(int(cryptoOff), data); done && len(completedCH) == 0 {
				completedCH = ch
			}
		default:
			pos = len(plaintext)
		}
	}
	return strings.Join(frameTypes, ","), completedCH
}

func skipQUICACKFrame(b []byte, pos int, withECN bool) (int, bool) {
	// Largest Acknowledged, ACK Delay, ACK Range Count, First ACK Range.
	var rangeCount uint64
	for i := range 4 {
		v, n, ok := readQUICVarint(b[pos:])
		if !ok {
			return 0, false
		}
		if i == 2 {
			rangeCount = v
		}
		pos += n
	}
	if rangeCount > 256 {
		return 0, false
	}
	for range rangeCount {
		for range 2 {
			_, n, ok := readQUICVarint(b[pos:])
			if !ok {
				return 0, false
			}
			pos += n
		}
	}
	if withECN {
		for range 3 {
			_, n, ok := readQUICVarint(b[pos:])
			if !ok {
				return 0, false
			}
			pos += n
		}
	}
	return pos, true
}
