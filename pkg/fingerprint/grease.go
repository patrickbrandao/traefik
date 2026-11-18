package fingerprint

// IsTLSGREASE reports whether v is a TLS GREASE value as defined in RFC 8701 (0x0a0a, 0x1a1a, ..., 0xfafa).
// HTTP/2 GREASE settings share this exact 16-bit pattern.
func IsTLSGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

// IsQUICTPGREASE reports whether id is a reserved GREASE QUIC transport parameter ID (27 + 31*N) per RFC 9000 Section 18.1.
func IsQUICTPGREASE(id uint64) bool {
	return id >= 27 && (id-27)%31 == 0
}

// IsQUICVersionGREASE reports whether ver is a reserved GREASE QUIC version (0x?a?a?a?a) per RFC 9000 Section 15.
func IsQUICVersionGREASE(ver uint32) bool {
	return (ver & 0x0f0f0f0f) == 0x0a0a0a0a
}

// IsH3GREASE reports whether id is a reserved GREASE HTTP/3 frame, setting, or unidirectional stream type (0x1f*N + 0x21) per RFC 9114 Section 7.2.8.
func IsH3GREASE(id uint64) bool {
	return id >= 0x21 && (id-0x21)%0x1f == 0
}
