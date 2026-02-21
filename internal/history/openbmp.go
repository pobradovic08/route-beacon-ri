package history

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	// OBMP v1.7 format (used by goBMP).
	obmpMagic        uint32 = 0x4F424D50 // "OBMP"
	obmpMinHeaderLen        = 12         // Minimum to read header_length and msg_length

	// Legacy v2 format (used in earlier tests).
	legacyHeaderSize      = 10 // version(2) + collector_hash(4) + msg_len(4)
	legacyVersionExpected = 2
)

// FrameResult contains the decoded OBMP frame contents.
type FrameResult struct {
	BMPBytes   []byte // Raw BMP message payload.
	RouterIP   string // Router IP from OBMP v1.7 header; empty if unavailable.
	RouterHash string // Router hash (hex) from OBMP v1.7 header; empty if unavailable.
}

// DecodeOpenBMPFrame decodes an OpenBMP frame and extracts the BMP payload.
// Supports both OBMP v1.7 (goBMP) and legacy v2 formats.
func DecodeOpenBMPFrame(data []byte, maxPayloadBytes int) (FrameResult, error) {
	if len(data) < 4 {
		return FrameResult{}, fmt.Errorf("openbmp: frame too short (%d bytes)", len(data))
	}

	// Detect format by checking for OBMP magic bytes.
	magic := binary.BigEndian.Uint32(data[0:4])
	if magic == obmpMagic {
		return decodeOBMPv17(data, maxPayloadBytes)
	}

	// Legacy v2 format fallback.
	return decodeLegacyV2(data, maxPayloadBytes)
}

// decodeOBMPv17 parses the full OBMP v1.7 header produced by goBMP.
//
// Header layout:
//
//	 0-3:  Magic (uint32) = 0x4F424D50 ("OBMP")
//	 4:    Version Major (uint8) = 1
//	 5:    Version Minor (uint8) = 7
//	 6-7:  Header Length (uint16) — total header size
//	 8-11: BMP Message Length (uint32)
//	12:    Flags (uint8)
//	13:    Message Type (uint8)
//	14-17: Timestamp seconds (uint32)
//	18-21: Timestamp microseconds (uint32)
//	22-37: Collector Hash (16 bytes)
//	38-39: Collector Admin ID Length (uint16)
//	40..40+N: Collector Admin ID (N bytes)
//	40+N..55+N: Router Hash (16 bytes)
//	56+N..71+N: Router IP (16 bytes)
//	72+N..73+N: Router Group Length (uint16)
//	74+N..74+N+M: Router Group (M bytes)
//	74+N+M..77+N+M: Row Count (uint32)
func decodeOBMPv17(data []byte, maxPayloadBytes int) (FrameResult, error) {
	if len(data) < obmpMinHeaderLen {
		return FrameResult{}, fmt.Errorf("openbmp: v1.7 frame too short (%d bytes)", len(data))
	}

	headerLen := int(binary.BigEndian.Uint16(data[6:8]))
	msgLen := binary.BigEndian.Uint32(data[8:12])

	if headerLen < obmpMinHeaderLen {
		return FrameResult{}, fmt.Errorf("openbmp: header_length %d too small", headerLen)
	}
	if headerLen > len(data) {
		return FrameResult{}, fmt.Errorf("openbmp: header_length %d exceeds frame (%d bytes)", headerLen, len(data))
	}
	if msgLen == 0 {
		return FrameResult{}, fmt.Errorf("openbmp: msg_len is 0")
	}
	if maxPayloadBytes > 0 && int(msgLen) > maxPayloadBytes {
		return FrameResult{}, fmt.Errorf("openbmp: msg_len %d exceeds limit %d", msgLen, maxPayloadBytes)
	}

	totalLen := headerLen + int(msgLen)
	if len(data) < totalLen {
		return FrameResult{}, fmt.Errorf("openbmp: frame truncated (have %d, need %d)", len(data), totalLen)
	}

	result := FrameResult{
		BMPBytes: data[headerLen:totalLen],
	}

	// Extract router identity from the variable-offset portion of the header.
	// Collector Admin ID length is at offset 38; router fields follow.
	if headerLen >= 40 && len(data) >= 40 {
		collectorIDLen := int(binary.BigEndian.Uint16(data[38:40]))
		routerHashOff := 40 + collectorIDLen
		routerIPOff := routerHashOff + 16

		if routerIPOff+16 <= headerLen {
			result.RouterHash = fmt.Sprintf("%x", data[routerHashOff:routerHashOff+16])
			result.RouterIP = parseOBMPRouterIP(data[routerIPOff : routerIPOff+16])
		}
	}

	return result, nil
}

// decodeLegacyV2 parses the simplified 10-byte OpenBMP v2 header.
// This format does not include router identity information.
func decodeLegacyV2(data []byte, maxPayloadBytes int) (FrameResult, error) {
	if len(data) < legacyHeaderSize {
		return FrameResult{}, fmt.Errorf("openbmp: frame too short (%d bytes, need %d)", len(data), legacyHeaderSize)
	}

	version := binary.BigEndian.Uint16(data[0:2])
	if version != legacyVersionExpected {
		return FrameResult{}, fmt.Errorf("openbmp: unrecognized format (no OBMP magic, version=%d)", version)
	}

	// collector_hash at offset 2-6 is ignored.
	msgLen := binary.BigEndian.Uint32(data[6:10])

	if msgLen == 0 {
		return FrameResult{}, fmt.Errorf("openbmp: msg_len is 0")
	}
	if maxPayloadBytes > 0 && int(msgLen) > maxPayloadBytes {
		return FrameResult{}, fmt.Errorf("openbmp: msg_len %d exceeds limit %d", msgLen, maxPayloadBytes)
	}

	totalLen := legacyHeaderSize + int(msgLen)
	if len(data) < totalLen {
		return FrameResult{}, fmt.Errorf("openbmp: frame truncated (have %d, need %d)", len(data), totalLen)
	}

	return FrameResult{
		BMPBytes: data[legacyHeaderSize:totalLen],
	}, nil
}

// parseOBMPRouterIP extracts a human-readable IP string from 16 bytes of OBMP router IP.
// Handles multiple encodings:
//   - IPv4 in first 4 bytes with 12 trailing zeros (goBMP format)
//   - IPv4 in last 4 bytes with 12 leading zeros (BMP per-peer style)
//   - IPv4-mapped IPv6 (::ffff:x.x.x.x)
//   - Full IPv6
func parseOBMPRouterIP(b []byte) string {
	if len(b) != 16 {
		return ""
	}

	// Check for standard IPv4-mapped IPv6 (::ffff:x.x.x.x).
	ip := net.IP(b)
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}

	// Check if IPv4 in first 4 bytes with trailing zeros (goBMP format).
	trailingZero := true
	for i := 4; i < 16; i++ {
		if b[i] != 0 {
			trailingZero = false
			break
		}
	}
	if trailingZero && (b[0] != 0 || b[1] != 0 || b[2] != 0 || b[3] != 0) {
		return net.IP(b[:4]).String()
	}

	// Check if IPv4 in last 4 bytes with leading zeros.
	leadingZero := true
	for i := 0; i < 12; i++ {
		if b[i] != 0 {
			leadingZero = false
			break
		}
	}
	if leadingZero && (b[12] != 0 || b[13] != 0 || b[14] != 0 || b[15] != 0) {
		return net.IP(b[12:16]).String()
	}

	// Unspecified address.
	if ip.IsUnspecified() {
		return ""
	}

	// Full IPv6.
	return ip.String()
}
