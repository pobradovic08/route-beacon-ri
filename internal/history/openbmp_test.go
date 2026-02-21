package history

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// buildLegacyFrame builds a legacy OpenBMP v2 frame (10-byte header).
func buildLegacyFrame(version uint16, collectorHash uint32, payload []byte) []byte {
	frame := make([]byte, 10+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], version)
	binary.BigEndian.PutUint32(frame[2:6], collectorHash)
	binary.BigEndian.PutUint32(frame[6:10], uint32(len(payload)))
	copy(frame[10:], payload)
	return frame
}

// buildOBMPv17Frame builds an OBMP v1.7 frame with the given router IP and BMP payload.
// collectorAdminID can be empty. routerIP must be 4 bytes for IPv4 (placed in first 4 + 12 zeros).
func buildOBMPv17Frame(routerIPv4 [4]byte, payload []byte) []byte {
	collectorAdminIDLen := 0
	routerHashOff := 40 + collectorAdminIDLen
	routerIPOff := routerHashOff + 16
	routerGroupOff := routerIPOff + 16
	routerGroupLen := 0
	rowCountOff := routerGroupOff + 2 + routerGroupLen
	headerLen := rowCountOff + 4

	frame := make([]byte, headerLen+len(payload))

	// Magic "OBMP"
	binary.BigEndian.PutUint32(frame[0:4], 0x4F424D50)
	// Version 1.7
	frame[4] = 1
	frame[5] = 7
	// Header length
	binary.BigEndian.PutUint16(frame[6:8], uint16(headerLen))
	// BMP message length
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(payload)))
	// Flags, msg type, timestamps, collector hash — leave as zeros
	// Collector Admin ID Length = 0
	binary.BigEndian.PutUint16(frame[38:40], 0)
	// Router Hash — leave as zeros (16 bytes at routerHashOff)
	// Router IP — IPv4 in first 4 bytes, trailing zeros (goBMP format)
	copy(frame[routerIPOff:routerIPOff+4], routerIPv4[:])
	// Router Group Length = 0
	binary.BigEndian.PutUint16(frame[routerGroupOff:routerGroupOff+2], 0)
	// Row Count = 1
	binary.BigEndian.PutUint32(frame[rowCountOff:rowCountOff+4], 1)

	copy(frame[headerLen:], payload)
	return frame
}

// buildOBMPv17FrameIPv6 builds an OBMP v1.7 frame with a full IPv6 router address.
func buildOBMPv17FrameIPv6(routerIPv6 [16]byte, payload []byte) []byte {
	collectorAdminIDLen := 0
	routerHashOff := 40 + collectorAdminIDLen
	routerIPOff := routerHashOff + 16
	routerGroupOff := routerIPOff + 16
	routerGroupLen := 0
	rowCountOff := routerGroupOff + 2 + routerGroupLen
	headerLen := rowCountOff + 4

	frame := make([]byte, headerLen+len(payload))

	binary.BigEndian.PutUint32(frame[0:4], 0x4F424D50)
	frame[4] = 1
	frame[5] = 7
	binary.BigEndian.PutUint16(frame[6:8], uint16(headerLen))
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(payload)))
	binary.BigEndian.PutUint16(frame[38:40], 0)
	copy(frame[routerIPOff:routerIPOff+16], routerIPv6[:])
	binary.BigEndian.PutUint16(frame[routerGroupOff:routerGroupOff+2], 0)
	binary.BigEndian.PutUint32(frame[rowCountOff:rowCountOff+4], 1)

	copy(frame[headerLen:], payload)
	return frame
}

// --- Legacy v2 tests ---

func TestDecodeOpenBMPFrame_Valid(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildLegacyFrame(2, 0xAABBCCDD, payload)

	result, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.BMPBytes) != len(payload) {
		t.Fatalf("expected %d bytes, got %d", len(payload), len(result.BMPBytes))
	}
	for i := range payload {
		if result.BMPBytes[i] != payload[i] {
			t.Fatalf("byte %d: expected 0x%02x, got 0x%02x", i, payload[i], result.BMPBytes[i])
		}
	}
	if result.RouterIP != "" {
		t.Errorf("expected empty RouterIP for legacy frame, got %q", result.RouterIP)
	}
}

func TestDecodeOpenBMPFrame_Truncated(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildLegacyFrame(2, 0xAABBCCDD, payload)
	truncated := frame[:8]

	_, err := DecodeOpenBMPFrame(truncated, 16*1024*1024)
	if err == nil {
		t.Fatal("expected error for truncated frame")
	}
}

func TestDecodeOpenBMPFrame_BadVersion(t *testing.T) {
	payload := []byte{0x03}
	frame := buildLegacyFrame(99, 0x00000000, payload)

	_, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestDecodeOpenBMPFrame_OversizedPayload(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildLegacyFrame(2, 0x00000000, payload)

	_, err := DecodeOpenBMPFrame(frame, 2)
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestDecodeOpenBMPFrame_ZeroLength(t *testing.T) {
	frame := make([]byte, 10)
	binary.BigEndian.PutUint16(frame[0:2], 2)
	binary.BigEndian.PutUint32(frame[2:6], 0)
	binary.BigEndian.PutUint32(frame[6:10], 0)

	_, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err == nil {
		t.Fatal("expected error for zero msg_len")
	}
}

func TestDecodeOpenBMPFrame_MultipleFrames(t *testing.T) {
	payload1 := []byte{0x01, 0x02, 0x03}
	payload2 := []byte{0x04, 0x05}
	frame1 := buildLegacyFrame(2, 0x11111111, payload1)
	frame2 := buildLegacyFrame(2, 0x22222222, payload2)

	combined := append(frame1, frame2...)

	result1, err := DecodeOpenBMPFrame(combined, 16*1024*1024)
	if err != nil {
		t.Fatalf("frame 1: unexpected error: %v", err)
	}
	if len(result1.BMPBytes) != 3 {
		t.Fatalf("frame 1: expected 3 bytes, got %d", len(result1.BMPBytes))
	}

	remaining := combined[10+len(payload1):]
	result2, err := DecodeOpenBMPFrame(remaining, 16*1024*1024)
	if err != nil {
		t.Fatalf("frame 2: unexpected error: %v", err)
	}
	if len(result2.BMPBytes) != 2 {
		t.Fatalf("frame 2: expected 2 bytes, got %d", len(result2.BMPBytes))
	}
}

// --- OBMP v1.7 tests ---

func TestDecodeOBMPv17_IPv4Router(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildOBMPv17Frame([4]byte{10, 0, 0, 1}, payload)

	result, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.BMPBytes) != len(payload) {
		t.Fatalf("expected %d BMP bytes, got %d", len(payload), len(result.BMPBytes))
	}
	if result.RouterIP != "10.0.0.1" {
		t.Errorf("expected RouterIP=10.0.0.1, got %q", result.RouterIP)
	}
	if result.RouterHash == "" {
		t.Error("expected non-empty RouterHash")
	}
}

func TestDecodeOBMPv17_IPv6Router(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	ipv6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	frame := buildOBMPv17FrameIPv6(ipv6, payload)

	result, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RouterIP != "2001:db8::1" {
		t.Errorf("expected RouterIP=2001:db8::1, got %q", result.RouterIP)
	}
}

func TestDecodeOBMPv17_EmptyCollectorID(t *testing.T) {
	payload := []byte{0xAA, 0xBB}
	frame := buildOBMPv17Frame([4]byte{192, 168, 1, 1}, payload)

	result, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RouterIP != "192.168.1.1" {
		t.Errorf("expected RouterIP=192.168.1.1, got %q", result.RouterIP)
	}
}

func TestDecodeOBMPv17_ZeroRouterIP(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildOBMPv17Frame([4]byte{0, 0, 0, 0}, payload)

	result, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RouterIP != "" {
		t.Errorf("expected empty RouterIP for all-zero address, got %q", result.RouterIP)
	}
}

func TestDecodeOBMPv17_Truncated(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildOBMPv17Frame([4]byte{10, 0, 0, 1}, payload)
	// Truncate to just the first 20 bytes of the header.
	truncated := frame[:20]

	_, err := DecodeOpenBMPFrame(truncated, 16*1024*1024)
	if err == nil {
		t.Fatal("expected error for truncated v1.7 frame")
	}
}

func TestDecodeOBMPv17_OversizedPayload(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildOBMPv17Frame([4]byte{10, 0, 0, 1}, payload)

	_, err := DecodeOpenBMPFrame(frame, 2)
	if err == nil {
		t.Fatal("expected error for oversized payload in v1.7 frame")
	}
}

func TestDecodeOBMPv17_ZeroMsgLen(t *testing.T) {
	frame := buildOBMPv17Frame([4]byte{10, 0, 0, 1}, nil)
	// Override msg_len to 0.
	binary.BigEndian.PutUint32(frame[8:12], 0)

	_, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err == nil {
		t.Fatal("expected error for zero msg_len in v1.7 frame")
	}
}

// --- Dedup Verification Tests ---

func TestCrossCollectorDedup_SameBMPPayload(t *testing.T) {
	bmpPayload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0xAA, 0xBB, 0xCC, 0xDD}

	frameCola := buildLegacyFrame(2, 0xAAAAAAAA, bmpPayload)
	frameColb := buildLegacyFrame(2, 0xBBBBBBBB, bmpPayload)

	resultA, err := DecodeOpenBMPFrame(frameCola, 16*1024*1024)
	if err != nil {
		t.Fatalf("cola decode: %v", err)
	}
	resultB, err := DecodeOpenBMPFrame(frameColb, 16*1024*1024)
	if err != nil {
		t.Fatalf("colb decode: %v", err)
	}

	hashA := ComputeEventID(resultA.BMPBytes)
	hashB := ComputeEventID(resultB.BMPBytes)

	for i := range hashA {
		if hashA[i] != hashB[i] {
			t.Fatalf("event_id differs at byte %d: cola=%x colb=%x", i, hashA, hashB)
		}
	}
}

func TestCrossCollectorDedup_DifferentBMPPayload(t *testing.T) {
	bmpA := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x11, 0x22}
	bmpB := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x33, 0x44}

	frameA := buildLegacyFrame(2, 0xAAAAAAAA, bmpA)
	frameB := buildLegacyFrame(2, 0xAAAAAAAA, bmpB)

	resultA, _ := DecodeOpenBMPFrame(frameA, 16*1024*1024)
	resultB, _ := DecodeOpenBMPFrame(frameB, 16*1024*1024)

	hashA := ComputeEventID(resultA.BMPBytes)
	hashB := ComputeEventID(resultB.BMPBytes)

	same := true
	for i := range hashA {
		if hashA[i] != hashB[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different BMP payloads should produce different event_ids")
	}
}

func TestComputeEventID_Deterministic(t *testing.T) {
	data := []byte("test BMP message payload")
	h1 := ComputeEventID(data)
	h2 := ComputeEventID(data)

	if len(h1) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(h1))
	}
	for i := range h1 {
		if h1[i] != h2[i] {
			t.Fatal("hashes differ for same input")
		}
	}
}

func TestComputeEventID_DifferentInputs(t *testing.T) {
	h1 := ComputeEventID([]byte("message A"))
	h2 := ComputeEventID([]byte("message B"))

	same := true
	for i := range h1 {
		if h1[i] != h2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("hashes should differ for different inputs")
	}
}

// --- parseOBMPRouterIP tests ---

func TestParseOBMPRouterIP_IPv4LeadingZeros(t *testing.T) {
	// IPv4 in last 4 bytes with 12 leading zeros (BMP per-peer style).
	b := make([]byte, 16)
	b[12] = 10
	b[13] = 0
	b[14] = 0
	b[15] = 2
	got := parseOBMPRouterIP(b)
	if got != "10.0.0.2" {
		t.Errorf("expected 10.0.0.2, got %q", got)
	}
}

func TestParseOBMPRouterIP_IPv4TrailingZeros(t *testing.T) {
	// IPv4 in first 4 bytes with 12 trailing zeros (goBMP format).
	b := make([]byte, 16)
	b[0] = 192
	b[1] = 168
	b[2] = 1
	b[3] = 1
	got := parseOBMPRouterIP(b)
	if got != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %q", got)
	}
}

func TestParseOBMPRouterIP_IPv4Mapped(t *testing.T) {
	// ::ffff:10.0.0.1
	b := make([]byte, 16)
	b[10] = 0xff
	b[11] = 0xff
	b[12] = 10
	b[13] = 0
	b[14] = 0
	b[15] = 1
	got := parseOBMPRouterIP(b)
	if got != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %q", got)
	}
}

func TestParseOBMPRouterIP_FullIPv6(t *testing.T) {
	b := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	got := parseOBMPRouterIP(b[:])
	if got != "2001:db8::1" {
		t.Errorf("expected 2001:db8::1, got %q", got)
	}
}

func TestParseOBMPRouterIP_AllZeros(t *testing.T) {
	b := make([]byte, 16)
	got := parseOBMPRouterIP(b)
	if got != "" {
		t.Errorf("expected empty string for all-zero address, got %q", got)
	}
}

func TestParseOBMPRouterIP_WrongLength(t *testing.T) {
	got := parseOBMPRouterIP([]byte{1, 2, 3})
	if got != "" {
		t.Errorf("expected empty string for wrong-length input, got %q", got)
	}
}

func TestDecodeOBMPv17_RouterHashExtracted(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildOBMPv17Frame([4]byte{10, 0, 0, 1}, payload)

	// Write a known router hash at offset 40 (after collector admin ID len at 38-39=0).
	for i := 0; i < 16; i++ {
		frame[40+i] = byte(i + 1)
	}

	result, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := fmt.Sprintf("%x", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	if result.RouterHash != expected {
		t.Errorf("expected RouterHash=%s, got %s", expected, result.RouterHash)
	}
}
