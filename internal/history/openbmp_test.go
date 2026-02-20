package history

import (
	"encoding/binary"
	"testing"
)

func buildOpenBMPFrame(version uint16, collectorHash uint32, payload []byte) []byte {
	frame := make([]byte, 10+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], version)
	binary.BigEndian.PutUint32(frame[2:6], collectorHash)
	binary.BigEndian.PutUint32(frame[6:10], uint32(len(payload)))
	copy(frame[10:], payload)
	return frame
}

func TestDecodeOpenBMPFrame_Valid(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04} // Minimal BMP common header
	frame := buildOpenBMPFrame(2, 0xAABBCCDD, payload)

	bmpBytes, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bmpBytes) != len(payload) {
		t.Fatalf("expected %d bytes, got %d", len(payload), len(bmpBytes))
	}
	for i := range payload {
		if bmpBytes[i] != payload[i] {
			t.Fatalf("byte %d: expected 0x%02x, got 0x%02x", i, payload[i], bmpBytes[i])
		}
	}
}

func TestDecodeOpenBMPFrame_Truncated(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildOpenBMPFrame(2, 0xAABBCCDD, payload)
	// Truncate the frame.
	truncated := frame[:8]

	_, err := DecodeOpenBMPFrame(truncated, 16*1024*1024)
	if err == nil {
		t.Fatal("expected error for truncated frame")
	}
}

func TestDecodeOpenBMPFrame_BadVersion(t *testing.T) {
	payload := []byte{0x03}
	frame := buildOpenBMPFrame(99, 0x00000000, payload)

	_, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestDecodeOpenBMPFrame_OversizedPayload(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildOpenBMPFrame(2, 0x00000000, payload)

	_, err := DecodeOpenBMPFrame(frame, 2) // max 2 bytes
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestDecodeOpenBMPFrame_ZeroLength(t *testing.T) {
	frame := make([]byte, 10)
	binary.BigEndian.PutUint16(frame[0:2], 2)
	binary.BigEndian.PutUint32(frame[2:6], 0)
	binary.BigEndian.PutUint32(frame[6:10], 0) // msg_len = 0

	_, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err == nil {
		t.Fatal("expected error for zero msg_len")
	}
}

func TestDecodeOpenBMPFrame_MultipleFrames(t *testing.T) {
	payload1 := []byte{0x01, 0x02, 0x03}
	payload2 := []byte{0x04, 0x05}
	frame1 := buildOpenBMPFrame(2, 0x11111111, payload1)
	frame2 := buildOpenBMPFrame(2, 0x22222222, payload2)

	// Concatenated frames.
	combined := append(frame1, frame2...)

	// Decode first frame.
	bmp1, err := DecodeOpenBMPFrame(combined, 16*1024*1024)
	if err != nil {
		t.Fatalf("frame 1: unexpected error: %v", err)
	}
	if len(bmp1) != 3 {
		t.Fatalf("frame 1: expected 3 bytes, got %d", len(bmp1))
	}

	// Decode second frame from remaining.
	remaining := combined[10+len(payload1):]
	bmp2, err := DecodeOpenBMPFrame(remaining, 16*1024*1024)
	if err != nil {
		t.Fatalf("frame 2: unexpected error: %v", err)
	}
	if len(bmp2) != 2 {
		t.Fatalf("frame 2: expected 2 bytes, got %d", len(bmp2))
	}
}

// --- Dedup Verification Tests (US3 T033) ---

func TestCrossCollectorDedup_SameBMPPayload(t *testing.T) {
	// Same BMP payload wrapped in two different OpenBMP frames (different collector_hash).
	bmpPayload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0xAA, 0xBB, 0xCC, 0xDD}

	frameCola := buildOpenBMPFrame(2, 0xAAAAAAAA, bmpPayload) // Collector A
	frameColb := buildOpenBMPFrame(2, 0xBBBBBBBB, bmpPayload) // Collector B

	bmpA, err := DecodeOpenBMPFrame(frameCola, 16*1024*1024)
	if err != nil {
		t.Fatalf("cola decode: %v", err)
	}
	bmpB, err := DecodeOpenBMPFrame(frameColb, 16*1024*1024)
	if err != nil {
		t.Fatalf("colb decode: %v", err)
	}

	hashA := ComputeEventID(bmpA)
	hashB := ComputeEventID(bmpB)

	// Hashes must be identical (same BMP bytes, different OpenBMP wrapper).
	for i := range hashA {
		if hashA[i] != hashB[i] {
			t.Fatalf("event_id differs at byte %d: cola=%x colb=%x", i, hashA, hashB)
		}
	}
}

func TestCrossCollectorDedup_DifferentBMPPayload(t *testing.T) {
	bmpA := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x11, 0x22}
	bmpB := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x33, 0x44}

	frameA := buildOpenBMPFrame(2, 0xAAAAAAAA, bmpA)
	frameB := buildOpenBMPFrame(2, 0xAAAAAAAA, bmpB)

	extractA, _ := DecodeOpenBMPFrame(frameA, 16*1024*1024)
	extractB, _ := DecodeOpenBMPFrame(frameB, 16*1024*1024)

	hashA := ComputeEventID(extractA)
	hashB := ComputeEventID(extractB)

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
