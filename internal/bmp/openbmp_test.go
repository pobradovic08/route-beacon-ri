package bmp

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

func TestDecodeOpenBMPFrame_TruncatedPayload(t *testing.T) {
	// Header is valid but payload is shorter than msg_len claims.
	// msg_len says 100 bytes but only 5 bytes of payload are present.
	frame := make([]byte, 10+5)
	binary.BigEndian.PutUint16(frame[0:2], 2)        // version
	binary.BigEndian.PutUint32(frame[2:6], 0)        // collector_hash
	binary.BigEndian.PutUint32(frame[6:10], 100)     // msg_len = 100 (but only 5 bytes follow)
	copy(frame[10:], []byte{0x03, 0x00, 0x00, 0x00, 0x06})

	_, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err == nil {
		t.Fatal("expected error for truncated payload (header OK, payload short)")
	}
}

// buildOpenBMPV17Frame builds an OpenBMP v1.7 binary frame ("OBMP" magic).
func buildOpenBMPV17Frame(payload []byte) []byte {
	hdrLen := uint16(78) // minimum header with no collector admin ID and no router group
	frame := make([]byte, int(hdrLen)+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], 0x4F424D50) // "OBMP" magic
	frame[4] = 1                                        // major version
	frame[5] = 7                                        // minor version
	binary.BigEndian.PutUint16(frame[6:8], hdrLen)
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(payload)))
	frame[12] = 0x80 // flags: router message
	frame[13] = 12   // message type: BMP_RAW
	// timestamps, hashes, router IP, etc. are zeroed (not used by decoder)
	copy(frame[hdrLen:], payload)
	return frame
}

func TestDecodeOpenBMPFrame_V17Valid(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildOpenBMPV17Frame(payload)

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

func TestDecodeOpenBMPFrame_V17Truncated(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildOpenBMPV17Frame(payload)
	truncated := frame[:20] // cut short

	_, err := DecodeOpenBMPFrame(truncated, 16*1024*1024)
	if err == nil {
		t.Fatal("expected error for truncated v1.7 frame")
	}
}

func TestDecodeOpenBMPFrame_V17ZeroMsgLen(t *testing.T) {
	frame := make([]byte, 78)
	binary.BigEndian.PutUint32(frame[0:4], 0x4F424D50)
	frame[4] = 1
	frame[5] = 7
	binary.BigEndian.PutUint16(frame[6:8], 78)
	binary.BigEndian.PutUint32(frame[8:12], 0) // msg_len = 0

	_, err := DecodeOpenBMPFrame(frame, 16*1024*1024)
	if err == nil {
		t.Fatal("expected error for zero msg_len in v1.7")
	}
}

func TestDecodeOpenBMPFrame_V17Oversized(t *testing.T) {
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04}
	frame := buildOpenBMPV17Frame(payload)

	_, err := DecodeOpenBMPFrame(frame, 2) // max 2 bytes
	if err == nil {
		t.Fatal("expected error for oversized v1.7 payload")
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
