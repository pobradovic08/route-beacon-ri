package history

import (
	"encoding/binary"
	"testing"

	"github.com/route-beacon/rib-ingester/internal/bmp"
)

func buildOpenBMPFrame(version uint16, collectorHash uint32, payload []byte) []byte {
	frame := make([]byte, 10+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], version)
	binary.BigEndian.PutUint32(frame[2:6], collectorHash)
	binary.BigEndian.PutUint32(frame[6:10], uint32(len(payload)))
	copy(frame[10:], payload)
	return frame
}

func TestCrossCollectorDedup_SameBMPPayload(t *testing.T) {
	// Same BMP payload wrapped in two different OpenBMP frames (different collector_hash).
	bmpPayload := []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0xAA, 0xBB, 0xCC, 0xDD}

	frameCola := buildOpenBMPFrame(2, 0xAAAAAAAA, bmpPayload) // Collector A
	frameColb := buildOpenBMPFrame(2, 0xBBBBBBBB, bmpPayload) // Collector B

	bmpA, err := bmp.DecodeOpenBMPFrame(frameCola, 16*1024*1024)
	if err != nil {
		t.Fatalf("cola decode: %v", err)
	}
	bmpB, err := bmp.DecodeOpenBMPFrame(frameColb, 16*1024*1024)
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

	extractA, _ := bmp.DecodeOpenBMPFrame(frameA, 16*1024*1024)
	extractB, _ := bmp.DecodeOpenBMPFrame(frameB, 16*1024*1024)

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
