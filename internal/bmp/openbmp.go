package bmp

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	OpenBMPHeaderSize      = 10 // version(2) + collector_hash(4) + msg_len(4)
	openBMPVersionExpected = 2
)

// DecodeOpenBMPFrame decodes an OpenBMP RAW v2 frame and extracts the BMP payload.
// Returns the BMP message bytes.
func DecodeOpenBMPFrame(data []byte, maxPayloadBytes int) ([]byte, error) {
	if len(data) < OpenBMPHeaderSize {
		return nil, fmt.Errorf("openbmp: frame too short (%d bytes, need %d)", len(data), OpenBMPHeaderSize)
	}

	version := binary.BigEndian.Uint16(data[0:2])
	if version != openBMPVersionExpected {
		return nil, fmt.Errorf("openbmp: unexpected version %d (expected %d)", version, openBMPVersionExpected)
	}

	// collector_hash at offset 2-6 is ignored (not used for dedup).
	msgLen := binary.BigEndian.Uint32(data[6:10])

	if msgLen == 0 {
		return nil, fmt.Errorf("openbmp: msg_len is 0")
	}
	if uint64(msgLen) > uint64(math.MaxInt)-uint64(OpenBMPHeaderSize) {
		return nil, fmt.Errorf("openbmp: msg_len %d overflows addressable size", msgLen)
	}
	if maxPayloadBytes > 0 && int(msgLen) > maxPayloadBytes {
		return nil, fmt.Errorf("openbmp: msg_len %d exceeds max_payload_bytes %d", msgLen, maxPayloadBytes)
	}

	totalLen := OpenBMPHeaderSize + int(msgLen)
	if len(data) < totalLen {
		return nil, fmt.Errorf("openbmp: frame truncated (have %d, need %d)", len(data), totalLen)
	}

	return data[OpenBMPHeaderSize:totalLen], nil
}
