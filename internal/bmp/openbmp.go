package bmp

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	OpenBMPHeaderSize      = 10 // v2: version(2) + collector_hash(4) + msg_len(4)
	openBMPVersionExpected = 2

	// OpenBMP v1.7 binary format (used by goBMP -bmp-raw=true)
	openBMPV17Magic      = 0x4F424D50 // "OBMP"
	openBMPV17MinHdrSize = 12         // magic(4) + ver(2) + hdr_len(2) + msg_len(4)
)

// DecodeOpenBMPFrame decodes an OpenBMP frame and extracts the BMP payload.
// Supports both the v2 format (10-byte header) and v1.7 binary format ("OBMP" magic).
func DecodeOpenBMPFrame(data []byte, maxPayloadBytes int) ([]byte, error) {
	if len(data) < OpenBMPHeaderSize {
		return nil, fmt.Errorf("openbmp: frame too short (%d bytes, need %d)", len(data), OpenBMPHeaderSize)
	}

	// Auto-detect format: v1.7 starts with "OBMP" magic (0x4F424D50).
	if binary.BigEndian.Uint32(data[0:4]) == openBMPV17Magic {
		return decodeV17(data, maxPayloadBytes)
	}

	return decodeV2(data, maxPayloadBytes)
}

// decodeV2 decodes the simple 10-byte OpenBMP v2 header.
func decodeV2(data []byte, maxPayloadBytes int) ([]byte, error) {
	version := binary.BigEndian.Uint16(data[0:2])
	if version != openBMPVersionExpected {
		return nil, fmt.Errorf("openbmp: unexpected version %d (expected %d)", version, openBMPVersionExpected)
	}

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

// decodeV17 decodes the OpenBMP v1.7 binary header ("OBMP" magic).
// Header layout:
//
//	Offset 0:    Magic "OBMP" (4 bytes)
//	Offset 4:    Major version (1 byte)
//	Offset 5:    Minor version (1 byte)
//	Offset 6:    Header length (2 bytes, uint16) — total header size
//	Offset 8:    BMP message length (4 bytes, uint32) — payload size
//	Offset 12+:  Flags, type, timestamps, hashes, router info (variable)
//	Offset hdrLen: Raw BMP message bytes
func decodeV17(data []byte, maxPayloadBytes int) ([]byte, error) {
	if len(data) < openBMPV17MinHdrSize {
		return nil, fmt.Errorf("openbmp v1.7: frame too short (%d bytes, need %d)", len(data), openBMPV17MinHdrSize)
	}

	hdrLen := binary.BigEndian.Uint16(data[6:8])
	msgLen := binary.BigEndian.Uint32(data[8:12])

	if hdrLen < openBMPV17MinHdrSize {
		return nil, fmt.Errorf("openbmp v1.7: header_len %d is too small", hdrLen)
	}
	if msgLen == 0 {
		return nil, fmt.Errorf("openbmp v1.7: msg_len is 0")
	}
	if uint64(msgLen) > uint64(math.MaxInt)-uint64(hdrLen) {
		return nil, fmt.Errorf("openbmp v1.7: msg_len %d overflows addressable size", msgLen)
	}
	if maxPayloadBytes > 0 && int(msgLen) > maxPayloadBytes {
		return nil, fmt.Errorf("openbmp v1.7: msg_len %d exceeds max_payload_bytes %d", msgLen, maxPayloadBytes)
	}

	totalLen := int(hdrLen) + int(msgLen)
	if len(data) < totalLen {
		return nil, fmt.Errorf("openbmp v1.7: frame truncated (have %d, need %d)", len(data), totalLen)
	}

	return data[hdrLen:totalLen], nil
}
