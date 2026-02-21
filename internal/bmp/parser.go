package bmp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ParseAll parses all concatenated BMP messages from raw bytes.
// goBMP may bundle multiple BMP messages in a single raw Kafka record
// (one per TCP read). Returns all successfully parsed messages.
func ParseAll(data []byte) ([]*ParsedBMP, error) {
	var results []*ParsedBMP
	offset := 0
	for offset < len(data) {
		remaining := data[offset:]
		if len(remaining) < CommonHeaderSize {
			break
		}
		msgLength := binary.BigEndian.Uint32(remaining[1:5])
		if msgLength < uint32(CommonHeaderSize) || int(msgLength) > len(remaining) {
			break
		}
		parsed, err := Parse(remaining[:msgLength])
		if err != nil {
			// Skip this message and try the next.
			offset += int(msgLength)
			continue
		}
		// Store the offset of this BMP message within the raw payload
		// so callers can extract the per-peer header.
		parsed.Offset = offset
		results = append(results, parsed)
		offset += int(msgLength)
	}
	if len(results) == 0 && offset == 0 {
		return nil, fmt.Errorf("bmp: no valid messages found in %d bytes", len(data))
	}
	return results, nil
}

// Parse parses a complete BMP message from raw bytes.
func Parse(data []byte) (*ParsedBMP, error) {
	if len(data) < CommonHeaderSize {
		return nil, fmt.Errorf("bmp: message too short for common header (%d bytes)", len(data))
	}

	version := data[0]
	if version != BMPVersion {
		return nil, fmt.Errorf("bmp: unsupported version %d (expected %d)", version, BMPVersion)
	}

	msgLength := binary.BigEndian.Uint32(data[1:5])
	msgType := data[5]

	if msgLength < uint32(CommonHeaderSize) {
		return nil, fmt.Errorf("bmp: declared msg_length %d smaller than common header size %d", msgLength, CommonHeaderSize)
	}
	if int(msgLength) > len(data) {
		return nil, fmt.Errorf("bmp: declared msg_length %d exceeds available data %d", msgLength, len(data))
	}

	result := &ParsedBMP{
		MsgType:   msgType,
		TableName: "UNKNOWN",
	}

	switch msgType {
	case MsgTypeRouteMonitoring:
		return parseRouteMonitoring(data[CommonHeaderSize:msgLength], result)
	case MsgTypePeerDown:
		return parsePeerDown(data[CommonHeaderSize:msgLength], result)
	case MsgTypeTermination:
		result.MsgType = MsgTypeTermination
		return result, nil
	default:
		// Initiation (4), Statistics Report (1), Peer Up (3), Route Mirroring (6) — not needed for Loc-RIB ingestion.
		return result, nil
	}
}

func parseRouteMonitoring(data []byte, result *ParsedBMP) (*ParsedBMP, error) {
	if len(data) < 42 {
		return nil, fmt.Errorf("bmp: route monitoring too short for per-peer header (%d bytes)", len(data))
	}

	result.PeerType = data[0]
	result.PeerFlags = data[1]
	result.IsLocRIB = result.PeerType == PeerTypeLocRIB
	result.HasAddPath = (result.PeerFlags & PeerFlagAddPath) != 0

	// After per-peer header (42 bytes), the BGP message follows.
	// But for Loc-RIB, we need to extract the BGP UPDATE first, then parse TLVs after.
	bgpStart := 42

	if bgpStart >= len(data) {
		return nil, fmt.Errorf("bmp: no data after per-peer header")
	}

	// Parse the BGP message to find its end.
	bgpData := data[bgpStart:]

	if result.IsLocRIB {
		// For Loc-RIB (RFC 9069), the structure is:
		// per-peer header (42) + BGP UPDATE + TLVs
		// We need to parse the BGP message header to find its length,
		// then parse TLVs after.
		bgpMsgLen, err := bgpMessageLength(bgpData)
		if err != nil {
			// If we can't parse BGP header, treat all remaining as BGP data.
			result.BGPData = bgpData
			return result, nil
		}

		if bgpMsgLen > len(bgpData) {
			result.BGPData = bgpData
			return result, nil
		}

		result.BGPData = bgpData[:bgpMsgLen]

		// Parse TLVs after BGP message for table name.
		tlvData := bgpData[bgpMsgLen:]
		parseTLVs(tlvData, result)
	} else {
		result.BGPData = bgpData
	}

	return result, nil
}

func parsePeerDown(data []byte, result *ParsedBMP) (*ParsedBMP, error) {
	if len(data) < 42 {
		return nil, fmt.Errorf("bmp: peer down too short for per-peer header (%d bytes)", len(data))
	}

	result.PeerType = data[0]
	result.PeerFlags = data[1]
	result.IsLocRIB = result.PeerType == PeerTypeLocRIB
	result.HasAddPath = (result.PeerFlags & PeerFlagAddPath) != 0

	if result.IsLocRIB {
		// RFC 9069 Section 5: Peer Down for Loc-RIB includes a reason code
		// byte after the per-peer header, followed by optional TLVs.
		if len(data) > 42 {
			// Reason code at offset 42 (first byte after per-peer header).
			// Skip reason code, parse TLVs from remaining data.
			tlvData := data[43:]
			parseTLVs(tlvData, result)
		}
	}

	return result, nil
}

// bgpMessageLength reads the length field from a BGP message header.
// BGP header: marker(16) + length(2) + type(1) = 19 bytes minimum.
func bgpMessageLength(data []byte) (int, error) {
	if len(data) < 19 {
		return 0, fmt.Errorf("bmp: bgp message too short (%d bytes)", len(data))
	}
	// Length is at offset 16-17 (after the 16-byte marker).
	length := int(binary.BigEndian.Uint16(data[16:18]))
	if length < 19 {
		return 0, fmt.Errorf("bmp: invalid bgp message length %d", length)
	}
	return length, nil
}

// parseTLVs extracts Table Name and other TLVs from data following the BGP message.
func parseTLVs(data []byte, result *ParsedBMP) {
	offset := 0
	for offset+4 <= len(data) {
		tlvType := binary.BigEndian.Uint16(data[offset : offset+2])
		tlvLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+tlvLen > len(data) {
			break
		}

		if tlvType == TLVTypeTableName && tlvLen > 0 {
			result.TableName = string(data[offset : offset+tlvLen])
		}

		offset += tlvLen
	}
}

// RouterIDFromPeerHeader extracts the router identifier from a BMP per-peer header.
//
// Per-peer header layout (RFC 7854 Section 4.2):
//
//	Offset  0: Peer Type (1 byte)
//	Offset  1: Peer Flags (1 byte)
//	Offset  2: Peer Distinguisher (8 bytes)
//	Offset 10: Peer Address (16 bytes)
//	Offset 26: Peer AS (4 bytes)
//	Offset 30: Peer BGP ID (4 bytes)
//
// For Loc-RIB (peer type 3, RFC 9069 Section 4.1), Peer Address and Peer AS
// are set to zero, but Peer BGP ID contains the local router's BGP identifier.
// This function checks the Peer Address first; if it is all zeros, it falls
// back to the Peer BGP ID field.
func RouterIDFromPeerHeader(data []byte) string {
	if len(data) < PerPeerHeaderSize {
		return ""
	}

	// Peer address at offset 10, 16 bytes (IPv6-mapped).
	addr := data[10:26]

	// Check if peer address is all zeros (Loc-RIB per RFC 9069).
	allZero := true
	for _, b := range addr {
		if b != 0 {
			allZero = false
			break
		}
	}

	if allZero {
		// For Loc-RIB, Peer BGP ID at offset 30 (4 bytes) holds the
		// local BGP identifier (RFC 9069 Section 4.1).
		bgpID := data[30:34]
		bgpIDZero := true
		for _, b := range bgpID {
			if b != 0 {
				bgpIDZero = false
				break
			}
		}
		if !bgpIDZero {
			return net.IP(bgpID).String()
		}
		return ""
	}

	// BMP (RFC 7854 §4.2) encodes IPv4 as 12 zero bytes + 4 IPv4 bytes,
	// which differs from the ::ffff: IPv4-mapped format that net.IP.To4()
	// recognizes. Check for the BMP convention explicitly.
	isV4 := true
	for _, b := range addr[:12] {
		if b != 0 {
			isV4 = false
			break
		}
	}
	if isV4 {
		return net.IP(addr[12:16]).String()
	}
	return net.IP(addr).String()
}
