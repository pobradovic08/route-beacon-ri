package bmp

import (
	"encoding/binary"
	"fmt"
	"net"
)

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
		// Skip other message types.
		return result, nil
	}
}

func parseRouteMonitoring(data []byte, result *ParsedBMP) (*ParsedBMP, error) {
	if len(data) < 42 {
		return nil, fmt.Errorf("bmp: route monitoring too short for per-peer header (%d bytes)", len(data))
	}

	result.PeerType = data[0]
	result.PeerFlags = binary.BigEndian.Uint16(data[1:3])
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
	result.IsLocRIB = result.PeerType == PeerTypeLocRIB

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

// RouterIDFromPeerHeader extracts the peer address from a per-peer header for logging.
func RouterIDFromPeerHeader(data []byte) string {
	if len(data) < 42 {
		return ""
	}
	// Peer address is at offset 3+8 = 11, 16 bytes (IPv6-mapped).
	addr := data[11:27]
	ip := net.IP(addr)
	// Check if it's an IPv4-mapped IPv6 address.
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
