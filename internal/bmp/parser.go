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
		if msgLength > uint32(len(remaining)) {
			break
		}
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
	case MsgTypePeerUp:
		return parsePeerUp(data[CommonHeaderSize:msgLength], result)
	case MsgTypeInitiation:
		return parseInitiation(data[CommonHeaderSize:msgLength], result)
	case MsgTypeTermination:
		result.MsgType = MsgTypeTermination
		return result, nil
	default:
		// Statistics Report (1), Route Mirroring (6) — not needed for Loc-RIB ingestion.
		return result, nil
	}
}

// parseInitiation handles BMP Initiation messages (RFC 7854 §4.3).
// Initiation messages have no per-peer header — TLVs follow immediately
// after the common header.
func parseInitiation(data []byte, result *ParsedBMP) (*ParsedBMP, error) {
	parseTLVs(data, result)
	return result, nil
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

	if len(data) > 42 {
		result.PeerDownReason = data[42]
	}

	if result.IsLocRIB {
		// RFC 9069 Section 5: Peer Down for Loc-RIB includes a reason code
		// byte after the per-peer header, followed by optional TLVs.
		if len(data) > 43 {
			tlvData := data[43:]
			parseTLVs(tlvData, result)
		}
	}

	return result, nil
}

func parsePeerUp(data []byte, result *ParsedBMP) (*ParsedBMP, error) {
	if len(data) < PerPeerHeaderSize {
		return nil, fmt.Errorf("bmp: peer up too short for per-peer header (%d bytes)", len(data))
	}
	result.PeerType = data[0]
	result.PeerFlags = data[1]
	result.IsLocRIB = result.PeerType == PeerTypeLocRIB
	result.HasAddPath = (result.PeerFlags & PeerFlagAddPath) != 0
	if result.IsLocRIB {
		// RFC 9069 Section 4.4: For Loc-RIB Peer Up, the Sent Open and
		// Received Open fields are empty (zero-length), so TLVs start
		// right after the per-peer header.
		result.LocalBGPID = RouterIDFromPeerHeader(data)
		parseTLVs(data[PerPeerHeaderSize:], result)
	} else {
		// Non-Loc-RIB Peer Up (RFC 7854 §4.10):
		//   Per-Peer Header (42) + Local Address (16) + Local Port (2) +
		//   Remote Port (2) = 62 bytes before the Sent OPEN message.
		const sentOpenOffset = PerPeerHeaderSize + 16 + 2 + 2 // 62
		if len(data) >= sentOpenOffset+29 {
			result.LocalASN = extractASNFromBGPOPEN(data[sentOpenOffset:])
			result.LocalBGPID = extractBGPIDFromBGPOPEN(data[sentOpenOffset:])
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
	for i := 0; i < 16; i++ {
		if data[i] != 0xFF {
			return 0, fmt.Errorf("bmp: invalid bgp marker at byte %d", i)
		}
	}
	// Length is at offset 16-17 (after the 16-byte marker).
	length := int(binary.BigEndian.Uint16(data[16:18]))
	if length < 19 {
		return 0, fmt.Errorf("bmp: invalid bgp message length %d", length)
	}
	if length > 4096 {
		return 0, fmt.Errorf("bmp: bgp message length %d exceeds maximum 4096", length)
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

		value := data[offset : offset+tlvLen]
		switch tlvType {
		case TLVTypeTableName:
			if tlvLen > 0 {
				result.TableName = string(value)
			}
		case TLVTypeSysDescr:
			result.SysDescr = string(value)
		case TLVTypeSysName:
			result.SysName = string(value)
		}

		offset += tlvLen
	}
}

// extractASNFromBGPOPEN parses a BGP OPEN message and returns the router's ASN.
// Input: raw BGP OPEN bytes starting at the 16-byte marker.
// Returns 0 if the data is malformed or too short.
//
// BGP OPEN layout (RFC 4271 §4.2):
//
//	Offset  0: Marker (16 bytes, all 0xFF)
//	Offset 16: Length (2 bytes)
//	Offset 18: Type (1 byte, must be 1 for OPEN)
//	Offset 19: Version (1 byte)
//	Offset 20: My Autonomous System (2 bytes)
//	Offset 22: Hold Time (2 bytes)
//	Offset 24: BGP Identifier (4 bytes)
//	Offset 28: Opt Parm Len (1 byte)
//	Offset 29: Optional Parameters (variable)
func extractASNFromBGPOPEN(data []byte) uint32 {
	// Need at least 29 bytes: marker(16) + length(2) + type(1) + version(1) +
	// my_as(2) + hold_time(2) + bgp_id(4) + opt_parm_len(1)
	if len(data) < 29 {
		return 0
	}
	// Validate BGP marker (16 bytes of 0xFF).
	for i := 0; i < 16; i++ {
		if data[i] != 0xFF {
			return 0
		}
	}
	// Type must be 1 (OPEN).
	if data[18] != 1 {
		return 0
	}

	msgLen := int(binary.BigEndian.Uint16(data[16:18]))
	if msgLen < 29 || msgLen > len(data) {
		return 0
	}

	asn := uint32(binary.BigEndian.Uint16(data[20:22]))

	// If 2-byte ASN is AS_TRANS (23456), look for 4-byte ASN capability.
	if asn == 23456 {
		optParmLen := int(data[28])
		if optParmLen > 0 && 29+optParmLen <= msgLen {
			if as4 := find4ByteASNCapability(data[29 : 29+optParmLen]); as4 != 0 {
				return as4
			}
		}
	}

	return asn
}

// extractBGPIDFromBGPOPEN parses a BGP OPEN message and returns the BGP
// Identifier as a dotted-quad string. This identifies the BMP speaker when
// extracted from the Sent OPEN in a Peer Up message.
// Returns empty string if the data is malformed or too short.
func extractBGPIDFromBGPOPEN(data []byte) string {
	if len(data) < 28 {
		return ""
	}
	for i := 0; i < 16; i++ {
		if data[i] != 0xFF {
			return ""
		}
	}
	if data[18] != 1 {
		return ""
	}
	return net.IP(data[24:28]).String()
}

// find4ByteASNCapability scans BGP Optional Parameters for the 4-byte ASN
// capability (RFC 6793, Capability Code 65). Returns the 4-byte ASN value
// or 0 if not found.
//
// Optional Parameters layout (RFC 5492):
//
//	Each parameter: Type(1) + Length(1) + Value(variable)
//	Type 2 = Capabilities: Value contains one or more capabilities
//	Each capability: Code(1) + Length(1) + Value(variable)
//	Code 65, Length 4 = 4-byte ASN capability
func find4ByteASNCapability(optParams []byte) uint32 {
	offset := 0
	for offset+2 <= len(optParams) {
		paramType := optParams[offset]
		paramLen := int(optParams[offset+1])
		offset += 2

		if offset+paramLen > len(optParams) {
			return 0
		}

		if paramType == 2 { // Capabilities parameter
			capData := optParams[offset : offset+paramLen]
			capOffset := 0
			for capOffset+2 <= len(capData) {
				capCode := capData[capOffset]
				capLen := int(capData[capOffset+1])
				capOffset += 2

				if capOffset+capLen > len(capData) {
					break
				}

				if capCode == 65 && capLen == 4 {
					return binary.BigEndian.Uint32(capData[capOffset : capOffset+4])
				}

				capOffset += capLen
			}
		}

		offset += paramLen
	}
	return 0
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
