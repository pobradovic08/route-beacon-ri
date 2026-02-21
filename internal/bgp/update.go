package bgp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ParseUpdate parses a BGP UPDATE message (after the 19-byte BGP header).
// Returns a list of route events, one per prefix found in the UPDATE.
func ParseUpdate(data []byte, hasAddPath bool) ([]*RouteEvent, error) {
	// Skip the 16-byte marker + 2-byte length + 1-byte type = 19 byte header.
	if len(data) < BGPHeaderSize {
		return nil, fmt.Errorf("bgp: update too short (%d bytes)", len(data))
	}

	msgType := data[18]
	if msgType != BGPMsgTypeUpdate {
		return nil, nil // Not an UPDATE message; skip.
	}

	payload := data[BGPHeaderSize:]
	return parseUpdatePayload(payload, hasAddPath)
}

func parseUpdatePayload(data []byte, hasAddPath bool) ([]*RouteEvent, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("bgp: update payload too short (%d bytes)", len(data))
	}

	offset := 0

	// Withdrawn routes length.
	withdrawnLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+withdrawnLen > len(data) {
		return nil, fmt.Errorf("bgp: withdrawn length %d exceeds data", withdrawnLen)
	}

	// Parse IPv4 withdrawn routes → action 'D'.
	withdrawnPrefixes := parsePrefixes(data[offset:offset+withdrawnLen], 4, hasAddPath)
	offset += withdrawnLen

	// Total path attribute length.
	if offset+2 > len(data) {
		return nil, fmt.Errorf("bgp: no room for path attr length")
	}
	totalPathAttrLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+totalPathAttrLen > len(data) {
		return nil, fmt.Errorf("bgp: path attr length %d exceeds data", totalPathAttrLen)
	}

	// Parse path attributes.
	attrs, err := ParsePathAttributes(data[offset:offset+totalPathAttrLen], hasAddPath)
	if err != nil {
		return nil, fmt.Errorf("bgp: parse path attrs: %w", err)
	}
	offset += totalPathAttrLen

	// Parse IPv4 NLRI → action 'A'.
	nlriPrefixes := parsePrefixes(data[offset:], 4, hasAddPath)

	var events []*RouteEvent

	// Build withdrawal events.
	for _, p := range withdrawnPrefixes {
		events = append(events, &RouteEvent{
			AFI:    4,
			Prefix: p.Prefix,
			PathID: p.PathID,
			Action: "D",
		})
	}

	// Build announcement events with attributes.
	for _, p := range nlriPrefixes {
		events = append(events, &RouteEvent{
			AFI:       4,
			Prefix:    p.Prefix,
			PathID:    p.PathID,
			Action:    "A",
			Nexthop:   attrs.Nexthop,
			ASPath:    attrs.ASPath,
			Origin:    attrs.Origin,
			LocalPref: attrs.LocalPref,
			MED:       attrs.MED,
			CommStd:   attrs.CommStd,
			CommExt:   attrs.CommExt,
			CommLarge: attrs.CommLarge,
			Attrs:     attrs.Attrs,
		})
	}

	// MP_REACH_NLRI announcements (IPv4/IPv6).
	if afi := afiToVersion(attrs.MPReachAFI); afi != 0 {
		for _, p := range attrs.MPReachNLRI {
			events = append(events, &RouteEvent{
				AFI:       afi,
				Prefix:    p.Prefix,
				PathID:    p.PathID,
				Action:    "A",
				Nexthop:   attrs.MPReachNexthop,
				ASPath:    attrs.ASPath,
				Origin:    attrs.Origin,
				LocalPref: attrs.LocalPref,
				MED:       attrs.MED,
				CommStd:   attrs.CommStd,
				CommExt:   attrs.CommExt,
				CommLarge: attrs.CommLarge,
				Attrs:     attrs.Attrs,
			})
		}
	}

	// MP_UNREACH_NLRI withdrawals (IPv4/IPv6).
	if afi := afiToVersion(attrs.MPUnreachAFI); afi != 0 {
		for _, p := range attrs.MPUnreachNLRI {
			events = append(events, &RouteEvent{
				AFI:    afi,
				Prefix: p.Prefix,
				PathID: p.PathID,
				Action: "D",
			})
		}
	}

	return events, nil
}

// DetectEORAFI determines the address family for an End-of-RIB marker.
// It scans the BGP UPDATE's path attributes for MP_UNREACH_NLRI.
// If found with AFI=2 (IPv6), returns 6. Otherwise returns 4 (IPv4).
// Only call this when ParseUpdate returned 0 events and no error.
func DetectEORAFI(data []byte) int {
	if len(data) < BGPHeaderSize+4 {
		return 4
	}

	payload := data[BGPHeaderSize:]
	offset := 0

	// Skip withdrawn routes.
	if offset+2 > len(payload) {
		return 4
	}
	withdrawnLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if offset+withdrawnLen > len(payload) {
		return 4
	}
	offset += withdrawnLen

	// Read path attributes length.
	if offset+2 > len(payload) {
		return 4
	}
	pathAttrLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if offset+pathAttrLen > len(payload) {
		return 4
	}

	// Scan path attributes for MP_UNREACH_NLRI (type 15).
	attrEnd := offset + pathAttrLen
	for offset < attrEnd {
		if offset+2 > attrEnd {
			break
		}
		flags := payload[offset]
		typeCode := payload[offset+1]
		offset += 2

		var attrLen int
		if flags&0x10 != 0 { // Extended Length
			if offset+2 > attrEnd {
				break
			}
			attrLen = int(binary.BigEndian.Uint16(payload[offset : offset+2]))
			offset += 2
		} else {
			if offset+1 > attrEnd {
				break
			}
			attrLen = int(payload[offset])
			offset++
		}

		if offset+attrLen > attrEnd {
			break
		}

		if typeCode == AttrTypeMPUnreachNLRI && attrLen >= 2 {
			afi := binary.BigEndian.Uint16(payload[offset : offset+2])
			if afi == AFIIPv6 {
				return 6
			}
		}

		offset += attrLen
	}

	return 4
}

func parsePrefixesV4(data []byte, hasAddPath bool) []PrefixInfo {
	var prefixes []PrefixInfo
	offset := 0
	for offset < len(data) {
		var pathID int64
		if hasAddPath {
			if offset+4 > len(data) {
				break
			}
			pathID = int64(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4
		}
		if offset >= len(data) {
			break
		}
		prefixLen := int(data[offset])
		offset++
		byteLen := (prefixLen + 7) / 8
		if offset+byteLen > len(data) {
			break
		}
		ipBytes := make([]byte, 4)
		copy(ipBytes, data[offset:offset+byteLen])
		offset += byteLen
		ip := net.IP(ipBytes)
		prefixes = append(prefixes, PrefixInfo{
			Prefix: fmt.Sprintf("%s/%d", ip.String(), prefixLen),
			PathID: pathID,
		})
	}
	return prefixes
}
