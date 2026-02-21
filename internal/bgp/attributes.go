package bgp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// PathAttributes holds parsed path attributes from a BGP UPDATE.
type PathAttributes struct {
	Origin    string
	ASPath    string
	Nexthop   string
	MED       *uint32
	LocalPref *uint32
	CommStd   []string
	CommExt   []string
	CommLarge []string
	Attrs     map[string]string // Unknown attributes keyed by type code

	// MP_REACH_NLRI / MP_UNREACH_NLRI extracted data
	MPReachAFI     uint16
	MPReachNLRI    []PrefixInfo
	MPReachNexthop string
	MPUnreachAFI   uint16
	MPUnreachNLRI  []PrefixInfo
}

// PrefixInfo represents a single NLRI prefix with optional path_id.
type PrefixInfo struct {
	Prefix string
	PathID int64
}

// ParsePathAttributes parses the path attributes section of a BGP UPDATE.
func ParsePathAttributes(data []byte, hasAddPath bool) (*PathAttributes, error) {
	attrs := &PathAttributes{
		Attrs: make(map[string]string),
	}

	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			return attrs, fmt.Errorf("bgp: attr header truncated at offset %d", offset)
		}

		flags := data[offset]
		typeCode := data[offset+1]
		offset += 2

		// Attribute length: 1 byte or 2 bytes depending on Extended Length flag.
		var attrLen int
		if flags&0x10 != 0 { // Extended Length
			if offset+2 > len(data) {
				return attrs, fmt.Errorf("bgp: extended attr length truncated")
			}
			attrLen = int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2
		} else {
			if offset+1 > len(data) {
				return attrs, fmt.Errorf("bgp: attr length truncated")
			}
			attrLen = int(data[offset])
			offset++
		}

		if offset+attrLen > len(data) {
			return attrs, fmt.Errorf("bgp: attr data truncated (type %d, need %d, have %d)", typeCode, attrLen, len(data)-offset)
		}

		attrData := data[offset : offset+attrLen]
		offset += attrLen

		switch typeCode {
		case AttrTypeOrigin:
			parseOrigin(attrData, attrs)
		case AttrTypeASPath:
			parseASPath(attrData, attrs)
		case AttrTypeNextHop:
			parseNextHop(attrData, attrs)
		case AttrTypeMED:
			parseMED(attrData, attrs)
		case AttrTypeLocalPref:
			parseLocalPref(attrData, attrs)
		case AttrTypeCommunity:
			parseCommunity(attrData, attrs)
		case AttrTypeMPReachNLRI:
			parseMPReachNLRI(attrData, attrs, hasAddPath)
		case AttrTypeMPUnreachNLRI:
			parseMPUnreachNLRI(attrData, attrs, hasAddPath)
		case AttrTypeExtCommunity:
			parseExtCommunity(attrData, attrs)
		case AttrTypeLargeCommunity:
			parseLargeCommunity(attrData, attrs)
		default:
			attrs.Attrs[fmt.Sprintf("%d", typeCode)] = hex.EncodeToString(attrData)
		}
	}

	return attrs, nil
}

func parseOrigin(data []byte, attrs *PathAttributes) {
	if len(data) < 1 {
		return
	}
	if v, ok := OriginValues[data[0]]; ok {
		attrs.Origin = v
	} else {
		attrs.Origin = fmt.Sprintf("UNKNOWN(%d)", data[0])
	}
}

func parseASPath(data []byte, attrs *PathAttributes) {
	var segments []string
	offset := 0
	for offset+2 <= len(data) {
		segType := data[offset]
		segLen := int(data[offset+1])
		offset += 2

		if offset+segLen*4 > len(data) {
			break
		}

		asns := make([]string, segLen)
		for i := 0; i < segLen; i++ {
			asn := binary.BigEndian.Uint32(data[offset : offset+4])
			asns[i] = fmt.Sprintf("%d", asn)
			offset += 4
		}

		switch segType {
		case ASPathSegmentSequence:
			segments = append(segments, strings.Join(asns, " "))
		case ASPathSegmentSet:
			segments = append(segments, "{"+strings.Join(asns, ",")+"}")
		}
	}

	attrs.ASPath = strings.Join(segments, " ")
}

func parseNextHop(data []byte, attrs *PathAttributes) {
	if len(data) == 4 {
		attrs.Nexthop = net.IP(data).String()
	}
}

func parseMED(data []byte, attrs *PathAttributes) {
	if len(data) == 4 {
		v := uint32(binary.BigEndian.Uint32(data))
		attrs.MED = &v
	}
}

func parseLocalPref(data []byte, attrs *PathAttributes) {
	if len(data) == 4 {
		v := uint32(binary.BigEndian.Uint32(data))
		attrs.LocalPref = &v
	}
}

func parseCommunity(data []byte, attrs *PathAttributes) {
	for i := 0; i+4 <= len(data); i += 4 {
		hi := binary.BigEndian.Uint16(data[i : i+2])
		lo := binary.BigEndian.Uint16(data[i+2 : i+4])
		attrs.CommStd = append(attrs.CommStd, fmt.Sprintf("%d:%d", hi, lo))
	}
}

func parseExtCommunity(data []byte, attrs *PathAttributes) {
	for i := 0; i+8 <= len(data); i += 8 {
		attrs.CommExt = append(attrs.CommExt, decodeExtCommunity(data[i:i+8]))
	}
}

// decodeExtCommunity decodes a single 8-byte extended community into a
// human-readable string. Recognises Route Target (subtype 0x02) and
// Route Origin / Site-of-Origin (subtype 0x03) for 2-octet AS, IPv4,
// and 4-octet AS types. Falls back to hex for unknown types.
func decodeExtCommunity(data []byte) string {
	typeHigh := data[0]
	typeLow := data[1]

	// Mask transitive bit for matching.
	typeHighBase := typeHigh & 0x3F

	switch typeHighBase {
	case 0x00: // 2-Octet AS Specific
		asn := binary.BigEndian.Uint16(data[2:4])
		val := binary.BigEndian.Uint32(data[4:8])
		switch typeLow {
		case 0x02:
			return fmt.Sprintf("RT:%d:%d", asn, val)
		case 0x03:
			return fmt.Sprintf("SOO:%d:%d", asn, val)
		}
	case 0x01: // IPv4 Address Specific
		ip := net.IP(data[2:6]).String()
		val := binary.BigEndian.Uint16(data[6:8])
		switch typeLow {
		case 0x02:
			return fmt.Sprintf("RT:%s:%d", ip, val)
		case 0x03:
			return fmt.Sprintf("SOO:%s:%d", ip, val)
		}
	case 0x02: // 4-Octet AS Specific
		asn := binary.BigEndian.Uint32(data[2:6])
		val := binary.BigEndian.Uint16(data[6:8])
		switch typeLow {
		case 0x02:
			return fmt.Sprintf("RT:%d:%d", asn, val)
		case 0x03:
			return fmt.Sprintf("SOO:%d:%d", asn, val)
		}
	}

	return hex.EncodeToString(data)
}

func parseLargeCommunity(data []byte, attrs *PathAttributes) {
	for i := 0; i+12 <= len(data); i += 12 {
		global := binary.BigEndian.Uint32(data[i : i+4])
		data1 := binary.BigEndian.Uint32(data[i+4 : i+8])
		data2 := binary.BigEndian.Uint32(data[i+8 : i+12])
		attrs.CommLarge = append(attrs.CommLarge, fmt.Sprintf("%d:%d:%d", global, data1, data2))
	}
}

func parseMPReachNLRI(data []byte, attrs *PathAttributes, hasAddPath bool) {
	if len(data) < 5 {
		return
	}

	afi := binary.BigEndian.Uint16(data[0:2])
	safi := data[2]
	if safi != SAFIUnicast {
		return // skip non-unicast AFI/SAFI silently
	}
	nhLen := int(data[3])

	attrs.MPReachAFI = afi
	offset := 4

	if offset+nhLen > len(data) {
		return
	}

	// Parse next-hop based on length.
	nhData := data[offset : offset+nhLen]
	switch nhLen {
	case 4:
		attrs.MPReachNexthop = net.IP(nhData).String()
	case 16:
		attrs.MPReachNexthop = net.IP(nhData).String()
	case 32:
		// Global + link-local; use global.
		attrs.MPReachNexthop = net.IP(nhData[:16]).String()
	}
	// nhLen is validated implicitly by the switch above; unrecognized
	// lengths are silently skipped (Nexthop left empty).
	if attrs.Nexthop == "" {
		attrs.Nexthop = attrs.MPReachNexthop
	}
	offset += nhLen

	// Skip SNPA entries (RFC 4760: 1-byte count, then N x {1-byte len, len bytes}).
	if offset >= len(data) {
		return
	}
	snpaCount := int(data[offset])
	offset++
	for i := 0; i < snpaCount; i++ {
		if offset >= len(data) {
			return
		}
		snpaLen := int(data[offset])
		offset++
		// SNPA length is in semi-octets; byte length = (snpaLen + 1) / 2
		snpaByteLen := (snpaLen + 1) / 2
		if offset+snpaByteLen > len(data) {
			return
		}
		offset += snpaByteLen
	}

	// Parse NLRI.
	if v := afiToVersion(afi); v != 0 {
		attrs.MPReachNLRI, _ = parsePrefixes(data[offset:], v, hasAddPath)
	}
}

func parseMPUnreachNLRI(data []byte, attrs *PathAttributes, hasAddPath bool) {
	if len(data) < 3 {
		return
	}

	afi := binary.BigEndian.Uint16(data[0:2])
	safi := data[2]
	if safi != SAFIUnicast {
		return // skip non-unicast AFI/SAFI silently
	}

	attrs.MPUnreachAFI = afi
	attrs.MPUnreachNLRI, _ = parsePrefixes(data[3:], afiToVersion(afi), hasAddPath)
}

func parsePrefixes(data []byte, ipVersion int, hasAddPath bool) ([]PrefixInfo, error) {
	var prefixes []PrefixInfo
	offset := 0

	for offset < len(data) {
		var pathID int64
		if hasAddPath {
			if offset+4 > len(data) {
				return prefixes, fmt.Errorf("bgp: prefix data truncated at offset %d", offset)
			}
			pathID = int64(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4
		}

		if offset >= len(data) {
			return prefixes, fmt.Errorf("bgp: prefix data truncated at offset %d", offset)
		}

		prefixLen := int(data[offset])
		offset++

		// Reject prefix lengths that exceed the AFI maximum.
		maxBits := maxIPLen(ipVersion) * 8
		if prefixLen > maxBits {
			return prefixes, fmt.Errorf("bgp: prefix data truncated at offset %d", offset)
		}

		// Number of bytes needed for the prefix.
		byteLen := (prefixLen + 7) / 8
		if offset+byteLen > len(data) {
			return prefixes, fmt.Errorf("bgp: prefix data truncated at offset %d", offset)
		}

		prefixBytes := make([]byte, maxIPLen(ipVersion))
		copy(prefixBytes, data[offset:offset+byteLen])
		offset += byteLen

		var ip net.IP
		if ipVersion == 4 {
			ip = net.IP(prefixBytes[:4])
		} else {
			ip = net.IP(prefixBytes[:16])
		}

		prefixes = append(prefixes, PrefixInfo{
			Prefix: fmt.Sprintf("%s/%d", ip.String(), prefixLen),
			PathID: pathID,
		})
	}

	return prefixes, nil
}

func afiToVersion(afi uint16) int {
	switch afi {
	case AFIIPv4:
		return 4
	case AFIIPv6:
		return 6
	default:
		return 0 // unsupported AFI
	}
}

func maxIPLen(version int) int {
	if version == 4 {
		return 4
	}
	return 16
}

// OriginASN extracts the origin AS number (last ASN) from a space-delimited
// AS path string. Returns nil if the path is empty or ends with an AS_SET
// (e.g. "{64497,64498}").
func OriginASN(asPath string) *int {
	asPath = strings.TrimSpace(asPath)
	if asPath == "" {
		return nil
	}

	fields := strings.Fields(asPath)
	last := fields[len(fields)-1]

	// AS_SET at the end → origin is ambiguous.
	if strings.HasPrefix(last, "{") {
		return nil
	}

	var asn int
	_, err := fmt.Sscanf(last, "%d", &asn)
	if err != nil {
		return nil
	}
	return &asn
}
