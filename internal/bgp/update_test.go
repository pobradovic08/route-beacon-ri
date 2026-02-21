package bgp

import (
	"encoding/binary"
	"testing"
)

// buildBGPUpdate constructs a BGP UPDATE message with the given components.
func buildBGPUpdate(withdrawn []byte, pathAttrs []byte, nlri []byte) []byte {
	bodyLen := 2 + len(withdrawn) + 2 + len(pathAttrs) + len(nlri)
	totalLen := 19 + bodyLen

	msg := make([]byte, totalLen)
	// Marker: 16 bytes of 0xFF
	for i := 0; i < 16; i++ {
		msg[i] = 0xFF
	}
	binary.BigEndian.PutUint16(msg[16:18], uint16(totalLen))
	msg[18] = 2 // type = UPDATE

	offset := 19
	binary.BigEndian.PutUint16(msg[offset:offset+2], uint16(len(withdrawn)))
	offset += 2
	copy(msg[offset:], withdrawn)
	offset += len(withdrawn)

	binary.BigEndian.PutUint16(msg[offset:offset+2], uint16(len(pathAttrs)))
	offset += 2
	copy(msg[offset:], pathAttrs)
	offset += len(pathAttrs)

	copy(msg[offset:], nlri)
	return msg
}

// buildPathAttr constructs a single path attribute.
func buildPathAttr(flags byte, typeCode byte, data []byte) []byte {
	if len(data) > 255 {
		// Extended length
		attr := make([]byte, 4+len(data))
		attr[0] = flags | 0x10 // Set Extended Length
		attr[1] = typeCode
		binary.BigEndian.PutUint16(attr[2:4], uint16(len(data)))
		copy(attr[4:], data)
		return attr
	}
	attr := make([]byte, 3+len(data))
	attr[0] = flags
	attr[1] = typeCode
	attr[2] = byte(len(data))
	copy(attr[3:], data)
	return attr
}

func TestParseUpdate_IPv4Announcement(t *testing.T) {
	// NLRI: 10.0.0.0/24
	nlri := []byte{24, 10, 0, 0} // prefixLen=24, 3 bytes of prefix

	// Path attributes: ORIGIN=IGP, NEXT_HOP=192.168.1.1
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0}) // IGP
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Action != "A" {
		t.Errorf("expected action 'A', got '%s'", ev.Action)
	}
	if ev.AFI != 4 {
		t.Errorf("expected AFI 4, got %d", ev.AFI)
	}
	if ev.Prefix != "10.0.0.0/24" {
		t.Errorf("expected prefix '10.0.0.0/24', got '%s'", ev.Prefix)
	}
	if ev.Origin != "IGP" {
		t.Errorf("expected origin 'IGP', got '%s'", ev.Origin)
	}
	if ev.Nexthop != "192.168.1.1" {
		t.Errorf("expected nexthop '192.168.1.1', got '%s'", ev.Nexthop)
	}
}

func TestParseUpdate_IPv4Withdrawal(t *testing.T) {
	// Withdrawn: 172.16.0.0/16
	withdrawn := []byte{16, 172, 16} // prefixLen=16, 2 bytes of prefix

	msg := buildBGPUpdate(withdrawn, nil, nil)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Action != "D" {
		t.Errorf("expected action 'D', got '%s'", ev.Action)
	}
	if ev.Prefix != "172.16.0.0/16" {
		t.Errorf("expected prefix '172.16.0.0/16', got '%s'", ev.Prefix)
	}
}

func TestParseUpdate_ASPath(t *testing.T) {
	// AS_PATH: AS_SEQUENCE [64496, 64497, 64498]
	asPathData := []byte{
		ASPathSegmentSequence, 3, // type=SEQUENCE, count=3
		0, 0, 0xFB, 0xF0, // AS64496
		0, 0, 0xFB, 0xF1, // AS64497
		0, 0, 0xFB, 0xF2, // AS64498
	}
	asPathAttr := buildPathAttr(0x40, AttrTypeASPath, asPathData)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, append(asPathAttr, nexthopAttr...)...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].ASPath != "64496 64497 64498" {
		t.Errorf("expected AS_PATH '64496 64497 64498', got '%s'", events[0].ASPath)
	}
}

func TestParseUpdate_StandardCommunities(t *testing.T) {
	// Communities: 64496:100, 64496:200
	commData := []byte{
		0xFB, 0xF0, 0x00, 0x64, // 64496:100
		0xFB, 0xF0, 0x00, 0xC8, // 64496:200
	}
	commAttr := buildPathAttr(0xC0, AttrTypeCommunity, commData)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, append(commAttr, nexthopAttr...)...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if len(ev.CommStd) != 2 {
		t.Fatalf("expected 2 communities, got %d", len(ev.CommStd))
	}
	if ev.CommStd[0] != "64496:100" {
		t.Errorf("expected '64496:100', got '%s'", ev.CommStd[0])
	}
	if ev.CommStd[1] != "64496:200" {
		t.Errorf("expected '64496:200', got '%s'", ev.CommStd[1])
	}
}

func TestParseUpdate_LargeCommunities(t *testing.T) {
	// Large community: 64496:1:2
	lcData := make([]byte, 12)
	binary.BigEndian.PutUint32(lcData[0:4], 64496)
	binary.BigEndian.PutUint32(lcData[4:8], 1)
	binary.BigEndian.PutUint32(lcData[8:12], 2)

	lcAttr := buildPathAttr(0xC0, AttrTypeLargeCommunity, lcData)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, append(lcAttr, nexthopAttr...)...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if len(events[0].CommLarge) != 1 {
		t.Fatalf("expected 1 large community, got %d", len(events[0].CommLarge))
	}
	if events[0].CommLarge[0] != "64496:1:2" {
		t.Errorf("expected '64496:1:2', got '%s'", events[0].CommLarge[0])
	}
}

func TestParseUpdate_AddPath(t *testing.T) {
	// NLRI with Add-Path: path_id=42, 10.0.0.0/24
	nlri := []byte{
		0, 0, 0, 42, // path_id=42
		24, 10, 0, 0, // prefixLen=24, 3 bytes
	}

	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, true) // hasAddPath=true
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].PathID != 42 {
		t.Errorf("expected PathID=42, got %d", events[0].PathID)
	}
}

func TestParseUpdate_IPv6MPReach(t *testing.T) {
	// Build MP_REACH_NLRI for IPv6
	// AFI=2, SAFI=1, NH_LEN=16, NH=2001:db8::1, SNPA=0, NLRI=2001:db8::/32
	nh := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	mpReach := make([]byte, 0, 4+16+1+5)
	mpReach = append(mpReach, 0, 2) // AFI=2 (IPv6)
	mpReach = append(mpReach, 1)    // SAFI=1 (unicast)
	mpReach = append(mpReach, 16)   // NH len
	mpReach = append(mpReach, nh...)
	mpReach = append(mpReach, 0)           // SNPA count
	mpReach = append(mpReach, 32)          // prefix len = /32
	mpReach = append(mpReach, 0x20, 0x01, 0x0d, 0xb8) // 4 bytes of prefix

	mpReachAttr := buildPathAttr(0x80, AttrTypeMPReachNLRI, mpReach)
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	pathAttrs := append(originAttr, mpReachAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nil)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Action != "A" {
		t.Errorf("expected action 'A', got '%s'", ev.Action)
	}
	if ev.AFI != 6 {
		t.Errorf("expected AFI 6, got %d", ev.AFI)
	}
	if ev.Prefix != "2001:db8::/32" {
		t.Errorf("expected prefix '2001:db8::/32', got '%s'", ev.Prefix)
	}
	if ev.Nexthop != "2001:db8::1" {
		t.Errorf("expected nexthop '2001:db8::1', got '%s'", ev.Nexthop)
	}
}

func TestParseUpdate_IPv6MPUnreach(t *testing.T) {
	// MP_UNREACH_NLRI: AFI=2, SAFI=1, 2001:db8:1::/48
	mpUnreach := []byte{
		0, 2, // AFI=2
		1,    // SAFI=1
		48,   // prefix len
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, // 6 bytes of prefix
	}
	mpUnreachAttr := buildPathAttr(0x80, AttrTypeMPUnreachNLRI, mpUnreach)

	msg := buildBGPUpdate(nil, mpUnreachAttr, nil)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Action != "D" {
		t.Errorf("expected action 'D', got '%s'", ev.Action)
	}
	if ev.AFI != 6 {
		t.Errorf("expected AFI 6, got %d", ev.AFI)
	}
	if ev.Prefix != "2001:db8:1::/48" {
		t.Errorf("expected prefix '2001:db8:1::/48', got '%s'", ev.Prefix)
	}
}

func TestParseUpdate_MEDAndLocalPref(t *testing.T) {
	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})

	medData := make([]byte, 4)
	binary.BigEndian.PutUint32(medData, 100)
	medAttr := buildPathAttr(0x80, AttrTypeMED, medData)

	lpData := make([]byte, 4)
	binary.BigEndian.PutUint32(lpData, 200)
	lpAttr := buildPathAttr(0x40, AttrTypeLocalPref, lpData)

	pathAttrs := append(originAttr, nexthopAttr...)
	pathAttrs = append(pathAttrs, medAttr...)
	pathAttrs = append(pathAttrs, lpAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.MED == nil || *ev.MED != 100 {
		t.Errorf("expected MED=100, got %v", ev.MED)
	}
	if ev.LocalPref == nil || *ev.LocalPref != 200 {
		t.Errorf("expected LocalPref=200, got %v", ev.LocalPref)
	}
}

func TestParseUpdate_UnknownAttribute(t *testing.T) {
	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	unknownAttr := buildPathAttr(0xC0, 99, []byte{0xDE, 0xAD})
	pathAttrs := append(originAttr, nexthopAttr...)
	pathAttrs = append(pathAttrs, unknownAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Attrs == nil {
		t.Fatal("expected attrs map to contain unknown attribute")
	}
	if events[0].Attrs["99"] != "dead" {
		t.Errorf("expected attrs[99]='dead', got '%s'", events[0].Attrs["99"])
	}
}

func TestParseUpdate_TruncatedAttrHeader(t *testing.T) {
	// Path attributes with only 1 byte (need at least 2 for flags+type).
	pathAttrs := []byte{0x40} // truncated: only flags, no type code
	nlri := []byte{24, 10, 0, 0}
	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	_, err := ParseUpdate(msg, false)
	if err == nil {
		t.Fatal("expected error for truncated attr header")
	}
}

func TestParseUpdate_TruncatedAttrLength(t *testing.T) {
	// Path attribute with extended length flag but missing length bytes.
	pathAttrs := []byte{0x50, AttrTypeOrigin} // 0x50 = 0x40|0x10 (transitive + extended), but no length bytes
	nlri := []byte{24, 10, 0, 0}
	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	_, err := ParseUpdate(msg, false)
	if err == nil {
		t.Fatal("expected error for truncated extended attr length")
	}
}

func TestParseUpdate_AttrDataTruncated(t *testing.T) {
	// Path attribute that claims 4 bytes of data but only has 2.
	pathAttrs := []byte{0x40, AttrTypeOrigin, 4, 0x00, 0x00} // length=4 but only 2 bytes of data
	nlri := []byte{24, 10, 0, 0}
	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	_, err := ParseUpdate(msg, false)
	if err == nil {
		t.Fatal("expected error for truncated attr data")
	}
}

func TestParseUpdate_UnsupportedAFI_MPReach(t *testing.T) {
	// MP_REACH_NLRI with unsupported AFI=3 should produce no events for that prefix.
	mpReach := make([]byte, 0, 32)
	mpReach = append(mpReach, 0, 3) // AFI=3 (unsupported)
	mpReach = append(mpReach, 1)    // SAFI=1
	mpReach = append(mpReach, 4)    // NH len = 4
	mpReach = append(mpReach, 192, 168, 1, 1) // NH
	mpReach = append(mpReach, 0)    // SNPA count
	mpReach = append(mpReach, 24, 10, 0, 0)   // prefix /24

	mpReachAttr := buildPathAttr(0x80, AttrTypeMPReachNLRI, mpReach)
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	pathAttrs := append(originAttr, mpReachAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nil)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events for unsupported AFI, got %d", len(events))
	}
}

func TestParseUpdate_UnsupportedAFI_MPUnreach(t *testing.T) {
	// MP_UNREACH_NLRI with unsupported AFI=3 should produce no events.
	mpUnreach := []byte{
		0, 3, // AFI=3 (unsupported)
		1,    // SAFI=1
		24, 10, 0, 0, // prefix /24
	}
	mpUnreachAttr := buildPathAttr(0x80, AttrTypeMPUnreachNLRI, mpUnreach)

	msg := buildBGPUpdate(nil, mpUnreachAttr, nil)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events for unsupported AFI, got %d", len(events))
	}
}

func TestParseUpdate_MPReachWithNonZeroSNPA(t *testing.T) {
	// MP_REACH_NLRI with 1 SNPA entry (length=4 semi-octets = 2 bytes payload).
	// After SNPA, there should be a valid IPv6 prefix 2001:db8::/32.
	nh := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	mpReach := make([]byte, 0, 64)
	mpReach = append(mpReach, 0, 2) // AFI=2 (IPv6)
	mpReach = append(mpReach, 1)    // SAFI=1 (unicast)
	mpReach = append(mpReach, 16)   // NH len
	mpReach = append(mpReach, nh...)
	mpReach = append(mpReach, 1)          // SNPA count = 1
	mpReach = append(mpReach, 4)          // SNPA length = 4 semi-octets (2 bytes)
	mpReach = append(mpReach, 0xAB, 0xCD) // SNPA data (2 bytes)
	mpReach = append(mpReach, 32)         // prefix len = /32
	mpReach = append(mpReach, 0x20, 0x01, 0x0d, 0xb8) // 4 bytes of prefix

	mpReachAttr := buildPathAttr(0x80, AttrTypeMPReachNLRI, mpReach)
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	pathAttrs := append(originAttr, mpReachAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nil)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Prefix != "2001:db8::/32" {
		t.Errorf("expected prefix '2001:db8::/32', got '%s'", ev.Prefix)
	}
	if ev.Nexthop != "2001:db8::1" {
		t.Errorf("expected nexthop '2001:db8::1', got '%s'", ev.Nexthop)
	}
}

func TestParseUpdate_IPv6MPReach_AddPath(t *testing.T) {
	// MP_REACH_NLRI for IPv6 with Add-Path: path_id=7, 2001:db8::/32
	nh := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	mpReach := make([]byte, 0, 64)
	mpReach = append(mpReach, 0, 2) // AFI=2 (IPv6)
	mpReach = append(mpReach, 1)    // SAFI=1 (unicast)
	mpReach = append(mpReach, 16)   // NH len
	mpReach = append(mpReach, nh...)
	mpReach = append(mpReach, 0)                     // SNPA count
	mpReach = append(mpReach, 0, 0, 0, 7)            // path_id=7
	mpReach = append(mpReach, 32)                     // prefix len = /32
	mpReach = append(mpReach, 0x20, 0x01, 0x0d, 0xb8) // 4 bytes of prefix

	mpReachAttr := buildPathAttr(0x80, AttrTypeMPReachNLRI, mpReach)
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	pathAttrs := append(originAttr, mpReachAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nil)

	events, err := ParseUpdate(msg, true) // hasAddPath=true
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.AFI != 6 {
		t.Errorf("expected AFI 6, got %d", ev.AFI)
	}
	if ev.Prefix != "2001:db8::/32" {
		t.Errorf("expected prefix '2001:db8::/32', got '%s'", ev.Prefix)
	}
	if ev.PathID != 7 {
		t.Errorf("expected PathID=7, got %d", ev.PathID)
	}
}

func TestParseUpdate_IPv6MPUnreach_AddPath(t *testing.T) {
	// MP_UNREACH_NLRI for IPv6 with Add-Path: path_id=99, 2001:db8:1::/48
	mpUnreach := []byte{
		0, 2, // AFI=2
		1,    // SAFI=1
		0, 0, 0, 99, // path_id=99
		48,                                    // prefix len
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01,   // 6 bytes of prefix
	}
	mpUnreachAttr := buildPathAttr(0x80, AttrTypeMPUnreachNLRI, mpUnreach)

	msg := buildBGPUpdate(nil, mpUnreachAttr, nil)

	events, err := ParseUpdate(msg, true) // hasAddPath=true
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Action != "D" {
		t.Errorf("expected action 'D', got '%s'", ev.Action)
	}
	if ev.AFI != 6 {
		t.Errorf("expected AFI 6, got %d", ev.AFI)
	}
	if ev.Prefix != "2001:db8:1::/48" {
		t.Errorf("expected prefix '2001:db8:1::/48', got '%s'", ev.Prefix)
	}
	if ev.PathID != 99 {
		t.Errorf("expected PathID=99, got %d", ev.PathID)
	}
}

func TestDetectEORAFI_IPv4(t *testing.T) {
	// Empty BGP UPDATE: withdrawn_len=0, path_attr_len=0, no NLRI → IPv4 EOR.
	msg := buildBGPUpdate(nil, nil, nil)
	afi := DetectEORAFI(msg)
	if afi != 4 {
		t.Errorf("expected AFI 4, got %d", afi)
	}
}

func TestDetectEORAFI_IPv6(t *testing.T) {
	// BGP UPDATE with MP_UNREACH_NLRI: AFI=2, SAFI=1, no prefixes → IPv6 EOR.
	mpUnreach := []byte{
		0, 2, // AFI=2 (IPv6)
		1,    // SAFI=1 (unicast)
		// No withdrawn prefixes.
	}
	mpUnreachAttr := buildPathAttr(0x80, AttrTypeMPUnreachNLRI, mpUnreach)
	msg := buildBGPUpdate(nil, mpUnreachAttr, nil)
	afi := DetectEORAFI(msg)
	if afi != 6 {
		t.Errorf("expected AFI 6, got %d", afi)
	}
}

func TestDetectEORAFI_IPv6WithPrecedingAttrs(t *testing.T) {
	// BGP UPDATE with ORIGIN + AS_PATH (extended-length) + MP_UNREACH_NLRI(AFI=2, SAFI=1).
	// Ensures DetectEORAFI correctly scans past preceding attributes,
	// including one with the extended-length flag set.
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0}) // 3 bytes

	// Build an AS_PATH with extended-length flag (>255 bytes of AS data).
	// 65 AS numbers * 4 bytes = 260 bytes of segment data + 2 byte segment header = 262 bytes.
	asPathData := make([]byte, 2+65*4)
	asPathData[0] = ASPathSegmentSequence
	asPathData[1] = 65
	for i := 0; i < 65; i++ {
		binary.BigEndian.PutUint32(asPathData[2+i*4:], uint32(64496+i))
	}
	asPathAttr := buildPathAttr(0x40, AttrTypeASPath, asPathData) // will auto-set extended-length flag

	// MP_UNREACH_NLRI: AFI=2, SAFI=1, no prefixes → IPv6 EOR.
	mpUnreach := []byte{0, 2, 1}
	mpUnreachAttr := buildPathAttr(0x80, AttrTypeMPUnreachNLRI, mpUnreach)

	pathAttrs := append(originAttr, asPathAttr...)
	pathAttrs = append(pathAttrs, mpUnreachAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nil)
	afi := DetectEORAFI(msg)
	if afi != 6 {
		t.Errorf("expected AFI 6 with preceding extended-length attrs, got %d", afi)
	}
}

func TestDetectEORAFI_TooShort(t *testing.T) {
	// Truncated data → safe default IPv4.
	afi := DetectEORAFI([]byte{0xFF})
	if afi != 4 {
		t.Errorf("expected AFI 4 for truncated data, got %d", afi)
	}
}

func TestParseUpdateAutoDetect_AddPathWithoutFBit(t *testing.T) {
	// Simulate cEOS behavior: Add-Path encoded NLRI with hasAddPath=false.
	// NLRI: path_id=68 (0x00000044), 10.100.3.0/24 + path_id=57 (0x00000039), 10.100.193.0/24
	nlri := []byte{
		0, 0, 0, 68, // path_id=68
		24, 10, 100, 3, // 10.100.3.0/24
		0, 0, 0, 57, // path_id=57
		24, 10, 100, 193, // 10.100.193.0/24
	}

	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{10, 0, 0, 2})
	pathAttrs := append(originAttr, nexthopAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	// Parse with hasAddPath=false (simulating missing F-bit).
	events, detectedAddPath, err := ParseUpdateAutoDetect(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !detectedAddPath {
		t.Fatal("expected auto-detection to enable Add-Path")
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Prefix != "10.100.3.0/24" {
		t.Errorf("expected prefix '10.100.3.0/24', got '%s'", events[0].Prefix)
	}
	if events[0].PathID != 68 {
		t.Errorf("expected PathID=68, got %d", events[0].PathID)
	}
	if events[1].Prefix != "10.100.193.0/24" {
		t.Errorf("expected prefix '10.100.193.0/24', got '%s'", events[1].Prefix)
	}
	if events[1].PathID != 57 {
		t.Errorf("expected PathID=57, got %d", events[1].PathID)
	}
}

func TestParseUpdateAutoDetect_AddPathECMP(t *testing.T) {
	// Simulate ECMP Add-Path without F-bit: multiple NLRI with small path_ids
	// that produce invalid CIDRs (host bits set) when parsed without Add-Path.
	// path_id=1, 10.100.0.0/24 + path_id=2, 10.100.0.0/24
	nlri := []byte{
		0, 0, 0, 1, // path_id=1
		24, 10, 100, 0, // 10.100.0.0/24
		0, 0, 0, 2, // path_id=2
		24, 10, 100, 0, // 10.100.0.0/24
	}

	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{172, 30, 0, 30})
	pathAttrs := append(originAttr, nexthopAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, detectedAddPath, err := ParseUpdateAutoDetect(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !detectedAddPath {
		t.Fatal("expected auto-detection to enable Add-Path for ECMP")
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Prefix != "10.100.0.0/24" {
		t.Errorf("expected prefix '10.100.0.0/24', got '%s'", events[0].Prefix)
	}
	if events[0].PathID != 1 {
		t.Errorf("expected PathID=1, got %d", events[0].PathID)
	}
	if events[1].PathID != 2 {
		t.Errorf("expected PathID=2, got %d", events[1].PathID)
	}
}

func TestParseUpdateAutoDetect_NoFalsePositive(t *testing.T) {
	// Normal NLRI without Add-Path should not trigger auto-detection.
	nlri := []byte{24, 10, 0, 0} // 10.0.0.0/24

	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, detectedAddPath, err := ParseUpdateAutoDetect(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detectedAddPath {
		t.Error("expected no Add-Path auto-detection for normal NLRI")
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Prefix != "10.0.0.0/24" {
		t.Errorf("expected prefix '10.0.0.0/24', got '%s'", events[0].Prefix)
	}
}

func TestParseUpdateAutoDetect_RealDefaultRoute(t *testing.T) {
	// A real 0.0.0.0/0 default route without Add-Path should not trigger detection.
	nlri := []byte{0} // prefix_len=0 → 0.0.0.0/0

	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, detectedAddPath, err := ParseUpdateAutoDetect(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	// If auto-detect retries with Add-Path and gets worse results, it should
	// keep the original. A single 0.0.0.0/0 followed by retry that produces
	// nothing valid should keep the original.
	_ = detectedAddPath // either value is acceptable for a genuine default route
	if events[0].Prefix != "0.0.0.0/0" {
		t.Errorf("expected prefix '0.0.0.0/0', got '%s'", events[0].Prefix)
	}
}

// --- H10-H15, H18 tests ---

func TestParseUpdate_NonUpdateMessageType(t *testing.T) {
	// Build a BGP message with type=4 (KEEPALIVE) instead of type=2 (UPDATE).
	msg := make([]byte, 19)
	for i := 0; i < 16; i++ {
		msg[i] = 0xFF
	}
	binary.BigEndian.PutUint16(msg[16:18], 19)
	msg[18] = 4 // KEEPALIVE

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("expected no error for non-UPDATE type, got: %v", err)
	}
	if events != nil {
		t.Errorf("expected nil events for non-UPDATE type, got %d events", len(events))
	}
}

func TestParseUpdate_TooShort(t *testing.T) {
	// Pass data shorter than 19 bytes (BGPHeaderSize).
	data := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	_, err := ParseUpdate(data, false)
	if err == nil {
		t.Fatal("expected error for data shorter than BGP header size")
	}
}

func TestParseUpdatePayload_TruncatedPayload(t *testing.T) {
	// Build a valid BGP UPDATE header but with payload less than 4 bytes.
	// The UPDATE header is 19 bytes, then we need at least 4 bytes for
	// withdrawn_len(2) + path_attr_len(2). Provide only 2.
	totalLen := 19 + 2
	msg := make([]byte, totalLen)
	for i := 0; i < 16; i++ {
		msg[i] = 0xFF
	}
	binary.BigEndian.PutUint16(msg[16:18], uint16(totalLen))
	msg[18] = 2 // type = UPDATE
	// Payload: only 2 bytes of zeros (withdrawn_len=0, but no room for path_attr_len).
	msg[19] = 0
	msg[20] = 0

	_, err := ParseUpdate(msg, false)
	if err == nil {
		t.Fatal("expected error for truncated payload (less than 4 bytes)")
	}
}

func TestParseUpdate_IPv4AddPathWithdrawals(t *testing.T) {
	// Build a BGP UPDATE with withdrawn routes that include Add-Path path IDs.
	// Withdrawn: path_id=10, 10.0.0.0/24 + path_id=20, 172.16.0.0/16
	withdrawn := []byte{
		0, 0, 0, 10, // path_id=10
		24, 10, 0, 0, // 10.0.0.0/24
		0, 0, 0, 20, // path_id=20
		16, 172, 16, // 172.16.0.0/16
	}

	msg := buildBGPUpdate(withdrawn, nil, nil)

	events, err := ParseUpdate(msg, true) // hasAddPath=true
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	// First withdrawal.
	if events[0].Action != "D" {
		t.Errorf("event[0]: expected action 'D', got '%s'", events[0].Action)
	}
	if events[0].Prefix != "10.0.0.0/24" {
		t.Errorf("event[0]: expected prefix '10.0.0.0/24', got '%s'", events[0].Prefix)
	}
	if events[0].PathID != 10 {
		t.Errorf("event[0]: expected PathID=10, got %d", events[0].PathID)
	}

	// Second withdrawal.
	if events[1].Action != "D" {
		t.Errorf("event[1]: expected action 'D', got '%s'", events[1].Action)
	}
	if events[1].Prefix != "172.16.0.0/16" {
		t.Errorf("event[1]: expected prefix '172.16.0.0/16', got '%s'", events[1].Prefix)
	}
	if events[1].PathID != 20 {
		t.Errorf("event[1]: expected PathID=20, got %d", events[1].PathID)
	}
}

func TestParseUpdateAutoDetect_InitialParseError(t *testing.T) {
	// Pass truncated/corrupt data that causes ParseUpdate to return an error.
	// 19-byte header with type=2 but only 1 byte of payload (need at least 4).
	totalLen := 20
	data := make([]byte, totalLen)
	for i := 0; i < 16; i++ {
		data[i] = 0xFF
	}
	binary.BigEndian.PutUint16(data[16:18], uint16(totalLen))
	data[18] = 2 // UPDATE
	data[19] = 0 // only 1 byte of payload

	events, hasAddPath, err := ParseUpdateAutoDetect(data, false)
	if err == nil {
		t.Fatal("expected error for truncated data")
	}
	// hasAddPath should match the original input (false).
	if hasAddPath != false {
		t.Errorf("expected hasAddPath=false, got %v", hasAddPath)
	}
	// events may be nil or empty; just verify the error was propagated.
	_ = events
}

func TestParseASPath_ASSet(t *testing.T) {
	// AS_PATH: AS_SEQUENCE [64496] + AS_SET {64497, 64498}
	asPathData := []byte{
		ASPathSegmentSequence, 1, // type=SEQUENCE, count=1
		0, 0, 0xFB, 0xF0, // AS64496
		ASPathSegmentSet, 2, // type=SET, count=2
		0, 0, 0xFB, 0xF1, // AS64497
		0, 0, 0xFB, 0xF2, // AS64498
	}
	asPathAttr := buildPathAttr(0x40, AttrTypeASPath, asPathData)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, append(asPathAttr, nexthopAttr...)...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	expected := "64496 {64497,64498}"
	if events[0].ASPath != expected {
		t.Errorf("expected AS_PATH '%s', got '%s'", expected, events[0].ASPath)
	}
}

// --- BGP attribute tests ---

func TestParseExtCommunities(t *testing.T) {
	// Extended community: 2 communities, each 8 bytes.
	extCommData := []byte{
		0x00, 0x02, 0xFB, 0xF0, 0x00, 0x00, 0x00, 0x64, // Route Target 64496:100
		0x00, 0x02, 0xFB, 0xF0, 0x00, 0x00, 0x00, 0xC8, // Route Target 64496:200
	}
	extCommAttr := buildPathAttr(0xC0, AttrTypeExtCommunity, extCommData)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, append(extCommAttr, nexthopAttr...)...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if len(ev.CommExt) != 2 {
		t.Fatalf("expected 2 extended communities, got %d", len(ev.CommExt))
	}
	// 2-Octet AS Route Target: type 0x00, subtype 0x02 → "RT:ASN:value"
	if ev.CommExt[0] != "RT:64496:100" {
		t.Errorf("expected CommExt[0]='RT:64496:100', got '%s'", ev.CommExt[0])
	}
	if ev.CommExt[1] != "RT:64496:200" {
		t.Errorf("expected CommExt[1]='RT:64496:200', got '%s'", ev.CommExt[1])
	}
}

func TestMPReachNLRI_DualNexthop(t *testing.T) {
	// MP_REACH_NLRI with 32-byte next-hop: global + link-local IPv6.
	// Global: 2001:db8::1, Link-local: fe80::1
	global := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	linkLocal := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	mpReach := make([]byte, 0, 64)
	mpReach = append(mpReach, 0, 2) // AFI=2 (IPv6)
	mpReach = append(mpReach, 1)    // SAFI=1 (unicast)
	mpReach = append(mpReach, 32)   // NH len = 32 (global + link-local)
	mpReach = append(mpReach, global...)
	mpReach = append(mpReach, linkLocal...)
	mpReach = append(mpReach, 0)                          // SNPA count
	mpReach = append(mpReach, 32)                          // prefix len = /32
	mpReach = append(mpReach, 0x20, 0x01, 0x0d, 0xb8) // 4 bytes of prefix

	mpReachAttr := buildPathAttr(0x80, AttrTypeMPReachNLRI, mpReach)
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	pathAttrs := append(originAttr, mpReachAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nil)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// Should use global address (first 16 bytes), not link-local.
	if events[0].Nexthop != "2001:db8::1" {
		t.Errorf("expected nexthop '2001:db8::1', got '%s'", events[0].Nexthop)
	}
}

func TestMPReachNLRI_IPv4Nexthop(t *testing.T) {
	// MP_REACH_NLRI with 4-byte next-hop (IPv4 over MP).
	mpReach := make([]byte, 0, 32)
	mpReach = append(mpReach, 0, 1)          // AFI=1 (IPv4)
	mpReach = append(mpReach, 1)              // SAFI=1 (unicast)
	mpReach = append(mpReach, 4)              // NH len = 4
	mpReach = append(mpReach, 10, 0, 0, 1)   // NH = 10.0.0.1
	mpReach = append(mpReach, 0)              // SNPA count
	mpReach = append(mpReach, 24, 10, 1, 0)  // 10.1.0.0/24

	mpReachAttr := buildPathAttr(0x80, AttrTypeMPReachNLRI, mpReach)
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	pathAttrs := append(originAttr, mpReachAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nil)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Nexthop != "10.0.0.1" {
		t.Errorf("expected nexthop '10.0.0.1', got '%s'", events[0].Nexthop)
	}
	if events[0].Prefix != "10.1.0.0/24" {
		t.Errorf("expected prefix '10.1.0.0/24', got '%s'", events[0].Prefix)
	}
}

func TestParseASPath_TruncatedSegment(t *testing.T) {
	// AS_PATH where segment header claims 3 ASNs but data only contains 2.
	// The parser should parse what's available and stop gracefully.
	asPathData := []byte{
		ASPathSegmentSequence, 3, // type=SEQUENCE, count=3
		0, 0, 0xFB, 0xF0, // AS64496
		0, 0, 0xFB, 0xF1, // AS64497
		// Missing third ASN — only 8 bytes of ASN data instead of required 12.
	}
	asPathAttr := buildPathAttr(0x40, AttrTypeASPath, asPathData)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, append(asPathAttr, nexthopAttr...)...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// The parser should break out of the segment when data runs out.
	// With segLen*4=12 > len(data)-offset, the parseASPath loop breaks
	// before parsing any ASNs in this segment, resulting in an empty AS_PATH.
	// This is graceful handling — no crash, no error.
	_ = events[0].ASPath // verify it doesn't crash; exact value depends on impl
}

func TestParseOrigin_EGP(t *testing.T) {
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{1}) // EGP
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	nlri := []byte{24, 10, 0, 0}

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Origin != "EGP" {
		t.Errorf("expected origin 'EGP', got '%s'", events[0].Origin)
	}
}

func TestParseOrigin_INCOMPLETE(t *testing.T) {
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{2}) // INCOMPLETE
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	nlri := []byte{24, 10, 0, 0}

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Origin != "INCOMPLETE" {
		t.Errorf("expected origin 'INCOMPLETE', got '%s'", events[0].Origin)
	}
}

func TestParseCommunity_NonMultipleOf4(t *testing.T) {
	// Community data is 6 bytes — not a multiple of 4.
	// Should parse the first complete 4-byte community and ignore the trailing 2 bytes.
	commData := []byte{
		0xFB, 0xF0, 0x00, 0x64, // 64496:100 (4 bytes)
		0xAA, 0xBB, // trailing 2 bytes (incomplete community)
	}
	commAttr := buildPathAttr(0xC0, AttrTypeCommunity, commData)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, append(commAttr, nexthopAttr...)...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if len(ev.CommStd) != 1 {
		t.Fatalf("expected 1 community (ignoring incomplete trailing bytes), got %d", len(ev.CommStd))
	}
	if ev.CommStd[0] != "64496:100" {
		t.Errorf("expected '64496:100', got '%s'", ev.CommStd[0])
	}
}

// --- Stream 3: SAFI validation tests ---

func TestParseMPReachNLRI_NonUnicastSAFI(t *testing.T) {
	// MP_REACH_NLRI with SAFI=2 (multicast) should produce no events.
	mpReach := make([]byte, 0, 32)
	mpReach = append(mpReach, 0, 2) // AFI=2 (IPv6)
	mpReach = append(mpReach, 2)    // SAFI=2 (multicast) — NOT unicast
	mpReach = append(mpReach, 16)   // NH len
	mpReach = append(mpReach, make([]byte, 16)...) // NH (zeros)
	mpReach = append(mpReach, 0)                   // SNPA count
	mpReach = append(mpReach, 32, 0x20, 0x01, 0x0d, 0xb8) // prefix /32

	mpReachAttr := buildPathAttr(0x80, AttrTypeMPReachNLRI, mpReach)
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	pathAttrs := append(originAttr, mpReachAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nil)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events for non-unicast SAFI in MP_REACH, got %d", len(events))
	}
}

func TestParseMPUnreachNLRI_NonUnicastSAFI(t *testing.T) {
	// MP_UNREACH_NLRI with SAFI=4 (MPLS-labeled) should produce no events.
	mpUnreach := []byte{
		0, 2, // AFI=2
		4,    // SAFI=4 (MPLS-labeled) — NOT unicast
		48,   // prefix len
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, // 6 bytes of prefix
	}
	mpUnreachAttr := buildPathAttr(0x80, AttrTypeMPUnreachNLRI, mpUnreach)

	msg := buildBGPUpdate(nil, mpUnreachAttr, nil)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events for non-unicast SAFI in MP_UNREACH, got %d", len(events))
	}
}

// --- Stream 3: parsePrefixes partial error ---

func TestParsePrefixes_PartialError(t *testing.T) {
	// NLRI with 2 prefixes where the second is truncated.
	nlri := []byte{
		24, 10, 0, 0, // valid: 10.0.0.0/24
		24, 10, // truncated: prefix_len=24 needs 3 bytes, only 1 provided
	}

	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should get at least 1 event for the valid first prefix.
	if len(events) < 1 {
		t.Fatalf("expected at least 1 event for partial NLRI, got %d", len(events))
	}
	if events[0].Prefix != "10.0.0.0/24" {
		t.Errorf("expected prefix '10.0.0.0/24', got '%s'", events[0].Prefix)
	}
}

// --- Stream 3: ParseUpdateAutoDetect retry also fails ---

func TestParseUpdateAutoDetect_RetryAlsoFails(t *testing.T) {
	// Build corrupt NLRI with prefix_len > 32 (invalid for IPv4).
	// Both initial parse and Add-Path retry should handle gracefully.
	nlri := []byte{33, 10, 0, 0, 0, 1} // prefix_len=33 > max 32 for IPv4

	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	// Key invariant: no panic, regardless of error/event result.
	events, _, err := ParseUpdateAutoDetect(msg, false)
	_ = events
	_ = err
}

// --- OriginASN tests ---

func TestOriginASN_SimpleSequence(t *testing.T) {
	asn := OriginASN("64496 64497 64498")
	if asn == nil {
		t.Fatal("expected non-nil origin ASN")
	}
	if *asn != 64498 {
		t.Errorf("expected 64498, got %d", *asn)
	}
}

func TestOriginASN_SingleASN(t *testing.T) {
	asn := OriginASN("64496")
	if asn == nil {
		t.Fatal("expected non-nil origin ASN")
	}
	if *asn != 64496 {
		t.Errorf("expected 64496, got %d", *asn)
	}
}

func TestOriginASN_Empty(t *testing.T) {
	asn := OriginASN("")
	if asn != nil {
		t.Errorf("expected nil for empty as_path, got %d", *asn)
	}
}

func TestOriginASN_ASSetAtEnd(t *testing.T) {
	asn := OriginASN("64496 {64497,64498}")
	if asn != nil {
		t.Errorf("expected nil for AS_SET origin, got %d", *asn)
	}
}

func TestOriginASN_Whitespace(t *testing.T) {
	asn := OriginASN("  64496  64497  ")
	if asn == nil {
		t.Fatal("expected non-nil origin ASN")
	}
	if *asn != 64497 {
		t.Errorf("expected 64497, got %d", *asn)
	}
}

// --- Extended community decoding tests ---

func TestDecodeExtCommunity_IPv4RT(t *testing.T) {
	// IPv4 Address Specific Route Target: type 0x01, subtype 0x02
	// IPv4: 10.0.0.1, value: 100
	data := []byte{0x01, 0x02, 10, 0, 0, 1, 0, 100}
	extCommAttr := buildPathAttr(0xC0, AttrTypeExtCommunity, data)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, append(extCommAttr, nexthopAttr...)...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if len(events[0].CommExt) != 1 {
		t.Fatalf("expected 1 ext community, got %d", len(events[0].CommExt))
	}
	if events[0].CommExt[0] != "RT:10.0.0.1:100" {
		t.Errorf("expected 'RT:10.0.0.1:100', got '%s'", events[0].CommExt[0])
	}
}

func TestDecodeExtCommunity_4OctetASRT(t *testing.T) {
	// 4-Octet AS Route Target: type 0x02, subtype 0x02
	// AS: 131072 (0x00020000), value: 500
	data := []byte{0x02, 0x02, 0x00, 0x02, 0x00, 0x00, 0x01, 0xF4}
	extCommAttr := buildPathAttr(0xC0, AttrTypeExtCommunity, data)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, append(extCommAttr, nexthopAttr...)...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events[0].CommExt) != 1 {
		t.Fatalf("expected 1 ext community, got %d", len(events[0].CommExt))
	}
	if events[0].CommExt[0] != "RT:131072:500" {
		t.Errorf("expected 'RT:131072:500', got '%s'", events[0].CommExt[0])
	}
}

func TestDecodeExtCommunity_SOO(t *testing.T) {
	// 2-Octet AS Site-of-Origin: type 0x00, subtype 0x03
	// AS: 64496, value: 1
	data := []byte{0x00, 0x03, 0xFB, 0xF0, 0x00, 0x00, 0x00, 0x01}
	extCommAttr := buildPathAttr(0xC0, AttrTypeExtCommunity, data)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, append(extCommAttr, nexthopAttr...)...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if events[0].CommExt[0] != "SOO:64496:1" {
		t.Errorf("expected 'SOO:64496:1', got '%s'", events[0].CommExt[0])
	}
}

func TestDecodeExtCommunity_TransitiveBit(t *testing.T) {
	// Transitive 2-Octet AS Route Target: type 0x40, subtype 0x02
	// (bit 6 set = non-transitive, but we mask with 0x3F)
	data := []byte{0x40, 0x02, 0xFB, 0xF0, 0x00, 0x00, 0x00, 0x64}
	extCommAttr := buildPathAttr(0xC0, AttrTypeExtCommunity, data)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, append(extCommAttr, nexthopAttr...)...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if events[0].CommExt[0] != "RT:64496:100" {
		t.Errorf("expected 'RT:64496:100', got '%s'", events[0].CommExt[0])
	}
}

func TestDecodeExtCommunity_UnknownType(t *testing.T) {
	// Unknown type 0x06, subtype 0x99 → hex fallback
	data := []byte{0x06, 0x99, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	extCommAttr := buildPathAttr(0xC0, AttrTypeExtCommunity, data)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, append(extCommAttr, nexthopAttr...)...)

	msg := buildBGPUpdate(nil, pathAttrs, nlri)

	events, err := ParseUpdate(msg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if events[0].CommExt[0] != "0699010203040506" {
		t.Errorf("expected hex fallback '0699010203040506', got '%s'", events[0].CommExt[0])
	}
}
