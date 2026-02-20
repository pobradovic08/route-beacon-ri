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
