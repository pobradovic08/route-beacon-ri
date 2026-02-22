package state

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/route-beacon/rib-ingester/internal/bgp"
	"github.com/route-beacon/rib-ingester/internal/bmp"
	"github.com/twmb/franz-go/pkg/kgo"
	"go.uber.org/zap"
)

// --- Test helpers for building OpenBMP / BMP / BGP frames ---

// buildBGPUpdate constructs a BGP UPDATE message with the given components.
func buildBGPUpdate(withdrawn []byte, pathAttrs []byte, nlri []byte) []byte {
	bodyLen := 2 + len(withdrawn) + 2 + len(pathAttrs) + len(nlri)
	totalLen := 19 + bodyLen

	msg := make([]byte, totalLen)
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

// buildPathAttr constructs a single BGP path attribute.
func buildPathAttr(flags byte, typeCode byte, data []byte) []byte {
	if len(data) > 255 {
		attr := make([]byte, 4+len(data))
		attr[0] = flags | 0x10
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

// buildPerPeerHeader constructs a 42-byte BMP per-peer header.
// peerType: 0=Global, 1=RD, 2=Local, 3=LocRIB
// peerAddr: 4-byte IPv4 address (placed as IPv4-mapped IPv6).
func buildPerPeerHeader(peerType uint8, peerFlags uint8, peerAddr [4]byte) []byte {
	hdr := make([]byte, 42)
	hdr[0] = peerType
	hdr[1] = peerFlags
	// Distinguisher: 8 bytes at offset 2 (zero)
	// Peer address: 16 bytes at offset 10 (IPv4-mapped IPv6)
	hdr[20] = 0xFF
	hdr[21] = 0xFF
	copy(hdr[22:26], peerAddr[:])
	// AS, BGPID, timestamps at offset 26-41 (zero)
	return hdr
}

// buildBMPRouteMonitoring builds a BMP Route Monitoring message wrapping a BGP UPDATE.
func buildBMPRouteMonitoring(peerType uint8, peerFlags uint8, peerAddr [4]byte, bgpUpdate []byte, tableName string) []byte {
	pph := buildPerPeerHeader(peerType, peerFlags, peerAddr)

	var tlvData []byte
	if tableName != "" {
		tlvData = make([]byte, 4+len(tableName))
		binary.BigEndian.PutUint16(tlvData[0:2], 0) // TLV type = TableName
		binary.BigEndian.PutUint16(tlvData[2:4], uint16(len(tableName)))
		copy(tlvData[4:], tableName)
	}

	msgLen := bmp.CommonHeaderSize + len(pph) + len(bgpUpdate) + len(tlvData)
	msg := make([]byte, msgLen)

	// Common header: version(1) + msg_length(4) + msg_type(1)
	msg[0] = 3 // BMP version
	binary.BigEndian.PutUint32(msg[1:5], uint32(msgLen))
	msg[5] = bmp.MsgTypeRouteMonitoring

	offset := bmp.CommonHeaderSize
	copy(msg[offset:], pph)
	offset += len(pph)
	copy(msg[offset:], bgpUpdate)
	offset += len(bgpUpdate)
	if len(tlvData) > 0 {
		copy(msg[offset:], tlvData)
	}

	return msg
}

// buildBMPPeerDown builds a BMP Peer Down message.
func buildBMPPeerDown(peerType uint8, peerAddr [4]byte) []byte {
	pph := buildPerPeerHeader(peerType, 0, peerAddr)

	// Peer Down has: common header + per-peer header + reason(1) + optional data.
	// We include just the reason byte.
	msgLen := bmp.CommonHeaderSize + len(pph) + 1
	msg := make([]byte, msgLen)
	msg[0] = 3
	binary.BigEndian.PutUint32(msg[1:5], uint32(msgLen))
	msg[5] = bmp.MsgTypePeerDown

	offset := bmp.CommonHeaderSize
	copy(msg[offset:], pph)
	offset += len(pph)
	msg[offset] = 1 // reason = Local system closed the session

	return msg
}

// wrapOpenBMP wraps a BMP message in an OpenBMP v2 frame.
func wrapOpenBMP(bmpMsg []byte) []byte {
	frame := make([]byte, bmp.OpenBMPHeaderSize+len(bmpMsg))
	binary.BigEndian.PutUint16(frame[0:2], 2)                    // version = 2
	binary.BigEndian.PutUint32(frame[2:6], 0)                    // collector_hash
	binary.BigEndian.PutUint32(frame[6:10], uint32(len(bmpMsg))) // msg_len
	copy(frame[bmp.OpenBMPHeaderSize:], bmpMsg)
	return frame
}

func newTestPipeline(rawMode bool) *Pipeline {
	return NewPipeline(nil, 1000, 200, rawMode, 16*1024*1024, zap.NewNop(), nil)
}

// --- T008: Raw mode route processing tests ---

func TestProcessRawRecord_IPv4Announcement(t *testing.T) {
	p := newTestPipeline(true)

	nlri := []byte{24, 10, 0, 0} // 10.0.0.0/24
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})

	asPathData := []byte{
		bgp.ASPathSegmentSequence, 2,
		0, 0, 0xFD, 0xE9, // AS65001
		0, 0, 0xFD, 0xEA, // AS65002
	}
	asPathAttr := buildPathAttr(0x40, bgp.AttrTypeASPath, asPathData)
	pathAttrs := append(originAttr, asPathAttr...)
	pathAttrs = append(pathAttrs, nexthopAttr...)

	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "locrib")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	if action != actionRoute {
		t.Fatalf("expected actionRoute, got %d", action)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}

	r := routes[0]
	if r.Prefix != "10.0.0.0/24" {
		t.Errorf("expected prefix '10.0.0.0/24', got '%s'", r.Prefix)
	}
	if r.AFI != 4 {
		t.Errorf("expected AFI 4, got %d", r.AFI)
	}
	if r.Action != "A" {
		t.Errorf("expected action 'A', got '%s'", r.Action)
	}
	if r.Nexthop != "192.168.1.1" {
		t.Errorf("expected nexthop '192.168.1.1', got '%s'", r.Nexthop)
	}
	if r.ASPath != "65001 65002" {
		t.Errorf("expected as_path '65001 65002', got '%s'", r.ASPath)
	}
	if r.Origin != "IGP" {
		t.Errorf("expected origin 'IGP', got '%s'", r.Origin)
	}
	if r.RouterID != "10.0.0.1" {
		t.Errorf("expected router_id '10.0.0.1', got '%s'", r.RouterID)
	}
	if r.TableName != "locrib" {
		t.Errorf("expected table_name 'locrib', got '%s'", r.TableName)
	}
	if !r.IsLocRIB {
		t.Error("expected IsLocRIB=true")
	}
}

func TestProcessRawRecord_IPv4Withdrawal(t *testing.T) {
	p := newTestPipeline(true)

	withdrawn := []byte{24, 10, 0, 0} // 10.0.0.0/24
	bgpUpdate := buildBGPUpdate(withdrawn, nil, nil)
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "locrib")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	if action != actionRoute {
		t.Fatalf("expected actionRoute, got %d", action)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Action != "D" {
		t.Errorf("expected action 'D', got '%s'", routes[0].Action)
	}
	if routes[0].Prefix != "10.0.0.0/24" {
		t.Errorf("expected prefix '10.0.0.0/24', got '%s'", routes[0].Prefix)
	}
}

func TestProcessRawRecord_IPv6Announcement(t *testing.T) {
	p := newTestPipeline(true)

	nh := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	mpReach := make([]byte, 0, 64)
	mpReach = append(mpReach, 0, 2) // AFI=2 (IPv6)
	mpReach = append(mpReach, 1)    // SAFI=1
	mpReach = append(mpReach, 16)   // NH len
	mpReach = append(mpReach, nh...)
	mpReach = append(mpReach, 0)                       // SNPA count
	mpReach = append(mpReach, 32)                       // prefix len = /32
	mpReach = append(mpReach, 0x20, 0x01, 0x0d, 0xb8) // prefix bytes

	mpReachAttr := buildPathAttr(0x80, bgp.AttrTypeMPReachNLRI, mpReach)
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	pathAttrs := append(originAttr, mpReachAttr...)

	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nil)
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "locrib")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	if action != actionRoute {
		t.Fatalf("expected actionRoute, got %d", action)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].AFI != 6 {
		t.Errorf("expected AFI 6, got %d", routes[0].AFI)
	}
	if routes[0].Prefix != "2001:db8::/32" {
		t.Errorf("expected prefix '2001:db8::/32', got '%s'", routes[0].Prefix)
	}
	if routes[0].Nexthop != "2001:db8::1" {
		t.Errorf("expected nexthop '2001:db8::1', got '%s'", routes[0].Nexthop)
	}
}

func TestProcessRawRecord_MultiPrefix(t *testing.T) {
	p := newTestPipeline(true)

	// 2 announcements + 1 withdrawal in a single UPDATE.
	withdrawn := []byte{16, 172, 16} // 172.16.0.0/16 withdrawal
	nlri := []byte{
		24, 10, 0, 0, // 10.0.0.0/24
		24, 10, 0, 1, // 10.0.1.0/24
	}

	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)

	bgpUpdate := buildBGPUpdate(withdrawn, pathAttrs, nlri)
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "locrib")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	if action != actionRoute {
		t.Fatalf("expected actionRoute, got %d", action)
	}
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}

	// First should be the withdrawal.
	if routes[0].Action != "D" {
		t.Errorf("expected first route action 'D', got '%s'", routes[0].Action)
	}
	if routes[0].Prefix != "172.16.0.0/16" {
		t.Errorf("expected prefix '172.16.0.0/16', got '%s'", routes[0].Prefix)
	}

	// Second and third should be announcements.
	if routes[1].Action != "A" || routes[1].Prefix != "10.0.0.0/24" {
		t.Errorf("expected second route: A 10.0.0.0/24, got %s %s", routes[1].Action, routes[1].Prefix)
	}
	if routes[2].Action != "A" || routes[2].Prefix != "10.0.1.0/24" {
		t.Errorf("expected third route: A 10.0.1.0/24, got %s %s", routes[2].Action, routes[2].Prefix)
	}
}

func TestProcessRawRecord_BackwardCompatibility(t *testing.T) {
	// Verify NewPipeline with rawMode=false still works for JSON processing.
	p := newTestPipeline(false)

	if p.rawMode {
		t.Error("expected rawMode=false for JSON pipeline")
	}
	// The Pipeline struct should not dispatch to processRawRecord.
	// We verify by checking processRecord with a non-raw (JSON) record
	// that would fail OpenBMP decoding if dispatched to raw mode.
	// Since JSON mode expects valid JSON and this isn't, it should
	// return nil (parse error), not panic.
	rec := &kgo.Record{
		Value: []byte(`{"router_hash":"r1","action":"add","prefix":"1.2.3.0/24","is_loc_rib":true}`),
		Topic: "gobmp.parsed.unicast_prefix_v4",
	}
	routes, action := p.processRecord(context.Background(), rec)
	if action != actionRoute {
		t.Fatalf("expected actionRoute, got %d", action)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route from JSON mode, got %d", len(routes))
	}
	if routes[0].Prefix != "1.2.3.0/24" {
		t.Errorf("expected prefix '1.2.3.0/24', got '%s'", routes[0].Prefix)
	}
}

// --- T009: EOR detection tests ---

func TestProcessRawRecord_IPv4EOR(t *testing.T) {
	p := newTestPipeline(true)

	// Empty BGP UPDATE = IPv4 EOR.
	bgpUpdate := buildBGPUpdate(nil, nil, nil)
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "locrib")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	if action != actionEOR {
		t.Fatalf("expected actionEOR, got %d", action)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if !routes[0].IsEOR {
		t.Error("expected IsEOR=true")
	}
	if routes[0].AFI != 4 {
		t.Errorf("expected AFI 4, got %d", routes[0].AFI)
	}
	if routes[0].RouterID != "10.0.0.1" {
		t.Errorf("expected router_id '10.0.0.1', got '%s'", routes[0].RouterID)
	}
	if routes[0].TableName != "locrib" {
		t.Errorf("expected table_name 'locrib', got '%s'", routes[0].TableName)
	}
}

func TestProcessRawRecord_IPv6EOR(t *testing.T) {
	p := newTestPipeline(true)

	// IPv6 EOR: MP_UNREACH_NLRI with AFI=2, SAFI=1, no prefixes.
	mpUnreach := []byte{0, 2, 1} // AFI=2, SAFI=1
	mpUnreachAttr := buildPathAttr(0x80, bgp.AttrTypeMPUnreachNLRI, mpUnreach)
	bgpUpdate := buildBGPUpdate(nil, mpUnreachAttr, nil)
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "locrib")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	if action != actionEOR {
		t.Fatalf("expected actionEOR, got %d", action)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if !routes[0].IsEOR {
		t.Error("expected IsEOR=true")
	}
	if routes[0].AFI != 6 {
		t.Errorf("expected AFI 6, got %d", routes[0].AFI)
	}
}

func TestProcessRawRecord_WithdrawalIsNotEOR(t *testing.T) {
	p := newTestPipeline(true)

	// UPDATE with withdrawn routes is NOT EOR — it has actual withdrawal events.
	withdrawn := []byte{24, 10, 0, 0} // 10.0.0.0/24
	bgpUpdate := buildBGPUpdate(withdrawn, nil, nil)
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "locrib")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	if action != actionRoute {
		t.Fatalf("expected actionRoute (not EOR), got %d", action)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Action != "D" {
		t.Errorf("expected withdrawal action 'D', got '%s'", routes[0].Action)
	}
}

// --- T010: Peer-down handling tests ---

func TestProcessRawRecord_LocRIBPeerDown(t *testing.T) {
	p := newTestPipeline(true)

	bmpMsg := buildBMPPeerDown(bmp.PeerTypeLocRIB, [4]byte{10, 0, 0, 1})
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	if action != actionPeerDown {
		t.Fatalf("expected actionPeerDown, got %d", action)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].RouterID != "10.0.0.1" {
		t.Errorf("expected router_id '10.0.0.1', got '%s'", routes[0].RouterID)
	}
}

func TestProcessRawRecord_NonLocRIBPeerDown(t *testing.T) {
	p := newTestPipeline(true)

	bmpMsg := buildBMPPeerDown(bmp.PeerTypeGlobal, [4]byte{10, 0, 0, 1})
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	if action != actionRoute {
		t.Fatalf("expected actionRoute (skipped), got %d", action)
	}
	if routes != nil {
		t.Errorf("expected nil routes for non-Loc-RIB peer down, got %d", len(routes))
	}
}

func TestProcessRawRecord_PeerDownIPv4Mapped(t *testing.T) {
	p := newTestPipeline(true)

	// Peer with IPv4 address 10.0.0.1 in IPv4-mapped form.
	bmpMsg := buildBMPPeerDown(bmp.PeerTypeLocRIB, [4]byte{10, 0, 0, 1})
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	if action != actionPeerDown {
		t.Fatalf("expected actionPeerDown, got %d", action)
	}
	if routes[0].RouterID != "10.0.0.1" {
		t.Errorf("expected router_id '10.0.0.1', got '%s'", routes[0].RouterID)
	}
}

func TestProcessRawRecord_NonUpdateNotEOR(t *testing.T) {
	// A BGP KEEPALIVE (type 4) wrapped in Route Monitoring must NOT be
	// misclassified as an EOR marker.
	p := newTestPipeline(true)

	// Build a minimal BGP KEEPALIVE: 16-byte marker + 2-byte length + 1-byte type.
	keepalive := make([]byte, 19)
	for i := 0; i < 16; i++ {
		keepalive[i] = 0xFF
	}
	binary.BigEndian.PutUint16(keepalive[16:18], 19)
	keepalive[18] = 4 // type = KEEPALIVE

	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, keepalive, "locrib")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	if action != actionRoute {
		t.Fatalf("expected actionRoute (skip), got %d — non-UPDATE was misclassified as EOR", action)
	}
	if routes != nil {
		t.Errorf("expected nil routes for KEEPALIVE, got %d", len(routes))
	}
}

// --- T011: Filtering and edge case tests ---

func TestProcessRawRecord_GlobalPeerFiltered(t *testing.T) {
	p := newTestPipeline(true)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeGlobal, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "global")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, _ := p.processRawRecord(context.Background(), rec)
	if routes != nil {
		t.Errorf("expected nil routes for Global peer, got %d", len(routes))
	}
}

func TestProcessRawRecord_RDPeerFiltered(t *testing.T) {
	p := newTestPipeline(true)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeRD, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "rd")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, _ := p.processRawRecord(context.Background(), rec)
	if routes != nil {
		t.Errorf("expected nil routes for RD peer, got %d", len(routes))
	}
}

func TestProcessRawRecord_LocalPeerFiltered(t *testing.T) {
	p := newTestPipeline(true)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocal, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "local")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, _ := p.processRawRecord(context.Background(), rec)
	if routes != nil {
		t.Errorf("expected nil routes for Local peer, got %d", len(routes))
	}
}

func TestProcessRawRecord_BMPInitiationFiltered(t *testing.T) {
	p := newTestPipeline(true)

	// Build a BMP Initiation message (type 4).
	msgLen := bmp.CommonHeaderSize + 4
	bmpMsg := make([]byte, msgLen)
	bmpMsg[0] = 3
	binary.BigEndian.PutUint32(bmpMsg[1:5], uint32(msgLen))
	bmpMsg[5] = bmp.MsgTypeInitiation
	// Initiation TLV data (minimal).
	binary.BigEndian.PutUint16(bmpMsg[6:8], 0) // TLV type
	binary.BigEndian.PutUint16(bmpMsg[8:10], 0) // TLV len

	frame := wrapOpenBMP(bmpMsg)
	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, _ := p.processRawRecord(context.Background(), rec)
	if routes != nil {
		t.Errorf("expected nil routes for BMP Initiation, got %d", len(routes))
	}
}

func TestProcessRawRecord_BMPStatisticsFiltered(t *testing.T) {
	p := newTestPipeline(true)

	// Build a BMP Statistics Report message (type 1).
	// Need per-peer header (42 bytes) + stats count (4 bytes).
	pph := buildPerPeerHeader(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1})
	msgLen := bmp.CommonHeaderSize + len(pph) + 4
	bmpMsg := make([]byte, msgLen)
	bmpMsg[0] = 3
	binary.BigEndian.PutUint32(bmpMsg[1:5], uint32(msgLen))
	bmpMsg[5] = bmp.MsgTypeStatisticsReport
	copy(bmpMsg[bmp.CommonHeaderSize:], pph)
	// Stats count = 0.

	frame := wrapOpenBMP(bmpMsg)
	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, _ := p.processRawRecord(context.Background(), rec)
	if routes != nil {
		t.Errorf("expected nil routes for BMP Statistics, got %d", len(routes))
	}
}

func TestProcessRawRecord_BMPTerminationFiltered(t *testing.T) {
	p := newTestPipeline(true)

	msgLen := bmp.CommonHeaderSize
	bmpMsg := make([]byte, msgLen)
	bmpMsg[0] = 3
	binary.BigEndian.PutUint32(bmpMsg[1:5], uint32(msgLen))
	bmpMsg[5] = bmp.MsgTypeTermination

	frame := wrapOpenBMP(bmpMsg)
	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, _ := p.processRawRecord(context.Background(), rec)
	if routes != nil {
		t.Errorf("expected nil routes for BMP Termination, got %d", len(routes))
	}
}

func TestProcessRawRecord_MalformedOpenBMP(t *testing.T) {
	p := newTestPipeline(true)

	// Truncated OpenBMP header (only 5 bytes, need 10).
	rec := &kgo.Record{Value: []byte{0, 2, 0, 0, 0}, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)
	if routes != nil {
		t.Errorf("expected nil routes for malformed OpenBMP, got %d", len(routes))
	}
	if action != actionRoute {
		t.Errorf("expected actionRoute, got %d", action)
	}
}

func TestProcessRawRecord_MalformedBMP(t *testing.T) {
	p := newTestPipeline(true)

	// Valid OpenBMP frame but bad BMP version (99 instead of 3).
	badBMP := make([]byte, bmp.CommonHeaderSize)
	badBMP[0] = 99 // bad version
	binary.BigEndian.PutUint32(badBMP[1:5], uint32(bmp.CommonHeaderSize))
	badBMP[5] = 0

	frame := wrapOpenBMP(badBMP)
	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)
	if routes != nil {
		t.Errorf("expected nil routes for malformed BMP, got %d", len(routes))
	}
	if action != actionRoute {
		t.Errorf("expected actionRoute, got %d", action)
	}
}

func TestProcessRawRecord_OversizedPayload(t *testing.T) {
	p := NewPipeline(nil, 1000, 200, true, 100, zap.NewNop(), nil) // maxPayloadBytes=100

	// Build a BMP message larger than 100 bytes.
	bigBGP := make([]byte, 200)
	for i := 0; i < 16; i++ {
		bigBGP[i] = 0xFF
	}
	binary.BigEndian.PutUint16(bigBGP[16:18], 200)
	bigBGP[18] = 2

	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bigBGP, "locrib")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)
	if routes != nil {
		t.Errorf("expected nil routes for oversized payload, got %d", len(routes))
	}
	if action != actionRoute {
		t.Errorf("expected actionRoute, got %d", action)
	}
}

// --- Stream 3: PeerUp tests ---

func buildBMPPeerUp(peerType uint8, peerAddr [4]byte, tableName string) []byte {
	pph := buildPerPeerHeader(peerType, 0, peerAddr)

	var tlvData []byte
	if tableName != "" {
		tlvData = make([]byte, 4+len(tableName))
		binary.BigEndian.PutUint16(tlvData[0:2], 0) // TLV type = TableName
		binary.BigEndian.PutUint16(tlvData[2:4], uint16(len(tableName)))
		copy(tlvData[4:], tableName)
	}

	// RFC 9069 §4.4: For Loc-RIB Peer Up, Sent Open and Received Open
	// are empty (zero-length), so TLVs follow immediately after per-peer header.
	msgLen := bmp.CommonHeaderSize + len(pph) + len(tlvData)
	msg := make([]byte, msgLen)
	msg[0] = 3 // BMP version
	binary.BigEndian.PutUint32(msg[1:5], uint32(msgLen))
	msg[5] = bmp.MsgTypePeerUp

	offset := bmp.CommonHeaderSize
	copy(msg[offset:], pph)
	offset += len(pph)
	if len(tlvData) > 0 {
		copy(msg[offset:], tlvData)
	}

	return msg
}

func TestProcessRawRecord_PeerUp_NonLocRIB(t *testing.T) {
	p := newTestPipeline(true)

	bmpMsg := buildBMPPeerUp(bmp.PeerTypeGlobal, [4]byte{10, 0, 0, 1}, "")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	// Non-Loc-RIB PeerUp should be filtered (IsLocRIB=false).
	if routes != nil {
		t.Errorf("expected nil routes for non-Loc-RIB PeerUp, got %d", len(routes))
	}
	if action != actionRoute {
		t.Errorf("expected actionRoute, got %d", action)
	}
}

// --- Stream 3: Mixed routes and EOR in same raw record ---

func TestProcessRawRecord_MixedRoutesAndEOR(t *testing.T) {
	p := newTestPipeline(true)

	// Build first BMP msg: route announcement
	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate1 := buildBGPUpdate(nil, pathAttrs, nlri)
	bmpMsg1 := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate1, "locrib")

	// Build second BMP msg: empty UPDATE = IPv4 EOR
	bgpUpdate2 := buildBGPUpdate(nil, nil, nil)
	bmpMsg2 := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate2, "locrib")

	// Concatenate both BMP messages into a single raw payload
	combined := append(bmpMsg1, bmpMsg2...)
	frame := wrapOpenBMP(combined)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	routes, action := p.processRawRecord(context.Background(), rec)

	if action != actionEOR {
		t.Fatalf("expected actionEOR, got %d", action)
	}
	// Should have the announcement route AND the EOR marker
	if len(routes) < 2 {
		t.Fatalf("expected at least 2 routes (announcement + EOR), got %d", len(routes))
	}

	hasEOR := false
	hasRoute := false
	for _, r := range routes {
		if r.IsEOR {
			hasEOR = true
		}
		if r.Prefix == "10.0.0.0/24" {
			hasRoute = true
		}
	}
	if !hasEOR {
		t.Error("expected at least one EOR route")
	}
	if !hasRoute {
		t.Error("expected at least one regular route")
	}
}
