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
// peerAddr: 4-byte IPv4 address (12 zero bytes + 4 IPv4, per BMP spec).
func buildPerPeerHeader(peerType uint8, peerFlags uint8, peerAddr [4]byte, peerAS uint32, peerBGPID [4]byte) []byte {
	hdr := make([]byte, 42)
	hdr[0] = peerType
	hdr[1] = peerFlags
	// Distinguisher: 8 bytes at offset 2 (zero)
	// Peer address: 16 bytes at offset 10 (12 zero bytes + 4 IPv4 bytes)
	copy(hdr[22:26], peerAddr[:])
	// Peer AS: 4 bytes at offset 26
	binary.BigEndian.PutUint32(hdr[26:30], peerAS)
	// Peer BGP ID: 4 bytes at offset 30
	copy(hdr[30:34], peerBGPID[:])
	// Timestamps at offset 34-41 (zero)
	return hdr
}

// buildBMPRouteMonitoring builds a BMP Route Monitoring message wrapping a BGP UPDATE.
func buildBMPRouteMonitoring(peerType uint8, peerFlags uint8, peerAddr [4]byte, bgpUpdate []byte, tableName string) []byte {
	pph := buildPerPeerHeader(peerType, peerFlags, peerAddr, 0, [4]byte{})

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
func buildBMPPeerDown(peerType uint8, peerAddr [4]byte, peerAS uint32, peerBGPID [4]byte) []byte {
	pph := buildPerPeerHeader(peerType, 0, peerAddr, peerAS, peerBGPID)

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

// wrapOpenBMPV17 wraps a BMP message in an OpenBMP v1.7 frame with a router IP.
func wrapOpenBMPV17(bmpMsg []byte, routerIP [4]byte) []byte {
	hdrLen := uint16(78)
	frame := make([]byte, int(hdrLen)+len(bmpMsg))
	binary.BigEndian.PutUint32(frame[0:4], 0x4F424D50) // "OBMP" magic
	frame[4] = 1                                        // major version
	frame[5] = 7                                        // minor version
	binary.BigEndian.PutUint16(frame[6:8], hdrLen)
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(bmpMsg)))
	frame[12] = 0x80 // flags
	frame[13] = 12   // message type: BMP_RAW
	binary.BigEndian.PutUint16(frame[38:40], 0) // admin ID len = 0
	// Router IP at offset 56 (first 4 bytes for IPv4)
	copy(frame[56:60], routerIP[:])
	binary.BigEndian.PutUint16(frame[72:74], 0) // router group len
	binary.BigEndian.PutUint32(frame[74:78], 1) // row count
	copy(frame[hdrLen:], bmpMsg)
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
	result := p.processRawRecord(context.Background(), rec)

	if result.locAction != actionRoute {
		t.Fatalf("expected actionRoute, got %d", result.locAction)
	}
	if len(result.locRoutes) != 1 {
		t.Fatalf("expected 1 loc route, got %d", len(result.locRoutes))
	}

	r := result.locRoutes[0]
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
	result := p.processRawRecord(context.Background(), rec)

	if result.locAction != actionRoute {
		t.Fatalf("expected actionRoute, got %d", result.locAction)
	}
	if len(result.locRoutes) != 1 {
		t.Fatalf("expected 1 loc route, got %d", len(result.locRoutes))
	}
	if result.locRoutes[0].Action != "D" {
		t.Errorf("expected action 'D', got '%s'", result.locRoutes[0].Action)
	}
	if result.locRoutes[0].Prefix != "10.0.0.0/24" {
		t.Errorf("expected prefix '10.0.0.0/24', got '%s'", result.locRoutes[0].Prefix)
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
	result := p.processRawRecord(context.Background(), rec)

	if result.locAction != actionRoute {
		t.Fatalf("expected actionRoute, got %d", result.locAction)
	}
	if len(result.locRoutes) != 1 {
		t.Fatalf("expected 1 loc route, got %d", len(result.locRoutes))
	}
	if result.locRoutes[0].AFI != 6 {
		t.Errorf("expected AFI 6, got %d", result.locRoutes[0].AFI)
	}
	if result.locRoutes[0].Prefix != "2001:db8::/32" {
		t.Errorf("expected prefix '2001:db8::/32', got '%s'", result.locRoutes[0].Prefix)
	}
	if result.locRoutes[0].Nexthop != "2001:db8::1" {
		t.Errorf("expected nexthop '2001:db8::1', got '%s'", result.locRoutes[0].Nexthop)
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
	result := p.processRawRecord(context.Background(), rec)

	if result.locAction != actionRoute {
		t.Fatalf("expected actionRoute, got %d", result.locAction)
	}
	if len(result.locRoutes) != 3 {
		t.Fatalf("expected 3 loc routes, got %d", len(result.locRoutes))
	}

	// First should be the withdrawal.
	if result.locRoutes[0].Action != "D" {
		t.Errorf("expected first route action 'D', got '%s'", result.locRoutes[0].Action)
	}
	if result.locRoutes[0].Prefix != "172.16.0.0/16" {
		t.Errorf("expected prefix '172.16.0.0/16', got '%s'", result.locRoutes[0].Prefix)
	}

	// Second and third should be announcements.
	if result.locRoutes[1].Action != "A" || result.locRoutes[1].Prefix != "10.0.0.0/24" {
		t.Errorf("expected second route: A 10.0.0.0/24, got %s %s", result.locRoutes[1].Action, result.locRoutes[1].Prefix)
	}
	if result.locRoutes[2].Action != "A" || result.locRoutes[2].Prefix != "10.0.1.0/24" {
		t.Errorf("expected third route: A 10.0.1.0/24, got %s %s", result.locRoutes[2].Action, result.locRoutes[2].Prefix)
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
	// return empty result (parse error), not panic.
	rec := &kgo.Record{
		Value: []byte(`{"router_hash":"r1","action":"add","prefix":"1.2.3.0/24","is_loc_rib":true}`),
		Topic: "gobmp.parsed.unicast_prefix_v4",
	}
	result := p.processRecord(context.Background(), rec)
	if result.locAction != actionRoute {
		t.Fatalf("expected actionRoute, got %d", result.locAction)
	}
	if len(result.locRoutes) != 1 {
		t.Fatalf("expected 1 route from JSON mode, got %d", len(result.locRoutes))
	}
	if result.locRoutes[0].Prefix != "1.2.3.0/24" {
		t.Errorf("expected prefix '1.2.3.0/24', got '%s'", result.locRoutes[0].Prefix)
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
	result := p.processRawRecord(context.Background(), rec)

	if result.locAction != actionEOR {
		t.Fatalf("expected actionEOR, got %d", result.locAction)
	}
	if len(result.locRoutes) != 1 {
		t.Fatalf("expected 1 loc route, got %d", len(result.locRoutes))
	}
	if !result.locRoutes[0].IsEOR {
		t.Error("expected IsEOR=true")
	}
	if result.locRoutes[0].AFI != 4 {
		t.Errorf("expected AFI 4, got %d", result.locRoutes[0].AFI)
	}
	if result.locRoutes[0].RouterID != "10.0.0.1" {
		t.Errorf("expected router_id '10.0.0.1', got '%s'", result.locRoutes[0].RouterID)
	}
	if result.locRoutes[0].TableName != "locrib" {
		t.Errorf("expected table_name 'locrib', got '%s'", result.locRoutes[0].TableName)
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
	result := p.processRawRecord(context.Background(), rec)

	if result.locAction != actionEOR {
		t.Fatalf("expected actionEOR, got %d", result.locAction)
	}
	if len(result.locRoutes) != 1 {
		t.Fatalf("expected 1 loc route, got %d", len(result.locRoutes))
	}
	if !result.locRoutes[0].IsEOR {
		t.Error("expected IsEOR=true")
	}
	if result.locRoutes[0].AFI != 6 {
		t.Errorf("expected AFI 6, got %d", result.locRoutes[0].AFI)
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
	result := p.processRawRecord(context.Background(), rec)

	if result.locAction != actionRoute {
		t.Fatalf("expected actionRoute (not EOR), got %d", result.locAction)
	}
	if len(result.locRoutes) != 1 {
		t.Fatalf("expected 1 loc route, got %d", len(result.locRoutes))
	}
	if result.locRoutes[0].Action != "D" {
		t.Errorf("expected withdrawal action 'D', got '%s'", result.locRoutes[0].Action)
	}
}

// --- T010: Peer-down handling tests ---

func TestProcessRawRecord_LocRIBPeerDown(t *testing.T) {
	p := newTestPipeline(true)

	bmpMsg := buildBMPPeerDown(bmp.PeerTypeLocRIB, [4]byte{10, 0, 0, 1}, 0, [4]byte{})
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.locAction != actionPeerDown {
		t.Fatalf("expected actionPeerDown, got %d", result.locAction)
	}
	if len(result.locRoutes) != 1 {
		t.Fatalf("expected 1 loc route, got %d", len(result.locRoutes))
	}
	if result.locRoutes[0].RouterID != "10.0.0.1" {
		t.Errorf("expected router_id '10.0.0.1', got '%s'", result.locRoutes[0].RouterID)
	}
}

func TestProcessRawRecord_NonLocRIBPeerDown(t *testing.T) {
	p := newTestPipeline(true)

	bmpMsg := buildBMPPeerDown(bmp.PeerTypeGlobal, [4]byte{10, 0, 0, 1}, 65001, [4]byte{10, 0, 0, 1})
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.adjAction != actionAdjRibInPeerDown {
		t.Fatalf("expected actionAdjRibInPeerDown, got %d", result.adjAction)
	}
	if len(result.adjRoutes) != 1 {
		t.Fatalf("expected 1 adj route for non-Loc-RIB peer down, got %d", len(result.adjRoutes))
	}
	if result.adjRoutes[0].RouterID != "10.0.0.2" {
		t.Errorf("expected RouterID '10.0.0.2' (from OBMP), got '%s'", result.adjRoutes[0].RouterID)
	}
	if result.adjRoutes[0].PeerAddress != "10.0.0.1" {
		t.Errorf("expected PeerAddress '10.0.0.1', got '%s'", result.adjRoutes[0].PeerAddress)
	}
	if result.adjRoutes[0].PeerAS != 65001 {
		t.Errorf("expected PeerAS 65001, got %d", result.adjRoutes[0].PeerAS)
	}
	if result.adjRoutes[0].PeerBGPID != "10.0.0.1" {
		t.Errorf("expected PeerBGPID '10.0.0.1', got '%s'", result.adjRoutes[0].PeerBGPID)
	}
}

func TestProcessRawRecord_PeerDownIPv4Mapped(t *testing.T) {
	p := newTestPipeline(true)

	// Peer with IPv4 address 10.0.0.1.
	bmpMsg := buildBMPPeerDown(bmp.PeerTypeLocRIB, [4]byte{10, 0, 0, 1}, 0, [4]byte{})
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.locAction != actionPeerDown {
		t.Fatalf("expected actionPeerDown, got %d", result.locAction)
	}
	if result.locRoutes[0].RouterID != "10.0.0.1" {
		t.Errorf("expected router_id '10.0.0.1', got '%s'", result.locRoutes[0].RouterID)
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
	result := p.processRawRecord(context.Background(), rec)

	// Non-UPDATE should produce empty result (no routes, no action).
	if len(result.locRoutes) != 0 {
		t.Errorf("expected 0 loc routes for KEEPALIVE, got %d", len(result.locRoutes))
	}
	if len(result.adjRoutes) != 0 {
		t.Errorf("expected 0 adj routes for KEEPALIVE, got %d", len(result.adjRoutes))
	}
}

// --- T011: Filtering and edge case tests ---

func TestProcessRawRecord_GlobalPeerAdjRibIn(t *testing.T) {
	p := newTestPipeline(true)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	// Non-Loc-RIB Route Monitoring has no TLVs (RFC 7854), so pass empty table name.
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeGlobal, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "")
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.adjAction != actionAdjRibInRoute {
		t.Fatalf("expected actionAdjRibInRoute, got %d", result.adjAction)
	}
	if len(result.adjRoutes) != 1 {
		t.Fatalf("expected 1 adj route for Global peer Adj-RIB-In, got %d", len(result.adjRoutes))
	}
	if result.adjRoutes[0].RouterID != "10.0.0.2" {
		t.Errorf("expected RouterID '10.0.0.2' (from OBMP), got '%s'", result.adjRoutes[0].RouterID)
	}
	if result.adjRoutes[0].PeerAddress != "10.0.0.1" {
		t.Errorf("expected PeerAddress '10.0.0.1', got '%s'", result.adjRoutes[0].PeerAddress)
	}
	if result.adjRoutes[0].Prefix != "10.0.0.0/24" {
		t.Errorf("expected prefix '10.0.0.0/24', got '%s'", result.adjRoutes[0].Prefix)
	}
	if result.adjRoutes[0].IsPostPolicy {
		t.Error("expected IsPostPolicy=false for pre-policy peer")
	}
}

func TestProcessRawRecord_RDPeerAdjRibIn(t *testing.T) {
	p := newTestPipeline(true)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeRD, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "")
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.adjAction != actionAdjRibInRoute {
		t.Fatalf("expected actionAdjRibInRoute, got %d", result.adjAction)
	}
	if len(result.adjRoutes) != 1 {
		t.Fatalf("expected 1 adj route for RD peer Adj-RIB-In, got %d", len(result.adjRoutes))
	}
	if result.adjRoutes[0].RouterID != "10.0.0.2" {
		t.Errorf("expected RouterID '10.0.0.2' (from OBMP), got '%s'", result.adjRoutes[0].RouterID)
	}
	if result.adjRoutes[0].PeerAddress != "10.0.0.1" {
		t.Errorf("expected PeerAddress '10.0.0.1', got '%s'", result.adjRoutes[0].PeerAddress)
	}
	if result.adjRoutes[0].Prefix != "10.0.0.0/24" {
		t.Errorf("expected prefix '10.0.0.0/24', got '%s'", result.adjRoutes[0].Prefix)
	}
}

func TestProcessRawRecord_LocalPeerAdjRibIn(t *testing.T) {
	p := newTestPipeline(true)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocal, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "")
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.adjAction != actionAdjRibInRoute {
		t.Fatalf("expected actionAdjRibInRoute, got %d", result.adjAction)
	}
	if len(result.adjRoutes) != 1 {
		t.Fatalf("expected 1 adj route for Local peer Adj-RIB-In, got %d", len(result.adjRoutes))
	}
	if result.adjRoutes[0].RouterID != "10.0.0.2" {
		t.Errorf("expected RouterID '10.0.0.2' (from OBMP), got '%s'", result.adjRoutes[0].RouterID)
	}
	if result.adjRoutes[0].PeerAddress != "10.0.0.1" {
		t.Errorf("expected PeerAddress '10.0.0.1', got '%s'", result.adjRoutes[0].PeerAddress)
	}
	if result.adjRoutes[0].Prefix != "10.0.0.0/24" {
		t.Errorf("expected prefix '10.0.0.0/24', got '%s'", result.adjRoutes[0].Prefix)
	}
}

func TestProcessRawRecord_AdjRibInAttrsPopulated(t *testing.T) {
	p := newTestPipeline(true)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	// Add a LocalPref attr (type 5) to verify attrs propagation (R3-M11).
	localPrefAttr := buildPathAttr(0x40, bgp.AttrTypeLocalPref, []byte{0, 0, 0, 100})
	pathAttrs := append(originAttr, nexthopAttr...)
	pathAttrs = append(pathAttrs, localPrefAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeGlobal, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "")
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.adjAction != actionAdjRibInRoute {
		t.Fatalf("expected actionAdjRibInRoute, got %d", result.adjAction)
	}
	if len(result.adjRoutes) != 1 {
		t.Fatalf("expected 1 adj route, got %d", len(result.adjRoutes))
	}
	if result.adjRoutes[0].RouterID != "10.0.0.2" {
		t.Errorf("expected RouterID '10.0.0.2' (from OBMP), got '%s'", result.adjRoutes[0].RouterID)
	}
	if result.adjRoutes[0].LocalPref == nil || *result.adjRoutes[0].LocalPref != 100 {
		t.Errorf("expected LocalPref 100, got %v", result.adjRoutes[0].LocalPref)
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
	result := p.processRawRecord(context.Background(), rec)
	if len(result.locRoutes) != 0 || len(result.adjRoutes) != 0 {
		t.Errorf("expected no routes for BMP Initiation, got loc=%d adj=%d", len(result.locRoutes), len(result.adjRoutes))
	}
}

func TestProcessRawRecord_BMPStatisticsFiltered(t *testing.T) {
	p := newTestPipeline(true)

	// Build a BMP Statistics Report message (type 1).
	// Need per-peer header (42 bytes) + stats count (4 bytes).
	pph := buildPerPeerHeader(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, 0, [4]byte{})
	msgLen := bmp.CommonHeaderSize + len(pph) + 4
	bmpMsg := make([]byte, msgLen)
	bmpMsg[0] = 3
	binary.BigEndian.PutUint32(bmpMsg[1:5], uint32(msgLen))
	bmpMsg[5] = bmp.MsgTypeStatisticsReport
	copy(bmpMsg[bmp.CommonHeaderSize:], pph)
	// Stats count = 0.

	frame := wrapOpenBMP(bmpMsg)
	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)
	if len(result.locRoutes) != 0 || len(result.adjRoutes) != 0 {
		t.Errorf("expected no routes for BMP Statistics, got loc=%d adj=%d", len(result.locRoutes), len(result.adjRoutes))
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
	result := p.processRawRecord(context.Background(), rec)
	if len(result.locRoutes) != 0 || len(result.adjRoutes) != 0 {
		t.Errorf("expected no routes for BMP Termination, got loc=%d adj=%d", len(result.locRoutes), len(result.adjRoutes))
	}
}

func TestProcessRawRecord_MalformedOpenBMP(t *testing.T) {
	p := newTestPipeline(true)

	// Truncated OpenBMP header (only 5 bytes, need 10).
	rec := &kgo.Record{Value: []byte{0, 2, 0, 0, 0}, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)
	if len(result.locRoutes) != 0 || len(result.adjRoutes) != 0 {
		t.Errorf("expected no routes for malformed OpenBMP, got loc=%d adj=%d", len(result.locRoutes), len(result.adjRoutes))
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
	result := p.processRawRecord(context.Background(), rec)
	if len(result.locRoutes) != 0 || len(result.adjRoutes) != 0 {
		t.Errorf("expected no routes for malformed BMP, got loc=%d adj=%d", len(result.locRoutes), len(result.adjRoutes))
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
	result := p.processRawRecord(context.Background(), rec)
	if len(result.locRoutes) != 0 || len(result.adjRoutes) != 0 {
		t.Errorf("expected no routes for oversized payload, got loc=%d adj=%d", len(result.locRoutes), len(result.adjRoutes))
	}
}

// --- Stream 3: PeerUp tests ---

func buildBMPPeerUp(peerType uint8, peerAddr [4]byte, tableName string) []byte {
	pph := buildPerPeerHeader(peerType, 0, peerAddr, 0, [4]byte{})

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
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	// Non-Loc-RIB PeerUp should produce no routes (calls writer directly).
	if len(result.locRoutes) != 0 || len(result.adjRoutes) != 0 {
		t.Errorf("expected no routes for non-Loc-RIB PeerUp, got loc=%d adj=%d", len(result.locRoutes), len(result.adjRoutes))
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
	result := p.processRawRecord(context.Background(), rec)

	if result.locAction != actionEOR {
		t.Fatalf("expected actionEOR, got %d", result.locAction)
	}
	// Should have the announcement route AND the EOR marker
	if len(result.locRoutes) < 2 {
		t.Fatalf("expected at least 2 loc routes (announcement + EOR), got %d", len(result.locRoutes))
	}

	hasEOR := false
	hasRoute := false
	for _, r := range result.locRoutes {
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

// --- Mixed Loc-RIB and Adj-RIB-In in same raw record (R3-H3) ---

func TestProcessRawRecord_MixedLocRIBAndAdjRibIn(t *testing.T) {
	p := newTestPipeline(true)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	// First BMP: Loc-RIB route
	bmpMsg1 := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "locrib")
	// Second BMP: Adj-RIB-In route (Global peer, different peer address)
	bmpMsg2 := buildBMPRouteMonitoring(bmp.PeerTypeGlobal, 0, [4]byte{10, 0, 0, 3}, bgpUpdate, "")

	combined := append(bmpMsg1, bmpMsg2...)
	frame := wrapOpenBMPV17(combined, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	// Should have both Loc-RIB and Adj-RIB-In routes.
	if len(result.locRoutes) == 0 {
		t.Fatal("expected at least 1 loc route")
	}
	if len(result.adjRoutes) == 0 {
		t.Fatal("expected at least 1 adj route")
	}
	if result.locAction != actionRoute {
		t.Errorf("expected locAction=actionRoute, got %d", result.locAction)
	}
	if result.adjAction != actionAdjRibInRoute {
		t.Errorf("expected adjAction=actionAdjRibInRoute, got %d", result.adjAction)
	}
	// Adj-RIB-In RouterID comes from OBMP header, not per-peer header.
	if result.adjRoutes[0].RouterID != "10.0.0.2" {
		t.Errorf("expected adj RouterID '10.0.0.2' (from OBMP), got '%s'", result.adjRoutes[0].RouterID)
	}
	if result.adjRoutes[0].PeerAddress != "10.0.0.3" {
		t.Errorf("expected adj PeerAddress '10.0.0.3', got '%s'", result.adjRoutes[0].PeerAddress)
	}
}

// --- Adj-RIB-In EOR test ---

func TestProcessRawRecord_AdjRibInEOR(t *testing.T) {
	p := newTestPipeline(true)

	// Empty BGP UPDATE = IPv4 EOR, from a Global peer.
	bgpUpdate := buildBGPUpdate(nil, nil, nil)
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeGlobal, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "")
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.adjAction != actionAdjRibInEOR {
		t.Fatalf("expected actionAdjRibInEOR, got %d", result.adjAction)
	}
	if len(result.adjRoutes) != 1 {
		t.Fatalf("expected 1 adj route, got %d", len(result.adjRoutes))
	}
	if !result.adjRoutes[0].IsEOR {
		t.Error("expected IsEOR=true for adj EOR")
	}
	if result.adjRoutes[0].AFI != 4 {
		t.Errorf("expected AFI 4, got %d", result.adjRoutes[0].AFI)
	}
	if result.adjRoutes[0].RouterID != "10.0.0.2" {
		t.Errorf("expected RouterID '10.0.0.2' (from OBMP), got '%s'", result.adjRoutes[0].RouterID)
	}
}

// --- Adj-RIB-In Post-Policy test ---

func TestProcessRawRecord_AdjRibInPostPolicy(t *testing.T) {
	p := newTestPipeline(true)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	// L-flag set (0x40) = post-policy.
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeGlobal, bmp.PeerFlagPostPolicy, [4]byte{10, 0, 0, 1}, bgpUpdate, "")
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.adjAction != actionAdjRibInRoute {
		t.Fatalf("expected actionAdjRibInRoute, got %d", result.adjAction)
	}
	if len(result.adjRoutes) != 1 {
		t.Fatalf("expected 1 adj route, got %d", len(result.adjRoutes))
	}
	if !result.adjRoutes[0].IsPostPolicy {
		t.Error("expected IsPostPolicy=true for L-flag=1 peer")
	}
	if result.adjRoutes[0].RouterID != "10.0.0.2" {
		t.Errorf("expected RouterID '10.0.0.2' (from OBMP), got '%s'", result.adjRoutes[0].RouterID)
	}
}

// --- Adj-RIB-In withdrawal test ---

func TestProcessRawRecord_AdjRibInWithdrawal(t *testing.T) {
	p := newTestPipeline(true)

	withdrawn := []byte{24, 10, 0, 0} // 10.0.0.0/24
	bgpUpdate := buildBGPUpdate(withdrawn, nil, nil)
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeGlobal, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "")
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.adjAction != actionAdjRibInRoute {
		t.Fatalf("expected actionAdjRibInRoute, got %d", result.adjAction)
	}
	if len(result.adjRoutes) != 1 {
		t.Fatalf("expected 1 adj route, got %d", len(result.adjRoutes))
	}
	if result.adjRoutes[0].RouterID != "10.0.0.2" {
		t.Errorf("expected RouterID '10.0.0.2' (from OBMP), got '%s'", result.adjRoutes[0].RouterID)
	}
	if result.adjRoutes[0].Action != "D" {
		t.Errorf("expected action 'D', got '%s'", result.adjRoutes[0].Action)
	}
	if result.adjRoutes[0].Prefix != "10.0.0.0/24" {
		t.Errorf("expected prefix '10.0.0.0/24', got '%s'", result.adjRoutes[0].Prefix)
	}
}

// --- Adj-RIB-In IPv6 route test (R3-M4) ---

func TestProcessRawRecord_AdjRibInIPv6(t *testing.T) {
	p := newTestPipeline(true)

	nh := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	mpReach := make([]byte, 0, 64)
	mpReach = append(mpReach, 0, 2) // AFI=2 (IPv6)
	mpReach = append(mpReach, 1)    // SAFI=1
	mpReach = append(mpReach, 16)   // NH len
	mpReach = append(mpReach, nh...)
	mpReach = append(mpReach, 0)                             // SNPA count
	mpReach = append(mpReach, 48)                             // prefix len = /48
	mpReach = append(mpReach, 0x20, 0x01, 0x0d, 0xb8, 0, 0) // prefix bytes

	mpReachAttr := buildPathAttr(0x80, bgp.AttrTypeMPReachNLRI, mpReach)
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	pathAttrs := append(originAttr, mpReachAttr...)

	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nil)
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeGlobal, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "")
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.adjAction != actionAdjRibInRoute {
		t.Fatalf("expected actionAdjRibInRoute, got %d", result.adjAction)
	}
	if len(result.adjRoutes) != 1 {
		t.Fatalf("expected 1 adj route, got %d", len(result.adjRoutes))
	}
	if result.adjRoutes[0].AFI != 6 {
		t.Errorf("expected AFI 6, got %d", result.adjRoutes[0].AFI)
	}
	if result.adjRoutes[0].Prefix != "2001:db8::/48" {
		t.Errorf("expected prefix '2001:db8::/48', got '%s'", result.adjRoutes[0].Prefix)
	}
	if result.adjRoutes[0].Nexthop != "2001:db8::1" {
		t.Errorf("expected nexthop '2001:db8::1', got '%s'", result.adjRoutes[0].Nexthop)
	}
	if result.adjRoutes[0].RouterID != "10.0.0.2" {
		t.Errorf("expected RouterID '10.0.0.2' (from OBMP), got '%s'", result.adjRoutes[0].RouterID)
	}
	if result.adjRoutes[0].PeerAddress != "10.0.0.1" {
		t.Errorf("expected PeerAddress '10.0.0.1', got '%s'", result.adjRoutes[0].PeerAddress)
	}
}

// --- Adj-RIB-In multi-prefix UPDATE test (R3-M9) ---

func TestProcessRawRecord_AdjRibInMultiPrefix(t *testing.T) {
	p := newTestPipeline(true)

	// 2 announcements + 1 withdrawal in a single UPDATE for an Adj-RIB-In peer.
	withdrawn := []byte{16, 172, 16} // 172.16.0.0/16 withdrawal
	nlri := []byte{
		24, 10, 0, 0, // 10.0.0.0/24
		24, 10, 0, 1, // 10.0.1.0/24
	}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)

	bgpUpdate := buildBGPUpdate(withdrawn, pathAttrs, nlri)
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeGlobal, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "")
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.adjAction != actionAdjRibInRoute {
		t.Fatalf("expected actionAdjRibInRoute, got %d", result.adjAction)
	}
	if len(result.adjRoutes) != 3 {
		t.Fatalf("expected 3 adj routes (1 withdrawal + 2 announcements), got %d", len(result.adjRoutes))
	}

	// First should be the withdrawal.
	if result.adjRoutes[0].Action != "D" || result.adjRoutes[0].Prefix != "172.16.0.0/16" {
		t.Errorf("expected first adj route: D 172.16.0.0/16, got %s %s", result.adjRoutes[0].Action, result.adjRoutes[0].Prefix)
	}
	// All routes should share the same RouterID and PeerAddress.
	for i, r := range result.adjRoutes {
		if r.RouterID != "10.0.0.2" {
			t.Errorf("route[%d]: expected RouterID '10.0.0.2', got '%s'", i, r.RouterID)
		}
		if r.PeerAddress != "10.0.0.1" {
			t.Errorf("route[%d]: expected PeerAddress '10.0.0.1', got '%s'", i, r.PeerAddress)
		}
	}
}

// --- Adj-RIB-In TableName normalization test (R3-M10) ---

func TestProcessRawRecord_AdjRibInTableNameNormalization(t *testing.T) {
	p := newTestPipeline(true)

	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	// Non-Loc-RIB with no TLVs gets TableName="UNKNOWN" from the parser,
	// which the pipeline normalizes to "".
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeGlobal, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "")
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if len(result.adjRoutes) != 1 {
		t.Fatalf("expected 1 adj route, got %d", len(result.adjRoutes))
	}
	if result.adjRoutes[0].TableName != "" {
		t.Errorf("expected TableName '' (normalized from UNKNOWN), got '%s'", result.adjRoutes[0].TableName)
	}
}

// --- Adj-RIB-In Add-Path test (R3-L6) ---

func TestProcessRawRecord_AdjRibInAddPath(t *testing.T) {
	p := newTestPipeline(true)

	// Build Add-Path NLRI: 4-byte path_id + prefix_len + prefix_bytes.
	// Path ID=1, 10.0.0.0/24; Path ID=2, 10.0.0.0/24 (same prefix, different path).
	nlri := []byte{
		0, 0, 0, 1, 24, 10, 0, 0, // path_id=1, 10.0.0.0/24
		0, 0, 0, 2, 24, 10, 0, 0, // path_id=2, 10.0.0.0/24
	}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	// F-bit set (0x80) = Add-Path capable.
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeGlobal, bmp.PeerFlagAddPath, [4]byte{10, 0, 0, 1}, bgpUpdate, "")
	frame := wrapOpenBMPV17(bmpMsg, [4]byte{10, 0, 0, 2})

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	result := p.processRawRecord(context.Background(), rec)

	if result.adjAction != actionAdjRibInRoute {
		t.Fatalf("expected actionAdjRibInRoute, got %d", result.adjAction)
	}
	if len(result.adjRoutes) != 2 {
		t.Fatalf("expected 2 adj routes (2 paths for same prefix), got %d", len(result.adjRoutes))
	}
	// Both should be for 10.0.0.0/24 but with different path IDs.
	for i, r := range result.adjRoutes {
		if r.Prefix != "10.0.0.0/24" {
			t.Errorf("route[%d]: expected prefix '10.0.0.0/24', got '%s'", i, r.Prefix)
		}
		if r.RouterID != "10.0.0.2" {
			t.Errorf("route[%d]: expected RouterID '10.0.0.2', got '%s'", i, r.RouterID)
		}
	}
	if result.adjRoutes[0].PathID != 1 {
		t.Errorf("expected first PathID=1, got %d", result.adjRoutes[0].PathID)
	}
	if result.adjRoutes[1].PathID != 2 {
		t.Errorf("expected second PathID=2, got %d", result.adjRoutes[1].PathID)
	}
}
