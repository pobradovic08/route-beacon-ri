package history

import (
	"bytes"
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

// wrapOpenBMP wraps a BMP message in an OpenBMP v2 frame.
func wrapOpenBMP(bmpMsg []byte) []byte {
	frame := make([]byte, bmp.OpenBMPHeaderSize+len(bmpMsg))
	binary.BigEndian.PutUint16(frame[0:2], 2)                    // version = 2
	binary.BigEndian.PutUint32(frame[2:6], 0)                    // collector_hash
	binary.BigEndian.PutUint32(frame[6:10], uint32(len(bmpMsg))) // msg_len
	copy(frame[bmp.OpenBMPHeaderSize:], bmpMsg)
	return frame
}

// newTestHistoryPipeline creates a Pipeline with nil writer for testing processRecord.
func newTestHistoryPipeline() *Pipeline {
	return NewPipeline(nil, 1000, 200, 16*1024*1024, zap.NewNop())
}

// --- C5. History processRecord tests ---

func TestHistoryProcessRecord_BasicRoute(t *testing.T) {
	p := newTestHistoryPipeline()

	// Build a valid BGP UPDATE with one IPv4 prefix: 10.0.0.0/24.
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
	rows := p.processRecord(context.Background(), rec)

	if len(rows) != 1 {
		t.Fatalf("expected 1 HistoryRow, got %d", len(rows))
	}
	row := rows[0]
	if row.Event.Prefix != "10.0.0.0/24" {
		t.Errorf("expected prefix '10.0.0.0/24', got '%s'", row.Event.Prefix)
	}
	if row.Event.AFI != 4 {
		t.Errorf("expected AFI 4, got %d", row.Event.AFI)
	}
	if row.Event.Action != "A" {
		t.Errorf("expected action 'A', got '%s'", row.Event.Action)
	}
	if row.Event.Nexthop != "192.168.1.1" {
		t.Errorf("expected nexthop '192.168.1.1', got '%s'", row.Event.Nexthop)
	}
	if row.Event.ASPath != "65001 65002" {
		t.Errorf("expected as_path '65001 65002', got '%s'", row.Event.ASPath)
	}
	if row.Event.Origin != "IGP" {
		t.Errorf("expected origin 'IGP', got '%s'", row.Event.Origin)
	}
	if row.TableName != "locrib" {
		t.Errorf("expected TableName 'locrib', got '%s'", row.TableName)
	}
	if len(row.EventID) != 32 {
		t.Errorf("expected 32-byte EventID, got %d bytes", len(row.EventID))
	}
	if row.BMPRaw == nil {
		t.Error("expected BMPRaw to be non-nil")
	}
	if row.Topic != "gobmp.raw" {
		t.Errorf("expected Topic 'gobmp.raw', got '%s'", row.Topic)
	}
}

func TestHistoryProcessRecord_SkipNonLocRIB(t *testing.T) {
	p := newTestHistoryPipeline()

	// Build with peer_type=0 (Global). Should be filtered out.
	nlri := []byte{24, 10, 0, 0}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeGlobal, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "global")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	rows := p.processRecord(context.Background(), rec)

	if len(rows) != 0 {
		t.Errorf("expected 0 rows for non-Loc-RIB peer, got %d", len(rows))
	}
}

func TestHistoryProcessRecord_SkipEOR(t *testing.T) {
	p := newTestHistoryPipeline()

	// Empty BGP UPDATE = IPv4 EOR marker. Should produce 0 events from
	// ParseUpdateAutoDetect, so the pipeline skips it.
	bgpUpdate := buildBGPUpdate(nil, nil, nil)
	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "locrib")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	rows := p.processRecord(context.Background(), rec)

	if len(rows) != 0 {
		t.Errorf("expected 0 rows for EOR marker, got %d", len(rows))
	}
}

func TestHistoryProcessRecord_MultiPrefix(t *testing.T) {
	p := newTestHistoryPipeline()

	// 3 IPv4 announcements in a single UPDATE.
	nlri := []byte{
		24, 10, 0, 0, // 10.0.0.0/24
		24, 10, 0, 1, // 10.0.1.0/24
		24, 10, 0, 2, // 10.0.2.0/24
	}
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate := buildBGPUpdate(nil, pathAttrs, nlri)

	bmpMsg := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate, "locrib")
	frame := wrapOpenBMP(bmpMsg)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	rows := p.processRecord(context.Background(), rec)

	if len(rows) != 3 {
		t.Fatalf("expected 3 HistoryRows, got %d", len(rows))
	}

	// Verify all 3 prefixes are present.
	prefixes := make(map[string]bool)
	for _, row := range rows {
		prefixes[row.Event.Prefix] = true
	}
	for _, expected := range []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"} {
		if !prefixes[expected] {
			t.Errorf("expected prefix '%s' in results", expected)
		}
	}

	// C1 fix verification: each row must have a DIFFERENT EventID.
	for i := 0; i < len(rows); i++ {
		for j := i + 1; j < len(rows); j++ {
			if bytes.Equal(rows[i].EventID, rows[j].EventID) {
				t.Errorf("rows[%d] and rows[%d] have the same EventID (prefix=%s, prefix=%s) -- per-prefix event IDs broken",
					i, j, rows[i].Event.Prefix, rows[j].Event.Prefix)
			}
		}
	}
}

func TestHistoryProcessRecord_MultiMessage(t *testing.T) {
	p := newTestHistoryPipeline()

	// Build two separate BMP Route Monitoring messages, each with one prefix,
	// and concatenate them in a single OpenBMP frame.
	nlri1 := []byte{24, 10, 0, 0} // 10.0.0.0/24
	originAttr := buildPathAttr(0x40, bgp.AttrTypeOrigin, []byte{0})
	nexthopAttr := buildPathAttr(0x40, bgp.AttrTypeNextHop, []byte{192, 168, 1, 1})
	pathAttrs := append(originAttr, nexthopAttr...)
	bgpUpdate1 := buildBGPUpdate(nil, pathAttrs, nlri1)
	bmpMsg1 := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate1, "locrib")

	nlri2 := []byte{16, 172, 16} // 172.16.0.0/16
	bgpUpdate2 := buildBGPUpdate(nil, pathAttrs, nlri2)
	bmpMsg2 := buildBMPRouteMonitoring(bmp.PeerTypeLocRIB, 0, [4]byte{10, 0, 0, 1}, bgpUpdate2, "locrib")

	// Concatenate two BMP messages in one payload.
	combined := make([]byte, 0, len(bmpMsg1)+len(bmpMsg2))
	combined = append(combined, bmpMsg1...)
	combined = append(combined, bmpMsg2...)

	// Wrap the concatenated BMP messages in a single OpenBMP frame.
	frame := make([]byte, bmp.OpenBMPHeaderSize+len(combined))
	binary.BigEndian.PutUint16(frame[0:2], 2)
	binary.BigEndian.PutUint32(frame[2:6], 0)
	binary.BigEndian.PutUint32(frame[6:10], uint32(len(combined)))
	copy(frame[bmp.OpenBMPHeaderSize:], combined)

	rec := &kgo.Record{Value: frame, Topic: "gobmp.raw"}
	rows := p.processRecord(context.Background(), rec)

	if len(rows) != 2 {
		t.Fatalf("expected 2 HistoryRows from 2 BMP messages, got %d", len(rows))
	}

	prefixes := make(map[string]bool)
	for _, row := range rows {
		prefixes[row.Event.Prefix] = true
	}
	if !prefixes["10.0.0.0/24"] {
		t.Error("expected prefix '10.0.0.0/24' from first BMP message")
	}
	if !prefixes["172.16.0.0/16"] {
		t.Error("expected prefix '172.16.0.0/16' from second BMP message")
	}
}
