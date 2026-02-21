package bmp

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildBMPRouteMonitoring builds a minimal BMP Route Monitoring message with the given peer type.
func buildBMPRouteMonitoring(peerType uint8, bgpPayload []byte) []byte {
	// BMP Common Header: version(1) + msg_length(4) + msg_type(1) = 6 bytes
	// Per-peer header: 42 bytes
	// BGP message payload
	totalLen := 6 + 42 + len(bgpPayload)

	msg := make([]byte, totalLen)
	msg[0] = BMPVersion                                             // version
	binary.BigEndian.PutUint32(msg[1:5], uint32(totalLen))          // msg_length
	msg[5] = MsgTypeRouteMonitoring                                 // msg_type

	// Per-peer header starts at offset 6
	msg[6] = peerType // peer_type
	// peer_flags, distinguisher, address, AS, BGPID, timestamps = zeros (41 bytes)
	// BGP payload starts at 6+42 = 48

	copy(msg[48:], bgpPayload)
	return msg
}

// buildMinimalBGPUpdate builds a minimal BGP UPDATE with just the header.
func buildMinimalBGPUpdate() []byte {
	// BGP header: marker(16) + length(2) + type(1) = 19
	// UPDATE body: withdrawn_len(2) + path_attr_len(2) = 4
	msg := make([]byte, 23)
	// Marker: 16 bytes of 0xFF
	for i := 0; i < 16; i++ {
		msg[i] = 0xFF
	}
	binary.BigEndian.PutUint16(msg[16:18], 23) // length
	msg[18] = 2                                 // type = UPDATE
	// withdrawn_len = 0, path_attr_len = 0 (already zero)
	return msg
}

func TestParse_LocRIB(t *testing.T) {
	bgp := buildMinimalBGPUpdate()
	bmpMsg := buildBMPRouteMonitoring(PeerTypeLocRIB, bgp)

	parsed, err := Parse(bmpMsg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.IsLocRIB {
		t.Error("expected IsLocRIB=true for peer_type=3")
	}
	if parsed.MsgType != MsgTypeRouteMonitoring {
		t.Errorf("expected MsgType=%d, got %d", MsgTypeRouteMonitoring, parsed.MsgType)
	}
}

func TestParse_NonLocRIB(t *testing.T) {
	bgp := buildMinimalBGPUpdate()
	bmpMsg := buildBMPRouteMonitoring(PeerTypeGlobal, bgp)

	parsed, err := Parse(bmpMsg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.IsLocRIB {
		t.Error("expected IsLocRIB=false for peer_type=0")
	}
}

func TestParse_TableNameTLV(t *testing.T) {
	bgp := buildMinimalBGPUpdate()
	// Build TLV: type=0 (Table Name), length=6, value="inet.0"
	tlv := make([]byte, 4+6)
	binary.BigEndian.PutUint16(tlv[0:2], 0) // type = TableName
	binary.BigEndian.PutUint16(tlv[2:4], 6) // length
	copy(tlv[4:], "inet.0")

	// Append TLV after BGP payload in a Loc-RIB message.
	payloadWithTLV := append(bgp, tlv...)
	bmpMsg := buildBMPRouteMonitoring(PeerTypeLocRIB, payloadWithTLV)

	parsed, err := Parse(bmpMsg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.TableName != "inet.0" {
		t.Errorf("expected TableName='inet.0', got '%s'", parsed.TableName)
	}
}

func TestParse_NoTLV_DefaultTableName(t *testing.T) {
	bgp := buildMinimalBGPUpdate()
	bmpMsg := buildBMPRouteMonitoring(PeerTypeLocRIB, bgp)

	parsed, err := Parse(bmpMsg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.TableName != "UNKNOWN" {
		t.Errorf("expected TableName='UNKNOWN', got '%s'", parsed.TableName)
	}
}

func TestParse_UnsupportedVersion(t *testing.T) {
	msg := make([]byte, 6)
	msg[0] = 2 // wrong version
	binary.BigEndian.PutUint32(msg[1:5], 6)
	msg[5] = MsgTypeRouteMonitoring

	_, err := Parse(msg)
	if err == nil {
		t.Fatal("expected error for unsupported BMP version")
	}
}

func TestParse_PeerDown(t *testing.T) {
	// Minimal Peer Down message.
	totalLen := 6 + 42 + 1 // common header + per-peer header + reason byte
	msg := make([]byte, totalLen)
	msg[0] = BMPVersion
	binary.BigEndian.PutUint32(msg[1:5], uint32(totalLen))
	msg[5] = MsgTypePeerDown
	msg[6] = PeerTypeLocRIB // peer_type in per-peer header

	parsed, err := Parse(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.MsgType != MsgTypePeerDown {
		t.Errorf("expected MsgType=%d, got %d", MsgTypePeerDown, parsed.MsgType)
	}
	if !parsed.IsLocRIB {
		t.Error("expected IsLocRIB=true for Loc-RIB peer down")
	}
}

func TestParse_MsgLengthTooSmall(t *testing.T) {
	// msg_length=3 is smaller than CommonHeaderSize(6) — must return error, not panic.
	msg := make([]byte, 6)
	msg[0] = BMPVersion
	binary.BigEndian.PutUint32(msg[1:5], 3) // msg_length < CommonHeaderSize
	msg[5] = MsgTypeRouteMonitoring

	_, err := Parse(msg)
	if err == nil {
		t.Fatal("expected error for msg_length smaller than common header size")
	}
}

func TestParse_MsgLengthExactlyHeader(t *testing.T) {
	// msg_length == CommonHeaderSize (6) — valid header but no payload.
	msg := make([]byte, 6)
	msg[0] = BMPVersion
	binary.BigEndian.PutUint32(msg[1:5], 6)
	msg[5] = MsgTypeRouteMonitoring

	// Should error because Route Monitoring requires a per-peer header.
	_, err := Parse(msg)
	if err == nil {
		t.Fatal("expected error for Route Monitoring with no per-peer header")
	}
}

func TestParse_TruncatedPerPeerHeader(t *testing.T) {
	// Route Monitoring with only 10 bytes of per-peer header (needs 42).
	totalLen := 6 + 10
	msg := make([]byte, totalLen)
	msg[0] = BMPVersion
	binary.BigEndian.PutUint32(msg[1:5], uint32(totalLen))
	msg[5] = MsgTypeRouteMonitoring

	_, err := Parse(msg)
	if err == nil {
		t.Fatal("expected error for truncated per-peer header")
	}
}

func TestParse_PeerDown_TruncatedPerPeerHeader(t *testing.T) {
	// Peer Down with only 20 bytes of per-peer header (needs 42).
	totalLen := 6 + 20
	msg := make([]byte, totalLen)
	msg[0] = BMPVersion
	binary.BigEndian.PutUint32(msg[1:5], uint32(totalLen))
	msg[5] = MsgTypePeerDown

	_, err := Parse(msg)
	if err == nil {
		t.Fatal("expected error for truncated per-peer header in peer down")
	}
}

func TestParse_TruncatedBGPPayload(t *testing.T) {
	// Route Monitoring with per-peer header but only 5 bytes of BGP data
	// (a valid BGP header needs 19 bytes minimum).
	totalLen := 6 + 42 + 5
	msg := make([]byte, totalLen)
	msg[0] = BMPVersion
	binary.BigEndian.PutUint32(msg[1:5], uint32(totalLen))
	msg[5] = MsgTypeRouteMonitoring
	msg[6] = PeerTypeLocRIB

	// For Loc-RIB, the parser tries to read BGP header length.
	// With only 5 bytes, bgpMessageLength fails and falls back to treating
	// all remaining data as BGP data (no panic).
	parsed, err := Parse(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still produce a result with the truncated data as BGPData.
	if parsed.BGPData == nil {
		t.Error("expected BGPData to be set even with truncated payload")
	}
}

func TestParse_MalformedTLV(t *testing.T) {
	bgp := buildMinimalBGPUpdate()
	// Build a malformed TLV: claims 100 bytes but only 2 bytes follow the header.
	tlv := []byte{
		0x00, 0x00, // type
		0x00, 0x64, // length = 100 (way more than available)
		0xAB, 0xCD, // only 2 bytes of data
	}
	payloadWithTLV := append(bgp, tlv...)
	bmpMsg := buildBMPRouteMonitoring(PeerTypeLocRIB, payloadWithTLV)

	// Should not panic; TLV parser should break gracefully.
	parsed, err := Parse(bmpMsg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Table name should remain default since TLV parsing failed.
	if parsed.TableName != "UNKNOWN" {
		t.Errorf("expected TableName='UNKNOWN' for malformed TLV, got '%s'", parsed.TableName)
	}
}

func TestParse_NoDataAfterPerPeerHeader(t *testing.T) {
	// Route Monitoring with exactly 42 bytes of per-peer header, no BGP data.
	totalLen := 6 + 42
	msg := make([]byte, totalLen)
	msg[0] = BMPVersion
	binary.BigEndian.PutUint32(msg[1:5], uint32(totalLen))
	msg[5] = MsgTypeRouteMonitoring
	msg[6] = PeerTypeLocRIB

	_, err := Parse(msg)
	if err == nil {
		t.Fatal("expected error for Route Monitoring with no data after per-peer header")
	}
}

func TestParse_AddPathFlag(t *testing.T) {
	bgp := buildMinimalBGPUpdate()
	bmpMsg := buildBMPRouteMonitoring(PeerTypeLocRIB, bgp)
	// Set Add-Path F flag: bit 0 (MSB) of single-byte peer_flags at offset 7.
	bmpMsg[7] = PeerFlagAddPath

	parsed, err := Parse(bmpMsg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.HasAddPath {
		t.Error("expected HasAddPath=true when F flag is set")
	}
}

func TestRouterIDFromPeerHeader_LocRIB_BGPIDFallback(t *testing.T) {
	// Simulate a Loc-RIB per-peer header where Peer Address (offset 10) is
	// all zeros but Peer BGP ID (offset 30) is set to 10.0.0.2.
	// Per RFC 9069 Section 4.1, Loc-RIB sets Peer Address and Peer AS to 0
	// but fills Peer BGP ID with the local BGP identifier.
	hdr := make([]byte, PerPeerHeaderSize)
	hdr[0] = PeerTypeLocRIB
	// Peer BGP ID at offset 30: 10.0.0.2
	hdr[30] = 10
	hdr[31] = 0
	hdr[32] = 0
	hdr[33] = 2

	routerID := RouterIDFromPeerHeader(hdr)
	if routerID != "10.0.0.2" {
		t.Errorf("expected router ID '10.0.0.2', got '%s'", routerID)
	}
}

func TestRouterIDFromPeerHeader_NormalPeer(t *testing.T) {
	// Normal IPv4 peer. BMP (RFC 7854 §4.2) encodes IPv4 as 12 zero bytes
	// followed by 4 IPv4 bytes in the 16-byte Peer Address field.
	// Peer Address starts at offset 10, so IPv4 bytes are at 10+12=22.
	hdr := make([]byte, PerPeerHeaderSize)
	hdr[0] = PeerTypeGlobal
	hdr[22] = 192
	hdr[23] = 168
	hdr[24] = 1
	hdr[25] = 1

	routerID := RouterIDFromPeerHeader(hdr)
	if routerID != "192.168.1.1" {
		t.Errorf("expected router ID '192.168.1.1', got '%s'", routerID)
	}
}

func TestRouterIDFromPeerHeader_AllZeros(t *testing.T) {
	// Loc-RIB with both Peer Address and BGP ID all zeros → empty string.
	hdr := make([]byte, PerPeerHeaderSize)
	hdr[0] = PeerTypeLocRIB

	routerID := RouterIDFromPeerHeader(hdr)
	if routerID != "" {
		t.Errorf("expected empty router ID, got '%s'", routerID)
	}
}

func TestRouterIDFromPeerHeader_TooShort(t *testing.T) {
	routerID := RouterIDFromPeerHeader([]byte{0, 0, 0})
	if routerID != "" {
		t.Errorf("expected empty router ID for short data, got '%s'", routerID)
	}
}

// --- C4. ParseAll multi-message tests ---

func TestParseAll_MultipleConcatenated(t *testing.T) {
	bgp := buildMinimalBGPUpdate()
	msg1 := buildBMPRouteMonitoring(PeerTypeLocRIB, bgp)
	msg2 := buildBMPRouteMonitoring(PeerTypeGlobal, bgp)
	msg3 := buildBMPRouteMonitoring(PeerTypeLocRIB, bgp)

	combined := make([]byte, 0, len(msg1)+len(msg2)+len(msg3))
	combined = append(combined, msg1...)
	combined = append(combined, msg2...)
	combined = append(combined, msg3...)

	results, err := ParseAll(combined)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 parsed messages, got %d", len(results))
	}
	if results[0].Offset != 0 {
		t.Errorf("expected first message Offset=0, got %d", results[0].Offset)
	}
	if results[1].Offset != len(msg1) {
		t.Errorf("expected second message Offset=%d, got %d", len(msg1), results[1].Offset)
	}
	if results[2].Offset != len(msg1)+len(msg2) {
		t.Errorf("expected third message Offset=%d, got %d", len(msg1)+len(msg2), results[2].Offset)
	}
	if !results[0].IsLocRIB {
		t.Error("expected first message IsLocRIB=true")
	}
	if results[1].IsLocRIB {
		t.Error("expected second message IsLocRIB=false")
	}
	if !results[2].IsLocRIB {
		t.Error("expected third message IsLocRIB=true")
	}
}

func TestParseAll_MixedValidInvalid(t *testing.T) {
	bgp := buildMinimalBGPUpdate()
	valid1 := buildBMPRouteMonitoring(PeerTypeLocRIB, bgp)
	valid2 := buildBMPRouteMonitoring(PeerTypeGlobal, bgp)

	// Build an invalid message: correct structure but bad BMP version byte.
	invalid := buildBMPRouteMonitoring(PeerTypeLocRIB, bgp)
	invalid[0] = 2 // wrong version — Parse will return error

	combined := make([]byte, 0, len(valid1)+len(invalid)+len(valid2))
	combined = append(combined, valid1...)
	combined = append(combined, invalid...)
	combined = append(combined, valid2...)

	results, err := ParseAll(combined)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 valid messages (skipping invalid), got %d", len(results))
	}
	if !results[0].IsLocRIB {
		t.Error("expected first valid message IsLocRIB=true")
	}
	if results[1].IsLocRIB {
		t.Error("expected second valid message IsLocRIB=false")
	}
}

func TestParseAll_TrailingGarbage(t *testing.T) {
	bgp := buildMinimalBGPUpdate()
	valid := buildBMPRouteMonitoring(PeerTypeLocRIB, bgp)

	// Append trailing garbage that is too short to form a valid BMP header.
	garbage := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	combined := append(valid, garbage...)

	results, err := ParseAll(combined)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 parsed message, got %d", len(results))
	}
	if !results[0].IsLocRIB {
		t.Error("expected IsLocRIB=true for the valid message")
	}
}

func TestParseAll_NoValidMessages(t *testing.T) {
	// Data too short for any BMP message.
	data := []byte{0x03, 0x00}

	results, err := ParseAll(data)
	if err == nil {
		t.Fatal("expected error when no valid messages can be parsed")
	}
	if results != nil {
		t.Errorf("expected nil results, got %d messages", len(results))
	}
}

// --- M22. RouterIDFromPeerHeader IPv6 test ---

func TestRouterIDFromPeerHeader_IPv6(t *testing.T) {
	// Build a per-peer header with a real IPv6 address (2001:db8::1) in the
	// Peer Address field at offset 10 (16 bytes).
	hdr := make([]byte, PerPeerHeaderSize)
	hdr[0] = PeerTypeGlobal

	ipv6 := net.ParseIP("2001:db8::1")
	copy(hdr[10:26], ipv6.To16())

	routerID := RouterIDFromPeerHeader(hdr)
	if routerID != "2001:db8::1" {
		t.Errorf("expected router ID '2001:db8::1', got '%s'", routerID)
	}
}

// --- M23. RouterIPFromOpenBMPV17 with non-zero admin ID ---

func TestRouterIPFromOpenBMPV17_NonZeroAdminID(t *testing.T) {
	// Build a mock OpenBMP v1.7 header where adminIDLen > 0.
	// The standard buildOpenBMPV17FrameWithIP uses hdrLen=78 and adminIDLen=0,
	// placing Router IP at offset 56. With adminIDLen=5, the Router IP moves
	// to offset 56+5=61.
	adminID := []byte("admin")
	adminIDLen := len(adminID)
	hdrLen := uint16(78 + adminIDLen)

	payload := []byte{0x03} // minimal payload
	frame := make([]byte, int(hdrLen)+len(payload))

	// Header fields
	binary.BigEndian.PutUint32(frame[0:4], 0x4F424D50) // "OBMP" magic
	frame[4] = 1                                        // major version
	frame[5] = 7                                        // minor version
	binary.BigEndian.PutUint16(frame[6:8], hdrLen)
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(payload)))
	frame[12] = 0x80 // flags
	frame[13] = 12   // message type: BMP_RAW

	// Offset 38: collector admin ID length
	binary.BigEndian.PutUint16(frame[38:40], uint16(adminIDLen))
	// Offset 40: collector admin ID
	copy(frame[40:40+adminIDLen], adminID)

	// Router Hash at offset 40+adminIDLen (16 bytes, zeroed)
	// Router IP at offset 56+adminIDLen (16 bytes)
	routerIPOffset := 56 + adminIDLen
	// IPv4 10.20.30.40 stored in first 4 bytes of the 16-byte field.
	frame[routerIPOffset] = 10
	frame[routerIPOffset+1] = 20
	frame[routerIPOffset+2] = 30
	frame[routerIPOffset+3] = 40

	// Remaining header fields (router group len, row count) at adjusted offsets.
	routerGroupLenOffset := 72 + adminIDLen
	binary.BigEndian.PutUint16(frame[routerGroupLenOffset:routerGroupLenOffset+2], 0)
	binary.BigEndian.PutUint32(frame[routerGroupLenOffset+2:routerGroupLenOffset+6], 1)

	copy(frame[hdrLen:], payload)

	got := RouterIPFromOpenBMPV17(frame)
	if got != "10.20.30.40" {
		t.Errorf("expected router IP '10.20.30.40', got '%s'", got)
	}
}

// --- M24. ParseAll truncated last message ---

func TestParseAll_TruncatedLastMessage(t *testing.T) {
	bgp := buildMinimalBGPUpdate()
	valid := buildBMPRouteMonitoring(PeerTypeLocRIB, bgp)

	// Append partial second message: only first 3 bytes of what would be a
	// valid BMP common header (needs 6 bytes minimum).
	partial := []byte{BMPVersion, 0x00, 0x00}
	combined := append(valid, partial...)

	results, err := ParseAll(combined)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 parsed message (truncated second skipped), got %d", len(results))
	}
	if !results[0].IsLocRIB {
		t.Error("expected the valid message to have IsLocRIB=true")
	}
}

// --- L24. Termination message ---

func TestParse_TerminationMessage(t *testing.T) {
	// Build a minimal BMP Termination message: common header only (no per-peer header).
	totalLen := CommonHeaderSize
	msg := make([]byte, totalLen)
	msg[0] = BMPVersion
	binary.BigEndian.PutUint32(msg[1:5], uint32(totalLen))
	msg[5] = MsgTypeTermination

	parsed, err := Parse(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.MsgType != MsgTypeTermination {
		t.Errorf("expected MsgType=%d, got %d", MsgTypeTermination, parsed.MsgType)
	}
}

// --- H9. Peer Down Loc-RIB with TLV ---

func TestParsePeerDown_LocRIB_TableNameTLV(t *testing.T) {
	// Build a BMP Peer Down message with:
	// - peer_type=3 (Loc-RIB)
	// - 1 byte reason code after per-peer header
	// - TLV with type=0 (table name), value="default"
	tableName := "default"
	tlv := make([]byte, 4+len(tableName))
	binary.BigEndian.PutUint16(tlv[0:2], uint16(TLVTypeTableName))
	binary.BigEndian.PutUint16(tlv[2:4], uint16(len(tableName)))
	copy(tlv[4:], tableName)

	// common header (6) + per-peer header (42) + reason code (1) + TLV
	totalLen := 6 + 42 + 1 + len(tlv)
	msg := make([]byte, totalLen)
	msg[0] = BMPVersion
	binary.BigEndian.PutUint32(msg[1:5], uint32(totalLen))
	msg[5] = MsgTypePeerDown
	msg[6] = PeerTypeLocRIB // peer_type in per-peer header
	msg[48] = 6             // reason code byte (value doesn't matter for this test)
	copy(msg[49:], tlv)     // TLV follows the reason code

	parsed, err := Parse(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.MsgType != MsgTypePeerDown {
		t.Errorf("expected MsgType=%d, got %d", MsgTypePeerDown, parsed.MsgType)
	}
	if !parsed.IsLocRIB {
		t.Error("expected IsLocRIB=true for Loc-RIB peer down")
	}
	if parsed.TableName != "default" {
		t.Errorf("expected TableName='default', got '%s'", parsed.TableName)
	}
}
