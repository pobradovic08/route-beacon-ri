package bmp

import (
	"encoding/binary"
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
