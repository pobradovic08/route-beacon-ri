package bmp

// BMP message type codes (RFC 7854).
const (
	MsgTypeRouteMonitoring  uint8 = 0
	MsgTypeStatisticsReport uint8 = 1
	MsgTypePeerDown         uint8 = 2
	MsgTypePeerUp           uint8 = 3
	MsgTypeInitiation       uint8 = 4
	MsgTypeTermination      uint8 = 5
	MsgTypeRouteMirroring   uint8 = 6
)

// BMP peer types.
const (
	PeerTypeGlobal uint8 = 0
	PeerTypeRD     uint8 = 1
	PeerTypeLocal  uint8 = 2
	PeerTypeLocRIB uint8 = 3 // RFC 9069
)

// BMP header sizes.
const (
	CommonHeaderSize  = 6  // version(1) + msg_length(4) + msg_type(1)
	PerPeerHeaderSize = 42 // peer_type(1) + flags(1) + distinguisher(8) + addr(16) + AS(4) + BGPID(4) + ts_sec(4) + ts_usec(4)
)

// TLV type codes (RFC 7854 §4.4, RFC 9069).
const (
	TLVTypeTableName uint16 = 0
	TLVTypeSysDescr  uint16 = 1
	TLVTypeSysName   uint16 = 2
)

// BMPVersion is the expected BMP protocol version.
const BMPVersion uint8 = 3

// PeerFlagAddPath is the F-bit in peer_flags (RFC 9069 Section 4.2).
// Per RFC 9069, this is bit 7 (MSB, 0x80) of the single-octet flags field.
// ParseUpdateAutoDetect provides a safety net for routers that do not set
// this bit despite sending Add-Path encoded NLRI.
const PeerFlagAddPath uint8 = 0x80

// ParsedBMP represents a parsed BMP message.
type ParsedBMP struct {
	MsgType        uint8
	PeerType       uint8
	PeerFlags      uint8
	IsLocRIB       bool
	HasAddPath     bool
	TableName      string
	BGPData        []byte // The encapsulated BGP message bytes
	Offset         int    // Byte offset of this message within the raw payload (set by ParseAll)
	SysName        string // From Initiation TLV type 2
	SysDescr       string // From Initiation TLV type 1
	PeerDownReason uint8  // Reason code from Peer Down (offset 42)
	LocalASN       uint32 // Router's own ASN from Sent OPEN in non-Loc-RIB Peer Up
	LocalBGPID     string // Router's own BGP Identifier from Sent OPEN in non-Loc-RIB Peer Up
}
