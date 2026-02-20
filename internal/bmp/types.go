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
	PerPeerHeaderSize = 42 // peer_type(1) + flags(2) + distinguisher(8) + addr(16) + AS(4) + BGPID(4) + ts_sec(4) + ts_usec(4) - 1 byte already included
)

// TLV type codes for Loc-RIB Route Monitoring (RFC 9069).
const (
	TLVTypeTableName uint16 = 0
)

// BMPVersion is the expected BMP protocol version.
const BMPVersion uint8 = 3

// PeerFlagAddPath is the bit position for Add-Path F flag in peer_flags.
// Bit 7 (counting from 0, MSB first) of the 16-bit flags field = 0x0100.
const PeerFlagAddPath uint16 = 0x0100

// ParsedBMP represents a parsed BMP message.
type ParsedBMP struct {
	MsgType   uint8
	PeerType  uint8
	PeerFlags uint16
	IsLocRIB  bool
	HasAddPath bool
	TableName string
	BGPData   []byte // The encapsulated BGP message bytes
}
