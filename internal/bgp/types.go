package bgp

// BGP path attribute type codes.
const (
	AttrTypeOrigin          uint8 = 1
	AttrTypeASPath          uint8 = 2
	AttrTypeNextHop         uint8 = 3
	AttrTypeMED             uint8 = 4
	AttrTypeLocalPref       uint8 = 5
	AttrTypeCommunity       uint8 = 8
	AttrTypeMPReachNLRI     uint8 = 14
	AttrTypeMPUnreachNLRI   uint8 = 15
	AttrTypeExtCommunity    uint8 = 16
	AttrTypeLargeCommunity  uint8 = 32
)

// AFI codes.
const (
	AFIIPv4 uint16 = 1
	AFIIPv6 uint16 = 2
)

// SAFI codes.
const (
	SAFIUnicast uint8 = 1
)

// AS_PATH segment types.
const (
	ASPathSegmentSet      uint8 = 1
	ASPathSegmentSequence uint8 = 2
)

// Origin values.
var OriginValues = map[uint8]string{
	0: "IGP",
	1: "EGP",
	2: "INCOMPLETE",
}

// BGP message types.
const (
	BGPMsgTypeUpdate uint8 = 2
)

// BGP UPDATE header size: marker(16) + length(2) + type(1) = 19
const BGPHeaderSize = 19

// RouteEvent represents a single route event extracted from a BGP UPDATE.
type RouteEvent struct {
	AFI       int    // 4 or 6
	Prefix    string // CIDR notation
	PathID    int64  // 0 if no Add-Path
	Action    string // "A" or "D"
	Nexthop   string
	ASPath    string
	Origin    string
	LocalPref *uint32
	MED       *uint32
	CommStd   []string
	CommExt   []string
	CommLarge []string
	Attrs     map[string]string // Unknown attributes as hex strings
}
