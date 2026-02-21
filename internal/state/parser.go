package state

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ParsedRoute represents a decoded goBMP unicast prefix JSON message.
type ParsedRoute struct {
	RouterID   string
	TableName  string
	AFI        int // 4 or 6
	Prefix     string
	PathID     int64
	Action     string // "A" or "D"
	IsLocRIB   bool
	IsEOR      bool
	Nexthop    string
	ASPath     string
	Origin     string
	LocalPref  *int32
	MED        *int32
	CommStd    []string
	CommExt    []string
	CommLarge  []string
	Attrs      map[string]any
}

// PeerEvent represents a decoded goBMP peer topic message for session lifecycle.
type PeerEvent struct {
	RouterID string
	Action   string // "peer_down", "peer_up"
	IsLocRIB bool
}

// DecodeUnicastPrefix decodes a goBMP parsed unicast prefix JSON message.
func DecodeUnicastPrefix(data []byte, topicAFI int) (*ParsedRoute, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}

	r := &ParsedRoute{
		TableName: "UNKNOWN",
		AFI:       topicAFI,
		PathID:    0,
	}

	// Router ID: router_hash → router_ip → bmp_router fallback
	r.RouterID = stringField(raw, "router_hash")
	if r.RouterID == "" {
		r.RouterID = stringField(raw, "router_ip")
	}
	if r.RouterID == "" {
		r.RouterID = stringField(raw, "bmp_router")
	}
	if r.RouterID == "" {
		return nil, fmt.Errorf("no router identifier found")
	}

	// Loc-RIB filter
	r.IsLocRIB = boolField(raw, "is_loc_rib")

	// Table name
	if tn := stringField(raw, "table_name"); tn != "" {
		r.TableName = tn
	}

	// AFI from message if available (override topic-based)
	if v, ok := raw["is_ipv4"]; ok {
		if isV4, ok := v.(bool); ok {
			if isV4 {
				r.AFI = 4
			} else {
				r.AFI = 6
			}
		}
	}

	// Action (case-insensitive)
	action := strings.ToLower(stringField(raw, "action"))
	switch action {
	case "add":
		r.Action = "A"
	case "del", "delete":
		r.Action = "D"
	default:
		r.Action = "A" // default to ADD if not specified
	}

	// EOR indicator
	r.IsEOR = boolField(raw, "is_eor")

	// Prefix
	r.Prefix = stringField(raw, "prefix")
	if r.Prefix == "" && !r.IsEOR {
		return nil, fmt.Errorf("missing prefix")
	}

	// Add prefix length if not already in CIDR notation
	if r.Prefix != "" && !strings.Contains(r.Prefix, "/") {
		prefixLen := intField(raw, "prefix_len")
		if prefixLen > 0 {
			r.Prefix = fmt.Sprintf("%s/%d", r.Prefix, prefixLen)
		}
	}

	// Path ID
	if pid, ok := raw["path_id"]; ok {
		r.PathID = int64Field(pid)
	}

	// Attributes
	r.Nexthop = stringField(raw, "nexthop")
	r.ASPath = stringField(raw, "as_path")
	r.Origin = stringField(raw, "origin")

	if lp, ok := raw["local_pref"]; ok {
		v := int32(int64Field(lp))
		r.LocalPref = &v
	}
	if med, ok := raw["med"]; ok {
		v := int32(int64Field(med))
		r.MED = &v
	}

	// Communities
	r.CommStd = stringArrayField(raw, "community_list")
	r.CommExt = stringArrayField(raw, "ext_community_list")
	r.CommLarge = stringArrayField(raw, "large_community_list")

	// Fall back to base_attrs for fields goBMP v1.1.0 nests there
	mergeBaseAttrs(raw, r)

	// Remaining attributes → attrs JSONB
	r.Attrs = extractRemainingAttrs(raw)

	return r, nil
}

// DecodePeerMessage decodes a goBMP parsed peer topic JSON message.
func DecodePeerMessage(data []byte) (*PeerEvent, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}

	pe := &PeerEvent{}

	// Router ID
	pe.RouterID = stringField(raw, "router_hash")
	if pe.RouterID == "" {
		pe.RouterID = stringField(raw, "router_ip")
	}
	if pe.RouterID == "" {
		pe.RouterID = stringField(raw, "bmp_router")
	}
	if pe.RouterID == "" {
		return nil, fmt.Errorf("no router identifier in peer message")
	}

	// Action: peer_down, peer_up
	pe.Action = strings.ToLower(stringField(raw, "action"))

	// Loc-RIB check
	pe.IsLocRIB = boolField(raw, "is_loc_rib")

	return pe, nil
}

// Helper functions for safe field extraction from map[string]any.

func stringField(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		switch s := v.(type) {
		case string:
			return s
		case float64:
			return strconv.FormatFloat(s, 'f', -1, 64)
		}
	}
	return ""
}

func boolField(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		switch b := v.(type) {
		case bool:
			return b
		case string:
			return strings.EqualFold(b, "true")
		}
	}
	return false
}

func intField(m map[string]any, key string) int {
	if v, ok := m[key]; ok {
		return int(int64Field(v))
	}
	return 0
}

func int64Field(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	}
	return 0
}

func stringArrayField(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch arr := v.(type) {
	case []any:
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		if len(result) == 0 {
			return nil
		}
		return result
	case string:
		// Some goBMP versions send communities as a single comma-separated string.
		if arr == "" {
			return nil
		}
		if strings.Contains(arr, ",") {
			parts := strings.Split(arr, ",")
			result := make([]string, 0, len(parts))
			for _, p := range parts {
				if s := strings.TrimSpace(p); s != "" {
					result = append(result, s)
				}
			}
			return result
		}
		return strings.Split(arr, " ")
	}
	return nil
}

// mergeBaseAttrs extracts route attributes from the nested base_attrs object
// that goBMP v1.1.0+ uses, filling in any fields not found at the top level.
func mergeBaseAttrs(raw map[string]any, r *ParsedRoute) {
	ba, ok := raw["base_attrs"]
	if !ok {
		return
	}
	baseAttrs, ok := ba.(map[string]any)
	if !ok {
		return
	}

	if r.ASPath == "" {
		if v, ok := baseAttrs["as_path"]; ok {
			switch arr := v.(type) {
			case []any:
				parts := make([]string, 0, len(arr))
				for _, item := range arr {
					switch n := item.(type) {
					case float64:
						parts = append(parts, strconv.FormatInt(int64(n), 10))
					case string:
						parts = append(parts, n)
					}
				}
				r.ASPath = strings.Join(parts, " ")
			case string:
				r.ASPath = arr
			}
		}
	}

	if r.Origin == "" {
		r.Origin = stringField(baseAttrs, "origin")
	}

	if r.Nexthop == "" {
		r.Nexthop = stringField(baseAttrs, "nexthop")
	}

	if r.LocalPref == nil {
		if lp, ok := baseAttrs["local_pref"]; ok {
			v := int32(int64Field(lp))
			r.LocalPref = &v
		}
	}

	if r.MED == nil {
		if med, ok := baseAttrs["med"]; ok {
			v := int32(int64Field(med))
			r.MED = &v
		}
	}

	if r.CommStd == nil {
		r.CommStd = stringArrayField(baseAttrs, "community_list")
	}
	if r.CommExt == nil {
		r.CommExt = stringArrayField(baseAttrs, "ext_community_list")
	}
	if r.CommLarge == nil {
		r.CommLarge = stringArrayField(baseAttrs, "large_community_list")
	}
}

// knownFields are fields already extracted; everything else goes to attrs.
var knownFields = map[string]bool{
	"router_hash": true, "router_ip": true, "bmp_router": true,
	"is_loc_rib": true, "table_name": true, "is_ipv4": true,
	"action": true, "is_eor": true, "prefix": true, "prefix_len": true,
	"path_id": true, "nexthop": true, "as_path": true, "origin": true,
	"local_pref": true, "med": true,
	"community_list": true, "ext_community_list": true, "large_community_list": true,
	"timestamp": true, "peer_hash": true, "peer_ip": true, "peer_asn": true,
	"peer_type": true, "base_attrs": true,
}

func extractRemainingAttrs(m map[string]any) map[string]any {
	attrs := make(map[string]any)
	for k, v := range m {
		if !knownFields[k] {
			attrs[k] = v
		}
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}
