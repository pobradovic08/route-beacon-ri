package state

import (
	"encoding/json"
	"testing"
)

func TestDecodeUnicastPrefix_BasicAnnouncement(t *testing.T) {
	msg := map[string]any{
		"router_hash": "abc123",
		"table_name":  "global",
		"action":      "add",
		"prefix":      "10.0.0.0/24",
		"nexthop":     "192.168.1.1",
		"as_path":     "64496 64497",
		"origin":      "IGP",
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.RouterID != "abc123" {
		t.Errorf("expected router_id 'abc123', got '%s'", r.RouterID)
	}
	if r.Action != "A" {
		t.Errorf("expected action 'A', got '%s'", r.Action)
	}
	if r.Prefix != "10.0.0.0/24" {
		t.Errorf("expected prefix '10.0.0.0/24', got '%s'", r.Prefix)
	}
	if r.AFI != 4 {
		t.Errorf("expected AFI 4, got %d", r.AFI)
	}
}

func TestDecodeUnicastPrefix_Withdrawal(t *testing.T) {
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "del",
		"prefix":      "10.0.0.0/24",
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Action != "D" {
		t.Errorf("expected action 'D', got '%s'", r.Action)
	}
}

func TestDecodeUnicastPrefix_EOR(t *testing.T) {
	msg := map[string]any{
		"router_hash": "abc123",
		"is_eor":      true,
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsEOR {
		t.Error("expected IsEOR=true")
	}
}

func TestDecodeUnicastPrefix_MissingRouterID(t *testing.T) {
	msg := map[string]any{
		"action": "add",
		"prefix": "10.0.0.0/24",
	}
	data, _ := json.Marshal(msg)

	_, err := DecodeUnicastPrefix(data, 4)
	if err == nil {
		t.Fatal("expected error for missing router identifier")
	}
}

func TestDecodeUnicastPrefix_MissingPrefix(t *testing.T) {
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "add",
	}
	data, _ := json.Marshal(msg)

	_, err := DecodeUnicastPrefix(data, 4)
	if err == nil {
		t.Fatal("expected error for missing prefix")
	}
}

func TestDecodeUnicastPrefix_CommunitySpaceSeparated(t *testing.T) {
	msg := map[string]any{
		"router_hash":    "abc123",
		"action":         "add",
		"prefix":         "10.0.0.0/24",
		"community_list": "64496:100 64496:200",
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.CommStd) != 2 {
		t.Fatalf("expected 2 communities, got %d: %v", len(r.CommStd), r.CommStd)
	}
	if r.CommStd[0] != "64496:100" {
		t.Errorf("expected '64496:100', got '%s'", r.CommStd[0])
	}
	if r.CommStd[1] != "64496:200" {
		t.Errorf("expected '64496:200', got '%s'", r.CommStd[1])
	}
}

func TestDecodeUnicastPrefix_CommunityCommaSeparated(t *testing.T) {
	msg := map[string]any{
		"router_hash":    "abc123",
		"action":         "add",
		"prefix":         "10.0.0.0/24",
		"community_list": "64496:100,64496:200,64496:300",
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.CommStd) != 3 {
		t.Fatalf("expected 3 communities, got %d: %v", len(r.CommStd), r.CommStd)
	}
	if r.CommStd[0] != "64496:100" {
		t.Errorf("expected '64496:100', got '%s'", r.CommStd[0])
	}
	if r.CommStd[1] != "64496:200" {
		t.Errorf("expected '64496:200', got '%s'", r.CommStd[1])
	}
	if r.CommStd[2] != "64496:300" {
		t.Errorf("expected '64496:300', got '%s'", r.CommStd[2])
	}
}

func TestDecodeUnicastPrefix_CommunityCommaWithSpaces(t *testing.T) {
	msg := map[string]any{
		"router_hash":    "abc123",
		"action":         "add",
		"prefix":         "10.0.0.0/24",
		"community_list": "64496:100, 64496:200",
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.CommStd) != 2 {
		t.Fatalf("expected 2 communities, got %d: %v", len(r.CommStd), r.CommStd)
	}
	if r.CommStd[0] != "64496:100" {
		t.Errorf("expected '64496:100', got '%s'", r.CommStd[0])
	}
	if r.CommStd[1] != "64496:200" {
		t.Errorf("expected '64496:200', got '%s'", r.CommStd[1])
	}
}

func TestDecodeUnicastPrefix_CommunityArray(t *testing.T) {
	msg := map[string]any{
		"router_hash":    "abc123",
		"action":         "add",
		"prefix":         "10.0.0.0/24",
		"community_list": []any{"64496:100", "64496:200"},
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.CommStd) != 2 {
		t.Fatalf("expected 2 communities, got %d: %v", len(r.CommStd), r.CommStd)
	}
}

func TestDecodeUnicastPrefix_PrefixWithoutCIDR(t *testing.T) {
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "add",
		"prefix":      "10.0.0.0",
		"prefix_len":  float64(24),
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Prefix != "10.0.0.0/24" {
		t.Errorf("expected '10.0.0.0/24', got '%s'", r.Prefix)
	}
}

func TestDecodeUnicastPrefix_IPv6FromIsIPv4Flag(t *testing.T) {
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "add",
		"prefix":      "2001:db8::/32",
		"is_ipv4":     false,
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.AFI != 6 {
		t.Errorf("expected AFI 6, got %d", r.AFI)
	}
}

func TestDecodeUnicastPrefix_BaseAttrsfallback(t *testing.T) {
	// Simulates goBMP v1.1.0 format where as_path, origin, med, communities
	// are nested inside base_attrs rather than at the top level.
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "add",
		"prefix":      "10.0.0.0",
		"prefix_len":  float64(24),
		"nexthop":     "172.30.0.30",
		"is_loc_rib":  true,
		"is_ipv4":     true,
		"base_attrs": map[string]any{
			"as_path":        []any{float64(65002), float64(65001)},
			"origin":         "igp",
			"nexthop":        "172.30.0.30",
			"local_pref":     float64(100),
			"med":            float64(100),
			"community_list": "65001:100 65001:200",
		},
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ASPath != "65002 65001" {
		t.Errorf("expected as_path '65002 65001', got '%s'", r.ASPath)
	}
	if r.Origin != "igp" {
		t.Errorf("expected origin 'igp', got '%s'", r.Origin)
	}
	if r.LocalPref == nil || *r.LocalPref != 100 {
		t.Errorf("expected localpref 100, got %v", r.LocalPref)
	}
	if r.MED == nil || *r.MED != 100 {
		t.Errorf("expected med 100, got %v", r.MED)
	}
	if len(r.CommStd) != 2 || r.CommStd[0] != "65001:100" || r.CommStd[1] != "65001:200" {
		t.Errorf("expected communities [65001:100 65001:200], got %v", r.CommStd)
	}
	// base_attrs should not appear in remaining attrs
	if r.Attrs != nil {
		if _, ok := r.Attrs["base_attrs"]; ok {
			t.Error("base_attrs should not appear in remaining attrs")
		}
	}
}

func TestDecodePeerMessage_Down(t *testing.T) {
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "peer_down",
		"is_loc_rib":  true,
	}
	data, _ := json.Marshal(msg)

	pe, err := DecodePeerMessage(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pe.RouterID != "abc123" {
		t.Errorf("expected router_id 'abc123', got '%s'", pe.RouterID)
	}
	if pe.Action != "peer_down" {
		t.Errorf("expected action 'peer_down', got '%s'", pe.Action)
	}
	if !pe.IsLocRIB {
		t.Error("expected IsLocRIB=true")
	}
}

func TestDecodePeerMessage_MissingRouterID(t *testing.T) {
	msg := map[string]any{
		"action": "peer_down",
	}
	data, _ := json.Marshal(msg)

	_, err := DecodePeerMessage(data)
	if err == nil {
		t.Fatal("expected error for missing router identifier")
	}
}

// --- M18. Router ID fallback chain ---

func TestDecodeUnicastPrefix_RouterIPFallback(t *testing.T) {
	// Empty router_hash, non-empty router_ip. RouterID should fall back to router_ip.
	msg := map[string]any{
		"router_hash": "",
		"router_ip":   "10.0.0.1",
		"action":      "add",
		"prefix":      "192.168.0.0/16",
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.RouterID != "10.0.0.1" {
		t.Errorf("expected RouterID '10.0.0.1', got '%s'", r.RouterID)
	}
}

func TestDecodeUnicastPrefix_BMPRouterFallback(t *testing.T) {
	// Empty router_hash and empty router_ip, non-empty bmp_router.
	// RouterID should fall back to bmp_router.
	msg := map[string]any{
		"router_hash": "",
		"router_ip":   "",
		"bmp_router":  "172.16.0.1",
		"action":      "add",
		"prefix":      "10.0.0.0/8",
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.RouterID != "172.16.0.1" {
		t.Errorf("expected RouterID '172.16.0.1', got '%s'", r.RouterID)
	}
}

// --- M19. Action "delete" mapping ---

func TestDecodeUnicastPrefix_ActionDelete(t *testing.T) {
	// action: "delete" (lowercase full word) should map to "D".
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "delete",
		"prefix":      "10.0.0.0/24",
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Action != "D" {
		t.Errorf("expected Action 'D', got '%s'", r.Action)
	}
}

// --- M20. Unknown action default ---

func TestDecodeUnicastPrefix_UnknownAction(t *testing.T) {
	// action: "refresh" (unknown) should default to "A".
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "refresh",
		"prefix":      "10.0.0.0/24",
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Action != "A" {
		t.Errorf("expected Action 'A' (default), got '%s'", r.Action)
	}
}

// --- M21. Extra fields -> attrs ---

func TestExtractRemainingAttrs_ExtraFields(t *testing.T) {
	// JSON with standard fields plus extra unknown fields.
	// The extra fields should appear in the parsed Attrs map.
	msg := map[string]any{
		"router_hash":  "abc123",
		"action":       "add",
		"prefix":       "10.0.0.0/24",
		"custom_field": "value",
		"extra_number": float64(99),
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Attrs == nil {
		t.Fatal("expected Attrs to be non-nil with extra fields")
	}
	if v, ok := r.Attrs["custom_field"]; !ok {
		t.Error("expected 'custom_field' in Attrs")
	} else if s, ok := v.(string); !ok || s != "value" {
		t.Errorf("expected custom_field='value', got %v", v)
	}
	if v, ok := r.Attrs["extra_number"]; !ok {
		t.Error("expected 'extra_number' in Attrs")
	} else if n, ok := v.(float64); !ok || n != 99 {
		t.Errorf("expected extra_number=99, got %v", v)
	}
}

// --- M26. Path ID parsing ---

func TestDecodeUnicastPrefix_PathID(t *testing.T) {
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "add",
		"prefix":      "10.0.0.0/24",
		"path_id":     float64(42),
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.PathID != 42 {
		t.Errorf("expected PathID 42, got %d", r.PathID)
	}
}

// --- L21. int64Field with string input ---

func TestInt64Field_String(t *testing.T) {
	got := int64Field("42")
	if got != 42 {
		t.Errorf("expected int64(42), got %d", got)
	}
}

// --- L22. boolField with string input ---

func TestBoolField_StringTrue(t *testing.T) {
	m := map[string]any{
		"flag": "true",
	}
	got := boolField(m, "flag")
	if !got {
		t.Error("expected boolField to return true for string 'true'")
	}
}

// --- L23. stringField with float64 input ---

func TestStringField_Float64(t *testing.T) {
	m := map[string]any{
		"value": float64(3.14),
	}
	got := stringField(m, "value")
	if got != "3.14" {
		t.Errorf("expected '3.14', got '%s'", got)
	}
}

// --- Additional: IsEOR without prefix ---

func TestDecodeUnicastPrefix_IsEOR(t *testing.T) {
	// is_eor: true should succeed even without a prefix field.
	msg := map[string]any{
		"router_hash": "abc123",
		"is_eor":      true,
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsEOR {
		t.Error("expected IsEOR=true")
	}
}

// --- Additional: MissingPrefix with is_eor=false ---

func TestDecodeUnicastPrefix_MissingPrefixNotEOR(t *testing.T) {
	// No prefix and is_eor is false should return error.
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "add",
		"is_eor":      false,
	}
	data, _ := json.Marshal(msg)

	_, err := DecodeUnicastPrefix(data, 4)
	if err == nil {
		t.Fatal("expected error for missing prefix when is_eor=false")
	}
}

// --- Additional: LocalPref and MED ---

func TestDecodeUnicastPrefix_LocalPrefAndMED(t *testing.T) {
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "add",
		"prefix":      "10.0.0.0/24",
		"local_pref":  float64(200),
		"med":         float64(100),
	}
	data, _ := json.Marshal(msg)

	r, err := DecodeUnicastPrefix(data, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.LocalPref == nil {
		t.Fatal("expected LocalPref to be non-nil")
	}
	if *r.LocalPref != 200 {
		t.Errorf("expected LocalPref=200, got %d", *r.LocalPref)
	}
	if r.MED == nil {
		t.Fatal("expected MED to be non-nil")
	}
	if *r.MED != 100 {
		t.Errorf("expected MED=100, got %d", *r.MED)
	}
}

// --- Stream 3: Peer message tests ---

func TestDecodePeerMessage_Up(t *testing.T) {
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "peer_up",
		"is_loc_rib":  true,
		"table_name":  "inet.0",
	}
	data, _ := json.Marshal(msg)

	pe, err := DecodePeerMessage(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pe.Action != "peer_up" {
		t.Errorf("expected action 'peer_up', got '%s'", pe.Action)
	}
	if !pe.IsLocRIB {
		t.Error("expected IsLocRIB=true")
	}
}

func TestDecodePeerMessage_TableName(t *testing.T) {
	msg := map[string]any{
		"router_hash": "abc123",
		"action":      "peer_down",
		"is_loc_rib":  true,
		"table_name":  "VRF-1",
	}
	data, _ := json.Marshal(msg)

	pe, err := DecodePeerMessage(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pe.TableName != "VRF-1" {
		t.Errorf("expected TableName 'VRF-1', got '%s'", pe.TableName)
	}
}

func TestDecodeUnicastPrefix_InvalidJSON(t *testing.T) {
	_, err := DecodeUnicastPrefix([]byte("not json"), 4)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
