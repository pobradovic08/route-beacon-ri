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
