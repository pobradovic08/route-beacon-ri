package maintenance

import "testing"

func TestValidPartitionName_Valid(t *testing.T) {
	name := "route_events_20250115"
	if !validPartitionName.MatchString(name) {
		t.Errorf("expected %q to match validPartitionName regex", name)
	}
}

func TestValidPartitionName_Invalid(t *testing.T) {
	invalid := []string{
		"route_events_abc",
		"other_table_20250115",
		"route_events_2025011",
		"",
	}
	for _, name := range invalid {
		if validPartitionName.MatchString(name) {
			t.Errorf("expected %q to NOT match validPartitionName regex", name)
		}
	}
}

func TestValidPartitionName_InjectionAttempt(t *testing.T) {
	name := "route_events_20250115; DROP TABLE x"
	if validPartitionName.MatchString(name) {
		t.Errorf("expected %q to NOT match validPartitionName regex (SQL injection attempt)", name)
	}
}
