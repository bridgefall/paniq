package obf

import "testing"

func TestParseHeadersOverlap(t *testing.T) {
	specs := []string{"1-5", "4-6", "", ""}
	if _, err := ParseHeaders(specs); err == nil {
		t.Fatalf("expected overlap error")
	}
}

func TestParseHeadersOK(t *testing.T) {
	specs := []string{"1-5", "6-10", "11", ""}
	set, err := ParseHeaders(specs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if set.H1 == nil || set.H2 == nil || set.H3 == nil {
		t.Fatalf("expected headers to parse")
	}
}
