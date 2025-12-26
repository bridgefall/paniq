package obf

import "testing"

func TestParseChains(t *testing.T) {
	specs := []string{"<b 0xdead>", "", "<r 4>", "<t>", ""}
	set, err := ParseChains(specs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if set.I1 == nil || set.I3 == nil || set.I4 == nil {
		t.Fatalf("expected parsed chains")
	}
}
