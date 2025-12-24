package obf

import "testing"

func TestHeaderParseValidate(t *testing.T) {
	header, err := ParseHeader("1-3")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if header.GenSpec() != "1-3" {
		t.Fatalf("unexpected spec: %s", header.GenSpec())
	}

	if !header.Validate(1) || !header.Validate(2) || !header.Validate(3) {
		t.Fatalf("expected values to validate")
	}
	if header.Validate(0) || header.Validate(4) {
		t.Fatalf("expected values to be invalid")
	}
}

func TestHeaderInvalidRange(t *testing.T) {
	if _, err := ParseHeader("3-1"); err == nil {
		t.Fatalf("expected error for invalid range")
	}
}
