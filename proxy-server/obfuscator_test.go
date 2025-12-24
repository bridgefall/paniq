package proxyserver

import "testing"

func TestAWGObfuscatorInvalidConfig(t *testing.T) {
	_, err := NewAWGObfuscator(ObfConfig{Jmin: 10, Jmax: 5})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestAWGObfuscatorValidConfig(t *testing.T) {
	obf, err := NewAWGObfuscator(ObfConfig{H1: "1-2", H2: "3-4", H3: "5-6", H4: "7-8"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !obf.Enabled() {
		t.Fatalf("expected obfuscation to be enabled")
	}
}

func TestAWGObfuscatorDisabled(t *testing.T) {
	obf, err := NewAWGObfuscator(ObfConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if obf.Enabled() {
		t.Fatalf("expected obfuscation to be disabled")
	}
}
