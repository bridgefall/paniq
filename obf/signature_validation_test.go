package obf

import "testing"

func TestValidateSignatureValid(t *testing.T) {
	chain, err := ParseChain("<b 0x0102><rc 4><rd 3><t><r 2>")
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	buf := make([]byte, chain.ObfuscatedLen(0))
	chain.Obfuscate(buf, make([]byte, chain.DeobfuscatedLen(0)))

	info, ok := chain.ValidateSignature(buf)
	if !ok {
		t.Fatalf("expected signature to validate")
	}
	if !info.HasTimestamp {
		t.Fatalf("expected timestamp to be present")
	}
}

func TestValidateSignatureRejectsBadBytes(t *testing.T) {
	chain, err := ParseChain("<b 0x0102><rc 4><rd 3>")
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	buf := make([]byte, chain.ObfuscatedLen(0))
	chain.Obfuscate(buf, make([]byte, chain.DeobfuscatedLen(0)))

	buf[0] ^= 0xFF
	if _, ok := chain.ValidateSignature(buf); ok {
		t.Fatalf("expected signature to reject wrong bytes tag")
	}
}

func TestValidateSignatureRejectsRandChar(t *testing.T) {
	chain, err := ParseChain("<rc 4>")
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	buf := make([]byte, chain.ObfuscatedLen(0))
	chain.Obfuscate(buf, make([]byte, chain.DeobfuscatedLen(0)))
	buf[2] = byte(0x80)
	if _, ok := chain.ValidateSignature(buf); ok {
		t.Fatalf("expected signature to reject non-ascii letter")
	}
}

func TestValidateSignatureRejectsRandDigit(t *testing.T) {
	chain, err := ParseChain("<rd 4>")
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	buf := make([]byte, chain.ObfuscatedLen(0))
	chain.Obfuscate(buf, make([]byte, chain.DeobfuscatedLen(0)))
	buf[1] = 'a'
	if _, ok := chain.ValidateSignature(buf); ok {
		t.Fatalf("expected signature to reject non-digit")
	}
}
