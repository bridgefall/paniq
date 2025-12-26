package obf

import "testing"

func TestChainLengths(t *testing.T) {
	chain, err := ParseChain("<b 0xdeadbeef><r 8><t>")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if chain.Spec() != "<b 0xdeadbeef><r 8><t>" {
		t.Fatalf("unexpected spec: %s", chain.Spec())
	}

	if chain.ObfuscatedLen(0) != 4+8+4 {
		t.Fatalf("unexpected obfuscated len: %d", chain.ObfuscatedLen(0))
	}

	if chain.DeobfuscatedLen(0) != 0 {
		t.Fatalf("unexpected deobfuscated len: %d", chain.DeobfuscatedLen(0))
	}
}

func TestChainInvalidTag(t *testing.T) {
	if _, err := ParseChain("<x 1>"); err == nil {
		t.Fatalf("expected error for unknown tag")
	}
}
