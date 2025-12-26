package obf

import "testing"

func TestComputeMac1(t *testing.T) {
	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i)
	}
	macKey, err := DeriveMac1Key(pub)
	if err != nil {
		t.Fatalf("derive mac1 key: %v", err)
	}
	msg := []byte("hello")
	mac1, err := ComputeMac1(macKey, msg)
	if err != nil {
		t.Fatalf("compute mac1: %v", err)
	}
	if !VerifyMac1(mac1, mac1[:]) {
		t.Fatalf("expected mac1 to verify")
	}
	msg[0] = 'H'
	mac2, _ := ComputeMac1(macKey, msg)
	if VerifyMac1(mac1, mac2[:]) {
		t.Fatalf("expected mac1 mismatch on different message")
	}
}
