package envelope

import (
	"testing"

	"github.com/bridgefall/paniq/pkg/obf"
)

func TestVerifyMac1(t *testing.T) {
	framer, err := obf.NewFramer(obf.Config{})
	if err != nil {
		t.Fatalf("new framer: %v", err)
	}
	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i)
	}
	macKey, err := obf.DeriveMac1Key(pub)
	if err != nil {
		t.Fatalf("derive mac1 key: %v", err)
	}
	payload := make([]byte, obf.Mac1Size)
	frame, err := framer.EncodeFrame(obf.MessageInitiation, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	mac1, err := obf.ComputeMac1(macKey, frame)
	if err != nil {
		t.Fatalf("compute mac1: %v", err)
	}
	copy(frame[framer.Config().S1+4:], mac1[:])
	s := &serverConn{framer: framer, mac1Key: &macKey}
	if !s.verifyMac1(frame, payload) {
		t.Fatalf("expected mac1 to verify")
	}
	frame[len(frame)-1] ^= 0x01
	if s.verifyMac1(frame, payload) {
		t.Fatalf("expected mac1 to fail on tampered frame")
	}
}
