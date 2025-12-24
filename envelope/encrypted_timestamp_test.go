package envelope

import (
	"crypto/rand"
	"testing"

	"github.com/bridgefall/transport/obf"
	"github.com/bridgefall/transport/tai64n"
)

func TestEncryptedTimestampRoundTrip(t *testing.T) {
	var serverPriv [32]byte
	if _, err := rand.Read(serverPriv[:]); err != nil {
		t.Fatalf("private key: %v", err)
	}
	serverPub, err := obf.DerivePublicKey(serverPriv)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	payload, err := buildEncryptedTimestampPayload(serverPub)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	ts, ok, err := parseEncryptedTimestampPayload(payload, serverPriv)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if !ok {
		t.Fatalf("expected encrypted timestamp payload to parse")
	}
	var zero tai64n.Timestamp
	if ts == zero {
		t.Fatalf("expected non-zero timestamp")
	}
}
