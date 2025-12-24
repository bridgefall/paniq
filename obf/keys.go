package obf

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// DecodeKeyBase64 decodes a base64 key into a 32-byte array.
func DecodeKeyBase64(val string) ([32]byte, error) {
	var out [32]byte
	raw, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return out, fmt.Errorf("decode base64: %w", err)
	}
	if len(raw) != len(out) {
		return out, fmt.Errorf("invalid key length %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// DerivePublicKey returns the Curve25519 public key for a private key.
func DerivePublicKey(privateKey [32]byte) ([32]byte, error) {
	var out [32]byte
	pub, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return out, err
	}
	if len(pub) != len(out) {
		return out, fmt.Errorf("unexpected public key length %d", len(pub))
	}
	copy(out[:], pub)
	return out, nil
}
