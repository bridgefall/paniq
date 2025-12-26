package obf

import (
	"crypto/subtle"

	"golang.org/x/crypto/blake2s"
)

const (
	mac1Label = "mac1----"
	Mac1Size  = 16
)

// DeriveMac1Key derives the MAC1 key from a server public key.
func DeriveMac1Key(pubKey [32]byte) ([32]byte, error) {
	var out [32]byte
	data := make([]byte, 0, len(mac1Label)+len(pubKey))
	data = append(data, []byte(mac1Label)...)
	data = append(data, pubKey[:]...)
	sum := blake2s.Sum256(data)
	copy(out[:], sum[:])
	return out, nil
}

// ComputeMac1 computes MAC1 over msg using the provided mac1 key.
func ComputeMac1(mac1Key [32]byte, msg []byte) ([Mac1Size]byte, error) {
	var out [Mac1Size]byte
	h, err := blake2s.New128(mac1Key[:])
	if err != nil {
		return out, err
	}
	if _, err := h.Write(msg); err != nil {
		return out, err
	}
	sum := h.Sum(nil)
	copy(out[:], sum)
	return out, nil
}

// VerifyMac1 compares the expected MAC1 to the provided bytes.
func VerifyMac1(expected [Mac1Size]byte, provided []byte) bool {
	if len(provided) != Mac1Size {
		return false
	}
	return subtle.ConstantTimeCompare(expected[:], provided) == 1
}
