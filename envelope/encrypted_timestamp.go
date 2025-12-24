package envelope

import (
	"crypto/rand"
	"errors"

	"github.com/bridgefall/paniq/tai64n"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	encryptedTimestampVersion    = 1
	encryptedTimestampLabel      = "ts-encrypt"
	encryptedTimestampPubKeySize = 32
	encryptedTimestampHeaderSize = 1 + encryptedTimestampPubKeySize + chacha20poly1305.NonceSizeX
)

func buildEncryptedTimestampPayload(serverPub [32]byte) ([]byte, error) {
	var clientPriv [32]byte
	if _, err := rand.Read(clientPriv[:]); err != nil {
		return nil, err
	}
	clientPub, err := curve25519.X25519(clientPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(clientPriv[:], serverPub[:])
	if err != nil {
		return nil, err
	}
	key := deriveEncryptedTimestampKey(shared)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	var nonce [chacha20poly1305.NonceSizeX]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	ts := tai64n.Now()
	ciphertext := aead.Seal(nil, nonce[:], ts[:], nil)

	payload := make([]byte, 0, encryptedTimestampHeaderSize+len(ciphertext))
	payload = append(payload, encryptedTimestampVersion)
	payload = append(payload, clientPub...)
	payload = append(payload, nonce[:]...)
	payload = append(payload, ciphertext...)
	return payload, nil
}

func parseEncryptedTimestampPayload(payload []byte, serverPriv [32]byte) (tai64n.Timestamp, bool, error) {
	var ts tai64n.Timestamp
	if len(payload) < encryptedTimestampHeaderSize+chacha20poly1305.Overhead+tai64n.TimestampSize {
		return ts, false, nil
	}
	if payload[0] != encryptedTimestampVersion {
		return ts, false, nil
	}
	clientPub := payload[1 : 1+encryptedTimestampPubKeySize]
	nonce := payload[1+encryptedTimestampPubKeySize : encryptedTimestampHeaderSize]
	ciphertext := payload[encryptedTimestampHeaderSize:]
	shared, err := curve25519.X25519(serverPriv[:], clientPub)
	if err != nil {
		return ts, true, err
	}
	key := deriveEncryptedTimestampKey(shared)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return ts, true, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ts, true, err
	}
	if len(plaintext) != tai64n.TimestampSize {
		return ts, true, errors.New("invalid timestamp size")
	}
	copy(ts[:], plaintext)
	return ts, true, nil
}

func deriveEncryptedTimestampKey(shared []byte) [32]byte {
	input := make([]byte, 0, len(encryptedTimestampLabel)+len(shared))
	input = append(input, []byte(encryptedTimestampLabel)...)
	input = append(input, shared...)
	return blake2s.Sum256(input)
}
