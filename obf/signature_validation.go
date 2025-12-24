package obf

import (
	"encoding/binary"
	"fmt"
)

// SignatureInfo captures parsed fields from a signature datagram.
type SignatureInfo struct {
	Timestamp    uint32
	HasTimestamp bool
}

// ValidateSignature validates a signature datagram against a chain spec.
// It returns parsed metadata and whether the signature is valid.
func (c *Chain) ValidateSignature(src []byte) (SignatureInfo, bool) {
	var info SignatureInfo
	if c == nil || c.inner == nil {
		return info, false
	}
	expected := c.inner.ObfuscatedLen(0)
	if len(src) != expected {
		return info, false
	}

	dynamicLen := len(src) - c.inner.ObfuscatedLen(0)
	read := 0
	for _, o := range c.inner.obfs {
		deobfLen := o.DeobfuscatedLen(dynamicLen)
		obfLen := o.ObfuscatedLen(deobfLen)
		if read+obfLen > len(src) {
			return info, false
		}
		segment := src[read : read+obfLen]
		dst := make([]byte, deobfLen)
		if !o.Deobfuscate(dst, segment) {
			return info, false
		}
		if _, ok := o.(*timestampObf); ok {
			if obfLen != 4 {
				return info, false
			}
			info.Timestamp = binary.BigEndian.Uint32(segment)
			info.HasTimestamp = true
		}
		read += obfLen
	}
	if read != len(src) {
		return info, false
	}
	return info, true
}

// ValidateSignatureSet validates a slice of signature datagrams against chains.
func ValidateSignatureSet(chains []*Chain, signatures [][]byte) ([]SignatureInfo, error) {
	if len(chains) != len(signatures) {
		return nil, fmt.Errorf("signature count mismatch")
	}
	results := make([]SignatureInfo, 0, len(chains))
	for i, chain := range chains {
		info, ok := chain.ValidateSignature(signatures[i])
		if !ok {
			return nil, fmt.Errorf("invalid signature %d", i)
		}
		results = append(results, info)
	}
	return results, nil
}
