package obf

import (
	"crypto/rand"
	"strconv"
)

const chars52 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func newRandCharObf(val string) (obf, error) {
	length, err := strconv.Atoi(val)
	if err != nil {
		return nil, err
	}

	return &randCharObf{
		length: length,
	}, nil
}

type randCharObf struct {
	length int
}

func (o *randCharObf) Obfuscate(dst, src []byte) {
	rand.Read(dst[:o.length])
	for i := range dst[:o.length] {
		dst[i] = chars52[dst[i]%52]
	}
}

func (o *randCharObf) Deobfuscate(dst, src []byte) bool {
	for _, b := range src[:o.length] {
		if !isASCIIAlpha(b) {
			return false
		}
	}
	return true
}

func (o *randCharObf) ObfuscatedLen(n int) int {
	return o.length
}

func (o *randCharObf) DeobfuscatedLen(n int) int {
	return 0
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
