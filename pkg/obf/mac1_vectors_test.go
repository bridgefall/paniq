package obf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestMac1Vectors(t *testing.T) {
	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i)
	}
	macKey, err := DeriveMac1Key(pub)
	if err != nil {
		t.Fatalf("derive mac1 key: %v", err)
	}
	vectors := []struct {
		name   string
		msgHex string
		macHex string
	}{
		{
			name:   "vector1",
			msgHex: "99bba5fc99aa83bd7b00c59a4cb9cf624023f38ed8d062645db28013dacec69161d630f132b3a2f47b43b5a7e2b1f56c746bb0cd1f94867bc8fb92ed549b44f5c87db78eff49c4e8397c19e0601951f8e48e02f17f1dcc8eb007fff8af7f668283cc7cfa80db8153adf7d80c10e020fde80b3f9015cd93ad0bd50ccc8856e43f",
			macHex: "fb280fafec8f8966531ad572c0e00812",
		},
		{
			name:   "vector2",
			msgHex: "33e72a849fff576c2dc32de1f55c9756b893c27dd441dd7a4a593b50dd7a7a8c9b96af553ceb6d0b130b9798b340c3ccb85733456e8b092b812ed2b9660b9305",
			macHex: "ae526b7fc431d1823dbcde7ce2a81622",
		},
		{
			name:   "vector3",
			msgHex: "9b96af553ceb6d0b130b9798b340c3ccb85733456e8b092b812ed2b9660b9305",
			macHex: "5ce00eb069f8bf1cb1ddf6e31a245f9f",
		},
	}

	for _, vec := range vectors {
		t.Run(vec.name, func(t *testing.T) {
			msg, err := hex.DecodeString(vec.msgHex)
			if err != nil {
				t.Fatalf("decode msg: %v", err)
			}
			expected, err := hex.DecodeString(vec.macHex)
			if err != nil {
				t.Fatalf("decode mac: %v", err)
			}
			mac1, err := ComputeMac1(macKey, msg)
			if err != nil {
				t.Fatalf("compute mac1: %v", err)
			}
			if !bytes.Equal(mac1[:], expected) {
				t.Fatalf("mac1 mismatch: got %x want %x", mac1, expected)
			}
		})
	}
}
