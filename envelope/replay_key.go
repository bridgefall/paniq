package envelope

import (
	"crypto/sha256"
	"encoding/binary"
)

func replayKey(timestamp uint32, payload []byte, mac1 []byte) [32]byte {
	payloadHash := sha256.Sum256(payload)
	buf := make([]byte, 0, 4+len(payloadHash)+len(mac1))
	var tsBuf [4]byte
	binary.BigEndian.PutUint32(tsBuf[:], timestamp)
	buf = append(buf, tsBuf[:]...)
	buf = append(buf, payloadHash[:]...)
	buf = append(buf, mac1...)
	return sha256.Sum256(buf)
}
