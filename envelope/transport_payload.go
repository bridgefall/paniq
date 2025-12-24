package envelope

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"

	"github.com/bridgefall/transport/profile"
)

var errReplayReject = errors.New("replay rejected")
var errInvalidTransportPayload = errors.New("invalid transport payload")

func buildTransportPayload(inner []byte, policy profile.PaddingPolicy, maxPayload int, transportReplay bool, counter uint64) ([]byte, int, bool, error) {
	if len(inner) == 0 {
		return nil, 0, false, errInvalidTransportPayload
	}
	if len(inner) > math.MaxUint16 {
		return nil, 0, false, errInvalidTransportPayload
	}
	counterSize := 0
	if transportReplay {
		counterSize = 8
	}
	baseLen := counterSize + 2 + len(inner)
	if baseLen > maxPayload {
		return nil, 0, false, errInvalidTransportPayload
	}
	padLen, clamped, err := selectPaddingLen(policy, baseLen, maxPayload)
	if err != nil {
		return nil, 0, false, err
	}
	out := make([]byte, baseLen+padLen)
	offset := 0
	if transportReplay {
		binary.BigEndian.PutUint64(out[:8], counter)
		offset = 8
	}
	binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(inner)))
	offset += 2
	copy(out[offset:offset+len(inner)], inner)
	offset += len(inner)
	if padLen > 0 {
		if _, err := rand.Read(out[offset:]); err != nil {
			return nil, 0, false, err
		}
	}
	return out, padLen, clamped, nil
}

func decodeTransportPayload(payload []byte, transportReplay bool, validateCounter func(uint64) bool) ([]byte, int, error) {
	counterSize := 0
	var counter uint64
	if transportReplay {
		counterSize = 8
		if len(payload) < counterSize+2 {
			return nil, 0, errInvalidTransportPayload
		}
		counter = binary.BigEndian.Uint64(payload[:8])
		payload = payload[8:]
	}
	if len(payload) < 2 {
		return nil, 0, errInvalidTransportPayload
	}
	innerLen := int(binary.BigEndian.Uint16(payload[:2]))
	payload = payload[2:]
	if innerLen <= 0 || innerLen > len(payload) {
		return nil, 0, errInvalidTransportPayload
	}
	if transportReplay && validateCounter != nil {
		if !validateCounter(counter) {
			return nil, 0, errReplayReject
		}
	}
	padLen := len(payload) - innerLen
	return payload[:innerLen], padLen, nil
}

func selectPaddingLen(policy profile.PaddingPolicy, baseLen int, maxPayload int) (int, bool, error) {
	if !policy.Enabled() {
		return 0, false, nil
	}
	min := policy.Min
	max := policy.Max
	if policy.BurstProb > 0 && shouldBurst(policy.BurstProb) {
		min = policy.BurstMin
		max = policy.BurstMax
	}
	if max < min {
		return 0, false, errInvalidTransportPayload
	}
	if max == 0 && min == 0 {
		return 0, false, nil
	}
	padLen, err := randRangeInt(min, max)
	if err != nil {
		return 0, false, err
	}
	target := baseLen + padLen
	if target > maxPayload {
		padLen = maxPayload - baseLen
		if padLen < 0 {
			return 0, false, errInvalidTransportPayload
		}
		return padLen, true, nil
	}
	return padLen, false, nil
}

func shouldBurst(prob float64) bool {
	if prob <= 0 {
		return false
	}
	if prob >= 1 {
		return true
	}
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return false
	}
	val := binary.BigEndian.Uint32(buf[:])
	threshold := uint32(prob * float64(math.MaxUint32))
	return val <= threshold
}

func randRangeInt(min int, max int) (int, error) {
	if min > max {
		return 0, errInvalidTransportPayload
	}
	if min == max {
		return min, nil
	}
	span := uint32(max - min + 1)
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	val := binary.BigEndian.Uint32(buf[:]) % span
	return min + int(val), nil
}
