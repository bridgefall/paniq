package envelope

import "testing"

func TestDecodeTransportPayloadValid(t *testing.T) {
	payload := make([]byte, 0, 2+3+5)
	payload = append(payload, 0, 3) // inner_len=3
	payload = append(payload, []byte("abc")...)
	payload = append(payload, []byte{1, 2, 3, 4, 5}...)

	inner, pad, err := decodeTransportPayload(payload, false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(inner) != "abc" {
		t.Fatalf("unexpected inner payload: %q", inner)
	}
	if pad != 5 {
		t.Fatalf("expected pad 5, got %d", pad)
	}
}

func TestDecodeTransportPayloadInvalidLen(t *testing.T) {
	payload := []byte{0, 0}
	if _, _, err := decodeTransportPayload(payload, false, nil); err == nil {
		t.Fatalf("expected error for zero inner_len")
	}
	payload = []byte{0, 5, 1, 2}
	if _, _, err := decodeTransportPayload(payload, false, nil); err == nil {
		t.Fatalf("expected error for oversized inner_len")
	}
}

func TestDecodeTransportPayloadReplayReject(t *testing.T) {
	payload := make([]byte, 0, 8+2+3)
	payload = append(payload, 0, 0, 0, 0, 0, 0, 0, 1) // counter
	payload = append(payload, 0, 3)                 // inner_len=3
	payload = append(payload, []byte("abc")...)

	_, _, err := decodeTransportPayload(payload, true, func(uint64) bool { return false })
	if err != errReplayReject {
		t.Fatalf("expected replay reject, got %v", err)
	}
}
