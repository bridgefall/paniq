package obf

import (
	"testing"
)

func TestFramerEncodeDecodeFrame(t *testing.T) {
	cfg := Config{
		S1: 2, S2: 1, S3: 0, S4: 0,
		H1: "100", H2: "200", H3: "300", H4: "400",
	}
	framer, err := NewFramer(cfg)
	if err != nil {
		t.Fatalf("new framer failed: %v", err)
	}

	payload := []byte("hello")
	datagram, err := framer.EncodeFrame(MessageInitiation, payload)
	if err != nil {
		t.Fatalf("encode frame failed: %v", err)
	}

	msgType, out, err := framer.DecodeFrame(datagram)
	if err != nil {
		t.Fatalf("decode frame failed: %v", err)
	}
	if msgType != MessageInitiation {
		t.Fatalf("unexpected message type: %v", msgType)
	}
	if string(out) != string(payload) {
		t.Fatalf("unexpected payload: %q", out)
	}
}

func TestFramerJunkAndSignatures(t *testing.T) {
	cfg := Config{
		Jc: 2, Jmin: 2, Jmax: 4,
		H1: "1", H2: "2", H3: "3", H4: "4",
		I1: "<b 0xdeadbeef>",
	}
	framer, err := NewFramer(cfg)
	if err != nil {
		t.Fatalf("new framer failed: %v", err)
	}

	junk, err := framer.JunkDatagrams()
	if err != nil {
		t.Fatalf("junk datagrams failed: %v", err)
	}
	if len(junk) != cfg.Jc {
		t.Fatalf("expected %d junk datagrams, got %d", cfg.Jc, len(junk))
	}
	for _, d := range junk {
		if len(d) < cfg.Jmin || len(d) > cfg.Jmax {
			t.Fatalf("junk length out of range: %d", len(d))
		}
	}

	sigs, err := framer.SignatureDatagrams()
	if err != nil {
		t.Fatalf("signature datagrams failed: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature datagram, got %d", len(sigs))
	}
	if len(sigs[0]) != framer.SignatureLengths()[0] {
		t.Fatalf("signature length mismatch")
	}
}
