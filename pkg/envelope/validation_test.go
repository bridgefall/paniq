package envelope

import (
	"net"
	"testing"
	"time"

	"github.com/bridgefall/paniq/pkg/obf"
)

func TestValidateTimestampSkew(t *testing.T) {
	now := time.Unix(1000, 0)
	s := &serverConn{
		skewSoft:   5 * time.Second,
		skewHard:   10 * time.Second,
		metrics:    &Metrics{},
		now:        func() time.Time { return now },
		logLimiter: newLogLimiter(time.Hour),
	}
	addr := &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}

	if s.validateTimestamp(now, uint32(1000-20), addr) {
		t.Fatalf("expected hard skew rejection")
	}
	if got := s.metrics.TimestampInvalid.Load(); got != 1 {
		t.Fatalf("expected timestamp_invalid metric, got %d", got)
	}
	if !s.validateTimestamp(now, uint32(1000-6), addr) {
		t.Fatalf("expected soft skew to pass")
	}
}

func TestMac1RejectBeforeReplay(t *testing.T) {
	framer, err := obf.NewFramer(obf.Config{})
	if err != nil {
		t.Fatalf("new framer: %v", err)
	}
	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	macKey, err := obf.DeriveMac1Key(pub)
	if err != nil {
		t.Fatalf("derive mac1: %v", err)
	}
	cache := newReplayCache(4)
	s := &serverConn{
		framer:      framer,
		mac1Key:     &macKey,
		replayCache: cache,
		now:         time.Now,
		logLimiter:  newLogLimiter(time.Hour),
	}
	state := &peerState{sigLengths: []int{}, sigChains: []*obf.Chain{}}
	frame, err := framer.EncodeFrame(obf.MessageInitiation, make([]byte, obf.Mac1Size))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	s.handlePreamble(state, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, frame)
	if len(cache.entries) != 0 {
		t.Fatalf("replay cache should not be populated on mac1 failure")
	}
}
