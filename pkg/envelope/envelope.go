package envelope

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"log/slog"

	"github.com/bridgefall/paniq/pkg/commons/metrics"
	"github.com/bridgefall/paniq/pkg/obf"
	"github.com/bridgefall/paniq/pkg/profile"
	"github.com/bridgefall/paniq/internal/ratelimiter"
	"github.com/bridgefall/paniq/internal/replay"
	"github.com/bridgefall/paniq/internal/tai64n"
)

// DropReason captures why a packet was rejected.
type DropReason string

const (
	DropHeaderMismatch    DropReason = "header_mismatch"
	DropSizeViolation     DropReason = "size_violation"
	DropSignatureMismatch DropReason = "signature_mismatch"
	DropSignatureInvalid  DropReason = "signature_invalid"
	DropTimestampInvalid  DropReason = "timestamp_invalid"
	DropMac1Invalid       DropReason = "mac1_invalid"
	DropReplayReject      DropReason = "replay_reject"
	DropLegacyMissingTS   DropReason = "legacy_timestamp_missing"
	DropRateLimit         DropReason = "rate_limit"
	DropBadInitiation     DropReason = "bad_initiation"
	DropDecodeFailure     DropReason = "decode_failure"
	DropUnexpected        DropReason = "unexpected"
)

// Metrics tracks envelope-level counters.
type Metrics struct {
	UDPBytesIn              metrics.Counter
	UDPBytesOut             metrics.Counter
	PayloadBytesIn          metrics.Counter
	PayloadBytesOut         metrics.Counter
	PaddedBytesIn           metrics.Counter
	PaddedBytesOut          metrics.Counter
	PreambleJunk            metrics.Counter
	PreambleSignatures      metrics.Counter
	DropHeaderMismatch      metrics.Counter
	DropSizeViolation       metrics.Counter
	DropSignatureMismatch   metrics.Counter
	SigContentInvalid       metrics.Counter
	TimestampInvalid        metrics.Counter
	ReplayReject            metrics.Counter
	ReplayCacheEvictions    metrics.Counter
	Mac1Invalid             metrics.Counter
	LegacyTimestampMissing  metrics.Counter
	TransportReplayReject   metrics.Counter
	RateLimitDrop           metrics.Counter
	DropBadInitiation       metrics.Counter
	DropDecodeFailure       metrics.Counter
	DropUnexpected          metrics.Counter
	TransportPaddingIn      metrics.Counter
	TransportPaddingOut     metrics.Counter
	TransportPaddingClamped metrics.Counter
	TransportPaddingDropped metrics.Counter
}

// HandshakeOptions controls preamble pacing and retries.
type HandshakeOptions struct {
	Attempts           int
	Timeout            time.Duration
	PreambleDelay      time.Duration
	PreambleJitter     time.Duration
	Mac1Key            *[32]byte
	EncryptedTimestamp bool
	ServerPublicKey    *[32]byte
}

// ServerOptions controls server-side envelope behavior.
type ServerOptions struct {
	HandshakeTimeout          time.Duration
	MaxPacketSize             int
	Metrics                   *Metrics
	SignatureValidate         bool
	RequireTimestamp          bool
	EncryptedTimestamp        bool
	RequireEncryptedTimestamp bool
	LegacyModeEnabled         bool
	LegacyModeSunset          time.Time
	SkewSoft                  time.Duration
	SkewHard                  time.Duration
	ReplayWindow              time.Duration
	ReplayCacheSize           int
	Mac1Key                   *[32]byte
	ServerPrivateKey          *[32]byte
	TransportReplay           bool
	TransportReplayLimit      uint64
	RateLimitPPS              int
	RateLimitBurst            int
	Logger                    *slog.Logger
	LogInterval               time.Duration
	Now                       func() time.Time
	PaddingPolicy             profile.PaddingPolicy
}

// ClientOptions controls client-side envelope behavior.
type ClientOptions struct {
	Remote               net.Addr
	MaxPacketSize        int
	Metrics              *Metrics
	TransportReplay      bool
	TransportReplayLimit uint64
	PaddingPolicy        profile.PaddingPolicy
	Logger               *slog.Logger
	LogInterval          time.Duration
}

const defaultMaxPacketSize = 1200

// ClientHandshake performs the AWG preamble and waits for the OK marker.
func ClientHandshake(ctx context.Context, conn net.PacketConn, remote net.Addr, framer *obf.Framer, opts HandshakeOptions, metrics *Metrics) error {
	if framer == nil {
		return errors.New("framer required")
	}
	if remote == nil {
		return errors.New("remote required")
	}
	attempts := opts.Attempts
	if attempts <= 0 {
		attempts = 3
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	initPayload := []byte{}
	if opts.EncryptedTimestamp {
		if opts.ServerPublicKey == nil {
			return fmt.Errorf("server public key required for encrypted timestamp")
		}
		payload, err := buildEncryptedTimestampPayload(*opts.ServerPublicKey)
		if err != nil {
			return err
		}
		initPayload = payload
	}
	if opts.Mac1Key != nil {
		initPayload = append(initPayload, make([]byte, obf.Mac1Size)...)
	}
	initFrame, err := framer.EncodeFrame(obf.MessageInitiation, initPayload)
	if err != nil {
		return err
	}
	if opts.Mac1Key != nil {
		macOffset := len(initFrame) - obf.Mac1Size
		if macOffset < framer.Config().S1+4 {
			return fmt.Errorf("initiation frame too short for mac1")
		}
		shadow := make([]byte, len(initFrame))
		copy(shadow, initFrame)
		for i := macOffset; i < macOffset+obf.Mac1Size; i++ {
			shadow[i] = 0
		}
		mac1, err := obf.ComputeMac1(*opts.Mac1Key, shadow)
		if err != nil {
			return err
		}
		copy(initFrame[macOffset:], mac1[:])
	}

	respBuf := make([]byte, defaultMaxPacketSize*2)
	for attempt := 1; attempt <= attempts; attempt++ {
		deadline := time.Now().Add(timeout)
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}

		junk, err := framer.JunkDatagrams()
		if err != nil {
			return err
		}
		for _, d := range junk {
			if _, err := conn.WriteTo(d, remote); err != nil {
				return err
			}
			if metrics != nil {
				metrics.UDPBytesOut.Add(int64(len(d)))
				metrics.PaddedBytesOut.Add(int64(len(d)))
			}
			sleepPreamble(opts.PreambleDelay, opts.PreambleJitter)
		}

		sigs, err := framer.SignatureDatagrams()
		if err != nil {
			return err
		}
		for _, d := range sigs {
			if _, err := conn.WriteTo(d, remote); err != nil {
				return err
			}
			if metrics != nil {
				metrics.UDPBytesOut.Add(int64(len(d)))
				metrics.PaddedBytesOut.Add(int64(len(d)))
			}
			sleepPreamble(opts.PreambleDelay, opts.PreambleJitter)
		}

		if _, err := conn.WriteTo(initFrame, remote); err != nil {
			return err
		}
		if metrics != nil {
			metrics.UDPBytesOut.Add(int64(len(initFrame)))
			metrics.PaddedBytesOut.Add(int64(len(initFrame)))
		}

		for {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			n, addr, err := conn.ReadFrom(respBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					break
				}
				return err
			}
			if addr.String() != remote.String() {
				continue
			}
			if metrics != nil {
				metrics.UDPBytesIn.Add(int64(n))
				metrics.PaddedBytesIn.Add(int64(n))
			}
			msgType, _, err := framer.DecodeFrame(respBuf[:n])
			if err != nil {
				if metrics != nil {
					metrics.DropDecodeFailure.Add(1)
				}
				continue
			}
			if msgType == obf.MessageResponse {
				_ = conn.SetDeadline(time.Time{})
				return nil
			}
		}
	}

	return fmt.Errorf("handshake timeout")
}

// NewClientConn wraps a PacketConn for use with QUIC after preamble completion.
func NewClientConn(conn net.PacketConn, framer *obf.Framer, opts ClientOptions) net.PacketConn {
	maxPacket := opts.MaxPacketSize
	if maxPacket <= 0 {
		maxPacket = defaultMaxPacketSize
	}
	limit := opts.TransportReplayLimit
	if limit == 0 {
		limit = replay.RejectAfterMessages
	}
	logInterval := opts.LogInterval
	if logInterval <= 0 {
		logInterval = 10 * time.Second
	}
	return &clientConn{
		conn:                 conn,
		framer:               framer,
		remote:               opts.Remote,
		maxPacket:            maxPacket,
		metrics:              opts.Metrics,
		transportReplay:      opts.TransportReplay,
		transportReplayLimit: limit,
		paddingPolicy:        opts.PaddingPolicy,
		logger:               opts.Logger,
		logLimiter:           newLogLimiter(logInterval),
	}
}

// NewServerConn wraps a PacketConn for use with QUIC while enforcing the preamble.
func NewServerConn(conn net.PacketConn, framer *obf.Framer, opts ServerOptions) net.PacketConn {
	maxPacket := opts.MaxPacketSize
	if maxPacket <= 0 {
		maxPacket = defaultMaxPacketSize
	}
	timeout := opts.HandshakeTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	logInterval := opts.LogInterval
	if logInterval <= 0 {
		logInterval = 10 * time.Second
	}
	replayWindow := opts.ReplayWindow
	if replayWindow <= 0 {
		replayWindow = 30 * time.Second
	}
	replayCacheSize := opts.ReplayCacheSize
	if replayCacheSize <= 0 {
		replayCacheSize = 4096
	}
	skewSoft := opts.SkewSoft
	if skewSoft <= 0 {
		skewSoft = 15 * time.Second
	}
	skewHard := opts.SkewHard
	if skewHard <= 0 {
		skewHard = 30 * time.Second
	}
	limit := opts.TransportReplayLimit
	if limit == 0 {
		limit = replay.RejectAfterMessages
	}
	var rl *ratelimiter.Ratelimiter
	if opts.RateLimitPPS > 0 {
		rl = &ratelimiter.Ratelimiter{}
		rl.Init(opts.RateLimitPPS, opts.RateLimitBurst)
	}
	return &serverConn{
		conn:                      conn,
		framer:                    framer,
		maxPacket:                 maxPacket,
		handshakeTimeout:          timeout,
		metrics:                   opts.Metrics,
		signatureValidate:         opts.SignatureValidate,
		requireTimestamp:          opts.RequireTimestamp,
		encryptedTimestamp:        opts.EncryptedTimestamp,
		requireEncryptedTimestamp: opts.RequireEncryptedTimestamp,
		legacyModeEnabled:         opts.LegacyModeEnabled,
		legacyModeSunset:          opts.LegacyModeSunset,
		skewSoft:                  skewSoft,
		skewHard:                  skewHard,
		replayWindow:              replayWindow,
		mac1Key:                   opts.Mac1Key,
		serverPrivateKey:          opts.ServerPrivateKey,
		transportReplay:           opts.TransportReplay,
		transportReplayLimit:      limit,
		replayCache:               newReplayCache(replayCacheSize),
		rateLimiter:               rl,
		rateLimitEnabled:          rl != nil,
		logger:                    opts.Logger,
		logLimiter:                newLogLimiter(logInterval),
		now:                       nowFn,
		states:                    map[string]*peerState{},
		paddingPolicy:             opts.PaddingPolicy,
	}
}

type clientConn struct {
	conn                 net.PacketConn
	framer               *obf.Framer
	remote               net.Addr
	maxPacket            int
	metrics              *Metrics
	transportReplay      bool
	transportReplayLimit uint64
	sendCounter          atomic.Uint64
	replayFilter         replay.Filter
	paddingPolicy        profile.PaddingPolicy
	logger               *slog.Logger
	logLimiter           *logLimiter
}

func (c *clientConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, c.maxPacket*2)
	for {
		n, addr, err := c.conn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if c.remote != nil && addr.String() != c.remote.String() {
			continue
		}
		if c.metrics != nil {
			c.metrics.UDPBytesIn.Add(int64(n))
			c.metrics.PaddedBytesIn.Add(int64(n))
		}
		msgType, payload, err := c.framer.DecodeFrame(buf[:n])
		if err != nil {
			if c.metrics != nil {
				c.metrics.DropDecodeFailure.Add(1)
			}
			continue
		}
		if msgType != obf.MessageTransport {
			if c.metrics != nil {
				c.metrics.DropUnexpected.Add(1)
			}
			continue
		}
		inner, padLen, err := decodeTransportPayload(payload, c.transportReplay, func(counter uint64) bool {
			return c.replayFilter.ValidateCounter(counter, c.transportReplayLimit)
		})
		if err != nil {
			if err == errReplayReject {
				if c.metrics != nil {
					c.metrics.TransportReplayReject.Add(1)
				}
				continue
			}
			if c.metrics != nil {
				c.metrics.DropDecodeFailure.Add(1)
				c.metrics.TransportPaddingDropped.Add(1)
			}
			continue
		}
		if len(inner) > len(p) {
			return 0, nil, fmt.Errorf("payload too large")
		}
		copy(p, inner)
		if c.metrics != nil {
			c.metrics.PayloadBytesIn.Add(int64(len(inner)))
			c.metrics.TransportPaddingIn.Add(int64(padLen))
		}
		c.logTransport("rx", addr, n, len(inner), padLen, false)
		return len(inner), addr, nil
	}
}

func (c *clientConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	target := addr
	if c.remote != nil {
		target = c.remote
	}
	counter := uint64(0)
	if c.transportReplay {
		counter = c.sendCounter.Add(1) - 1
	}
	payload, padLen, clamped, err := buildTransportPayload(p, c.paddingPolicy, c.maxPayload(), c.transportReplay, counter)
	if err != nil {
		if c.metrics != nil {
			c.metrics.DropSizeViolation.Add(1)
			c.metrics.TransportPaddingDropped.Add(1)
		}
		return 0, err
	}
	if clamped && c.metrics != nil {
		c.metrics.TransportPaddingClamped.Add(1)
	}
	frame, err := c.framer.EncodeFrame(obf.MessageTransport, payload)
	if err != nil {
		return 0, err
	}
	if c.metrics != nil {
		c.metrics.UDPBytesOut.Add(int64(len(frame)))
		c.metrics.PaddedBytesOut.Add(int64(len(frame)))
		c.metrics.PayloadBytesOut.Add(int64(len(p)))
		c.metrics.TransportPaddingOut.Add(int64(padLen))
	}
	c.logTransport("tx", target, len(frame), len(p), padLen, clamped)
	return c.conn.WriteTo(frame, target)
}

func (c *clientConn) Close() error                       { return c.conn.Close() }
func (c *clientConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *clientConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *clientConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *clientConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *clientConn) SetReadBuffer(bytes int) error {
	if setter, ok := c.conn.(interface{ SetReadBuffer(int) error }); ok {
		return setter.SetReadBuffer(bytes)
	}
	return nil
}
func (c *clientConn) SetWriteBuffer(bytes int) error {
	if setter, ok := c.conn.(interface{ SetWriteBuffer(int) error }); ok {
		return setter.SetWriteBuffer(bytes)
	}
	return nil
}

func (c *clientConn) maxPayload() int {
	pad := c.framer.Config().S4 + 4
	max := c.maxPacket - pad
	if max <= 0 {
		return 0
	}
	return max
}

func (c *clientConn) logTransport(dir string, addr net.Addr, frameLen int, innerLen int, padLen int, clamped bool) {
	logTransportShared(c.logger, c.logLimiter, time.Now(), dir, addr, frameLen, innerLen, padLen, clamped)
}

type serverConn struct {
	conn                      net.PacketConn
	framer                    *obf.Framer
	maxPacket                 int
	handshakeTimeout          time.Duration
	metrics                   *Metrics
	signatureValidate         bool
	requireTimestamp          bool
	encryptedTimestamp        bool
	requireEncryptedTimestamp bool
	legacyModeEnabled         bool
	legacyModeSunset          time.Time
	skewSoft                  time.Duration
	skewHard                  time.Duration
	replayWindow              time.Duration
	mac1Key                   *[32]byte
	serverPrivateKey          *[32]byte
	transportReplay           bool
	transportReplayLimit      uint64
	replayCache               *replayCache
	rateLimiter               *ratelimiter.Ratelimiter
	rateLimitEnabled          bool
	logger                    *slog.Logger
	logLimiter                *logLimiter
	now                       func() time.Time
	lastClockCheck            time.Time
	mu                        sync.Mutex
	states                    map[string]*peerState
	paddingPolicy             profile.PaddingPolicy
}

type peerState struct {
	junkRemaining          int
	sigIndex               int
	sigLengths             []int
	sigChains              []*obf.Chain
	sigTimestamp           uint32
	sigHasTime             bool
	lastEncryptedTimestamp tai64n.Timestamp
	hasEncryptedTimestamp  bool
	transportReplayFilter  replay.Filter
	sendCounter            uint64
	ready                  bool
	lastSeen               time.Time
}

func (s *serverConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, s.maxPacket*2)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n == 0 {
			continue
		}
		if s.metrics != nil {
			s.metrics.UDPBytesIn.Add(int64(n))
			s.metrics.PaddedBytesIn.Add(int64(n))
		}
		state := s.stateFor(addr)
		if !state.ready {
			if s.expired(state) {
				s.resetState(state)
			}
			if handled := s.handlePreamble(state, addr, buf[:n]); handled {
				continue
			}
			if s.metrics != nil {
				s.metrics.DropUnexpected.Add(1)
			}
			continue
		}

		msgType, payload, err := s.framer.DecodeFrame(buf[:n])
		if err != nil {
			if s.metrics != nil {
				s.metrics.DropDecodeFailure.Add(1)
			}
			continue
		}
		if msgType != obf.MessageTransport {
			if s.metrics != nil {
				s.metrics.DropUnexpected.Add(1)
			}
			continue
		}
		inner, padLen, err := decodeTransportPayload(payload, s.transportReplay, func(counter uint64) bool {
			return state.transportReplayFilter.ValidateCounter(counter, s.transportReplayLimit)
		})
		if err != nil {
			if err == errReplayReject {
				if s.metrics != nil {
					s.metrics.TransportReplayReject.Add(1)
				}
				continue
			}
			if s.metrics != nil {
				s.metrics.DropDecodeFailure.Add(1)
				s.metrics.TransportPaddingDropped.Add(1)
			}
			continue
		}
		if len(inner) > len(p) {
			return 0, nil, fmt.Errorf("payload too large")
		}
		copy(p, inner)
		if s.metrics != nil {
			s.metrics.PayloadBytesIn.Add(int64(len(inner)))
			s.metrics.TransportPaddingIn.Add(int64(padLen))
		}
		s.logTransport("rx", addr, n, len(inner), padLen, false)
		return len(inner), addr, nil
	}
}

func (s *serverConn) handlePreamble(state *peerState, addr net.Addr, data []byte) bool {
	now := s.now()
	state.lastSeen = now
	if s.rateLimitEnabled {
		if ip, ok := addrIP(addr); ok {
			if !s.rateLimiter.Allow(ip) {
				if s.metrics != nil {
					s.metrics.RateLimitDrop.Add(1)
				}
				s.logDrop(DropRateLimit, addr, "rate limit")
				s.resetState(state)
				return true
			}
		}
	}
	if state.junkRemaining > 0 {
		state.junkRemaining--
		if s.metrics != nil {
			s.metrics.PreambleJunk.Add(1)
		}
		return true
	}
	if state.sigIndex < len(state.sigLengths) {
		if len(data) != state.sigLengths[state.sigIndex] {
			if s.metrics != nil {
				s.metrics.DropSignatureMismatch.Add(1)
			}
			s.logDrop(DropSignatureMismatch, addr, "signature length mismatch")
			s.resetState(state)
			return true
		}
		if s.signatureValidate {
			if state.sigIndex >= len(state.sigChains) {
				if s.metrics != nil {
					s.metrics.SigContentInvalid.Add(1)
				}
				s.logDrop(DropSignatureInvalid, addr, "signature chain missing")
				s.resetState(state)
				return true
			}
			info, ok := state.sigChains[state.sigIndex].ValidateSignature(data)
			if !ok {
				if s.metrics != nil {
					s.metrics.SigContentInvalid.Add(1)
				}
				s.logDrop(DropSignatureInvalid, addr, "signature content invalid")
				s.resetState(state)
				return true
			}
			if info.HasTimestamp {
				state.sigTimestamp = info.Timestamp
				state.sigHasTime = true
			}
		}
		state.sigIndex++
		if s.metrics != nil {
			s.metrics.PreambleSignatures.Add(1)
		}
		return true
	}
	msgType, payload, err := s.framer.DecodeFrame(data)
	if err != nil || msgType != obf.MessageInitiation {
		if s.metrics != nil {
			s.metrics.DropBadInitiation.Add(1)
		}
		s.logDrop(DropBadInitiation, addr, "invalid initiation")
		s.resetState(state)
		return true
	}
	hasMac1 := s.mac1Key != nil && len(payload) >= obf.Mac1Size
	payloadData := payload
	if hasMac1 {
		payloadData = payload[:len(payload)-obf.Mac1Size]
	}
	if s.mac1Key != nil {
		if !s.verifyMac1(data, payload) {
			if s.metrics != nil {
				s.metrics.Mac1Invalid.Add(1)
			}
			s.logDrop(DropMac1Invalid, addr, "mac1 invalid")
			s.resetState(state)
			return true
		}
	}
	encTimestamp := false
	if s.encryptedTimestamp && s.serverPrivateKey != nil {
		ts, ok, err := parseEncryptedTimestampPayload(payloadData, *s.serverPrivateKey)
		if err != nil && ok {
			if s.metrics != nil {
				s.metrics.TimestampInvalid.Add(1)
			}
			s.logDrop(DropTimestampInvalid, addr, "encrypted timestamp decrypt failed")
			s.resetState(state)
			return true
		}
		if ok {
			if state.hasEncryptedTimestamp && !ts.After(state.lastEncryptedTimestamp) {
				if s.metrics != nil {
					s.metrics.TimestampInvalid.Add(1)
				}
				s.logDrop(DropTimestampInvalid, addr, "encrypted timestamp replay")
				s.resetState(state)
				return true
			}
			state.lastEncryptedTimestamp = ts
			state.hasEncryptedTimestamp = true
			encTimestamp = true
		}
	}
	if s.requireEncryptedTimestamp && !encTimestamp {
		if s.metrics != nil {
			s.metrics.TimestampInvalid.Add(1)
		}
		s.logDrop(DropTimestampInvalid, addr, "encrypted timestamp missing")
		s.resetState(state)
		return true
	}
	if encTimestamp {
		if err := s.sendOK(addr); err == nil {
			s.markReady(state)
		}
		return true
	}
	if s.requireTimestamp && !state.sigHasTime {
		if !s.legacyAllowed(now) {
			if s.metrics != nil {
				s.metrics.TimestampInvalid.Add(1)
			}
			s.logDrop(DropTimestampInvalid, addr, "timestamp missing")
			s.resetState(state)
			return true
		}
		if s.metrics != nil {
			s.metrics.LegacyTimestampMissing.Add(1)
		}
		s.logDrop(DropLegacyMissingTS, addr, "legacy missing timestamp")
	} else if state.sigHasTime {
		if !s.validateTimestamp(now, state.sigTimestamp, addr) {
			s.resetState(state)
			return true
		}
		if !s.checkReplay(state.sigTimestamp, payload, data, addr) {
			s.resetState(state)
			return true
		}
	}
	if err := s.sendOK(addr); err == nil {
		s.markReady(state)
	}
	return true
}

func (s *serverConn) sendOK(addr net.Addr) error {
	frame, err := s.framer.EncodeFrame(obf.MessageResponse, []byte{})
	if err != nil {
		return err
	}
	if s.metrics != nil {
		s.metrics.UDPBytesOut.Add(int64(len(frame)))
		s.metrics.PaddedBytesOut.Add(int64(len(frame)))
	}
	_, err = s.conn.WriteTo(frame, addr)
	return err
}

func (s *serverConn) stateFor(addr net.Addr) *peerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := addr.String()
	state := s.states[key]
	if state == nil {
		state = &peerState{
			junkRemaining: s.framer.Config().Jc,
			sigLengths:    s.framer.SignatureLengths(),
			sigChains:     s.framer.SignatureChains(),
			lastSeen:      s.now(),
		}
		s.states[key] = state
	}
	return state
}

func (s *serverConn) resetState(state *peerState) {
	state.junkRemaining = s.framer.Config().Jc
	state.sigIndex = 0
	state.sigTimestamp = 0
	state.sigHasTime = false
	state.lastEncryptedTimestamp = tai64n.Timestamp{}
	state.hasEncryptedTimestamp = false
	state.transportReplayFilter.Reset()
	state.sendCounter = 0
	state.ready = false
	state.lastSeen = s.now()
}

func (s *serverConn) expired(state *peerState) bool {
	if s.handshakeTimeout <= 0 {
		return false
	}
	return s.now().Sub(state.lastSeen) > s.handshakeTimeout
}

func (s *serverConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	counter := uint64(0)
	if s.transportReplay {
		counter = s.nextSendCounter(addr)
	}
	payload, padLen, clamped, err := buildTransportPayload(p, s.paddingPolicy, s.maxPayload(), s.transportReplay, counter)
	if err != nil {
		if s.metrics != nil {
			s.metrics.DropSizeViolation.Add(1)
			s.metrics.TransportPaddingDropped.Add(1)
		}
		return 0, err
	}
	if clamped && s.metrics != nil {
		s.metrics.TransportPaddingClamped.Add(1)
	}
	frame, err := s.framer.EncodeFrame(obf.MessageTransport, payload)
	if err != nil {
		return 0, err
	}
	if s.metrics != nil {
		s.metrics.UDPBytesOut.Add(int64(len(frame)))
		s.metrics.PaddedBytesOut.Add(int64(len(frame)))
		s.metrics.PayloadBytesOut.Add(int64(len(p)))
		s.metrics.TransportPaddingOut.Add(int64(padLen))
	}
	s.logTransport("tx", addr, len(frame), len(p), padLen, clamped)
	return s.conn.WriteTo(frame, addr)
}

func (s *serverConn) Close() error {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
	return s.conn.Close()
}
func (s *serverConn) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *serverConn) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *serverConn) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *serverConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
func (s *serverConn) SetReadBuffer(bytes int) error {
	if setter, ok := s.conn.(interface{ SetReadBuffer(int) error }); ok {
		return setter.SetReadBuffer(bytes)
	}
	return nil
}
func (s *serverConn) SetWriteBuffer(bytes int) error {
	if setter, ok := s.conn.(interface{ SetWriteBuffer(int) error }); ok {
		return setter.SetWriteBuffer(bytes)
	}
	return nil
}

func (s *serverConn) maxPayload() int {
	pad := s.framer.Config().S4 + 4
	max := s.maxPacket - pad
	if max <= 0 {
		return 0
	}
	return max
}

func (s *serverConn) logTransport(dir string, addr net.Addr, frameLen int, innerLen int, padLen int, clamped bool) {
	logTransportShared(s.logger, s.logLimiter, s.now(), dir, addr, frameLen, innerLen, padLen, clamped)
}

func (s *serverConn) nextSendCounter(addr net.Addr) uint64 {
	state := s.stateFor(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	counter := state.sendCounter
	state.sendCounter++
	return counter
}

func (s *serverConn) markReady(state *peerState) {
	state.transportReplayFilter.Reset()
	state.sendCounter = 0
	state.ready = true
}

func (s *serverConn) logDrop(reason DropReason, addr net.Addr, msg string) {
	if s.logLimiter == nil {
		return
	}
	logger := resolveLogger(s.logger)
	now := s.now()
	if !s.logLimiter.Allow(string(reason), now) {
		return
	}
	logger.Warn("envelope drop", "reason", reason, "addr", addr.String(), "msg", msg)
}

func (s *serverConn) verifyMac1(frame []byte, payload []byte) bool {
	if s.mac1Key == nil {
		return true
	}
	if len(payload) < obf.Mac1Size {
		return false
	}
	macOffset := len(frame) - obf.Mac1Size
	if macOffset < s.framer.Config().S1+4 {
		return false
	}
	shadow := make([]byte, len(frame))
	copy(shadow, frame)
	for i := macOffset; i < macOffset+obf.Mac1Size; i++ {
		shadow[i] = 0
	}
	expected, err := obf.ComputeMac1(*s.mac1Key, shadow)
	if err != nil {
		return false
	}
	return obf.VerifyMac1(expected, frame[macOffset:macOffset+obf.Mac1Size])
}

func (s *serverConn) validateTimestamp(now time.Time, ts uint32, addr net.Addr) bool {
	nowUnix := now.Unix()
	delta := nowUnix - int64(ts)
	if delta < 0 {
		delta = -delta
	}
	skew := time.Duration(delta) * time.Second
	if s.skewHard > 0 && skew > s.skewHard {
		if s.metrics != nil {
			s.metrics.TimestampInvalid.Add(1)
		}
		s.logDrop(DropTimestampInvalid, addr, "timestamp skew hard")
		return false
	}
	if s.skewSoft > 0 && skew > s.skewSoft {
		s.logDrop(DropTimestampInvalid, addr, "timestamp skew soft")
	}
	return true
}

func (s *serverConn) checkReplay(timestamp uint32, payload []byte, frame []byte, addr net.Addr) bool {
	if s.replayCache == nil {
		return true
	}
	now := s.now()
	if s.clockJumped(now) {
		s.replayCache.Reset()
		if s.logger != nil && s.logLimiter != nil && s.logLimiter.Allow("clock_jump", now) {
			s.logger.Warn("envelope clock jump detected; replay cache reset")
		}
	}
	mac1 := []byte{}
	if s.mac1Key != nil {
		payloadOffset := s.framer.Config().S1 + 4
		if payloadOffset+obf.Mac1Size <= len(frame) {
			mac1 = frame[payloadOffset : payloadOffset+obf.Mac1Size]
		}
	}
	key := replayKey(timestamp, payload, mac1)
	replayed, evicted := s.replayCache.Seen(key)
	if evicted > 0 && s.metrics != nil {
		s.metrics.ReplayCacheEvictions.Add(int64(evicted))
	}
	if replayed {
		if s.metrics != nil {
			s.metrics.ReplayReject.Add(1)
		}
		s.logDrop(DropReplayReject, addr, "replay detected")
		return false
	}
	return true
}

func (s *serverConn) legacyAllowed(now time.Time) bool {
	if s.requireEncryptedTimestamp {
		return false
	}
	if !s.legacyModeEnabled {
		return false
	}
	if !s.legacyModeSunset.IsZero() && now.After(s.legacyModeSunset) {
		return false
	}
	return true
}

func (s *serverConn) clockJumped(now time.Time) bool {
	if s.lastClockCheck.IsZero() {
		s.lastClockCheck = now
		return false
	}
	diff := now.Sub(s.lastClockCheck)
	s.lastClockCheck = now
	threshold := s.replayWindow * 2
	if threshold <= 0 {
		threshold = 1 * time.Minute
	}
	return diff < 0 || diff > threshold
}

func sleepPreamble(delay time.Duration, jitter time.Duration) {
	if delay <= 0 && jitter <= 0 {
		return
	}
	if jitter > 0 {
		if extra, err := randDuration(jitter); err == nil {
			delay += extra
		}
	}
	if delay > 0 {
		time.Sleep(delay)
	}
}

func randDuration(max time.Duration) (time.Duration, error) {
	if max <= 0 {
		return 0, nil
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	val := binary.LittleEndian.Uint64(buf[:])
	return time.Duration(val % uint64(max)), nil
}
