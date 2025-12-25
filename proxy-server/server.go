package proxyserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/bridgefall/paniq/commons/logger"
	"github.com/bridgefall/paniq/commons/metrics"
	"github.com/bridgefall/paniq/envelope"
	"github.com/bridgefall/paniq/obf"
	"github.com/bridgefall/paniq/profile"
)

const (
	proxyVersion           = 0x01
	statusSuccess          = 0x00
	statusFailure          = 0x01
	statusBadRequest       = 0x02
	addrTypeIPv4           = 0x01
	addrTypeDomain         = 0x03
	addrTypeIPv6           = 0x04
	defaultWorkerCount     = 8
	defaultMaxConnections  = 128
	defaultHandshakeTTL    = 5 * time.Second
	defaultDialTimeout     = 5 * time.Second
	defaultAcceptTTL       = 500 * time.Millisecond
	defaultIdleTimeout     = 2 * time.Minute
	defaultMetricsInterval = 10 * time.Second
	latencySampleSize      = 256
	maxDatagramSize        = 1200
)

const invalidConfigPrefix = "invalid config"

// Obfuscator wraps a connection with the AmneziaWG obfuscation layer.
type Obfuscator interface {
	Wrap(conn net.Conn) (net.Conn, error)
}

// NoopObfuscator applies no obfuscation.
type NoopObfuscator struct{}

func (NoopObfuscator) Wrap(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

// Config defines the proxy server configuration.
type Config struct {
	ListenAddr                string
	WorkerCount               int
	MaxConnections            int
	HandshakeTimeout          time.Duration
	Quic                      QuicConfig
	DialTimeout               time.Duration
	AcceptTimeout             time.Duration
	IdleTimeout               time.Duration
	MetricsInterval           time.Duration
	LogLevel                  string
	Obfuscator                Obfuscator
	SignatureValidate         bool
	RequireTimestamp          bool
	EncryptedTimestamp        bool
	RequireEncryptedTimestamp bool
	LegacyModeEnabled         bool
	LegacyModeSunset          time.Time
	LegacyModeMaxDays         int
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
	TransportPadding          profile.PaddingPolicy
}

// QuicConfig defines QUIC transport settings.
type QuicConfig struct {
	MaxPacketSize int
	MaxPayload    int
	KeepAlive     time.Duration
	IdleTimeout   time.Duration
	MaxStreams    int
}

// ServerMetrics captures proxy server metrics.
type ServerMetrics struct {
	ActiveConns       metrics.Gauge
	HandshakeFailures metrics.Counter
	HandshakeSuccess  metrics.Counter
	Reconnects        metrics.Counter
	BytesIn           metrics.Counter
	BytesOut          metrics.Counter
	JunkPackets       metrics.Counter
	SignatureMismatch metrics.Counter
	HandshakeBadInit  metrics.Counter
	DecodeFailures    metrics.Counter
	HandshakeLatency  *metrics.LatencySampler
}

// Server implements the proxy server (QUIC-only).
type Server struct {
	cfg        Config
	conn       net.PacketConn
	readyCh    chan struct{}
	wg         sync.WaitGroup
	mu         sync.RWMutex
	metrics    *ServerMetrics
	envMetrics *envelope.Metrics
}

// NewServer validates configuration and returns a new Server instance.
func NewServer(cfg Config) (*Server, error) {
	logger.Setup(cfg.LogLevel)

	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:     normalized,
		readyCh: make(chan struct{}),
		metrics: newServerMetrics(),
	}, nil
}

// Ready returns a channel that is closed when the server is listening.
func (s *Server) Ready() <-chan struct{} {
	return s.readyCh
}

// Addr returns the listener address once the server is running.
func (s *Server) Addr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// Serve runs the server until the context is canceled.
func (s *Server) Serve(ctx context.Context) error {
	return s.serveQUIC(ctx)
}

func (s *Server) requireFramer() (*obf.Framer, error) {
	obfAdapter, ok := s.cfg.Obfuscator.(*AWGObfuscator)
	if !ok || obfAdapter == nil || !obfAdapter.Enabled() {
		return nil, fmt.Errorf("obfuscation required for QUIC mode")
	}
	framer := obfAdapter.Framer()
	if framer == nil {
		return nil, fmt.Errorf("obfuscation framer missing")
	}
	return framer, nil
}

func (s *Server) dial(ctx context.Context, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: s.cfg.DialTimeout}
	return dialer.DialContext(ctx, "tcp", address)
}

type request struct {
	address string
}

func readRequest(reader io.Reader) (request, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return request{}, err
	}
	if header[0] != proxyVersion {
		return request{}, fmt.Errorf("unsupported proxy version: %d", header[0])
	}
	atyp := header[1]
	host, err := readAddress(reader, atyp)
	if err != nil {
		return request{}, err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return request{}, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return request{address: net.JoinHostPort(host, strconv.Itoa(int(port)))}, nil
}

func readAddress(reader io.Reader, atyp byte) (string, error) {
	switch atyp {
	case addrTypeIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case addrTypeIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case addrTypeDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(reader, lenBuf); err != nil {
			return "", err
		}
		domainLen := int(lenBuf[0])
		buf := make([]byte, domainLen)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", errors.New("unsupported address type")
	}
}

func buildResponsePayload(status byte, atyp byte, addr []byte, port uint16) []byte {
	buf := make([]byte, 0, 4+len(addr))
	buf = append(buf, status, atyp)
	buf = append(buf, addr...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf = append(buf, portBytes...)
	return buf
}

func addrToReply(addr net.Addr) (byte, []byte, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0, nil, 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return 0, nil, 0, errors.New("invalid ip address")
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return addrTypeIPv4, ipv4, uint16(port), nil
	}
	return addrTypeIPv6, ip.To16(), uint16(port), nil
}

func normalizeConfig(cfg Config) (Config, error) {
	if cfg.ListenAddr == "" {
		return Config{}, fmt.Errorf("%s: listen address required", invalidConfigPrefix)
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = defaultWorkerCount
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = defaultMaxConnections
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshakeTTL
	}
	if cfg.Quic.MaxPacketSize <= 0 {
		cfg.Quic.MaxPacketSize = 1350
	}
	if cfg.Quic.KeepAlive <= 0 {
		cfg.Quic.KeepAlive = 20 * time.Second
	}
	if cfg.Quic.IdleTimeout <= 0 {
		cfg.Quic.IdleTimeout = 2 * time.Minute
	}
	if cfg.Quic.MaxStreams <= 0 {
		cfg.Quic.MaxStreams = 256
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaultDialTimeout
	}
	if cfg.AcceptTimeout <= 0 {
		cfg.AcceptTimeout = defaultAcceptTTL
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.MetricsInterval <= 0 {
		cfg.MetricsInterval = defaultMetricsInterval
	}
	cfg.LogLevel = strings.ToLower(cfg.LogLevel)
	switch cfg.LogLevel {
	case "", "error", "warn", "info", "debug":
	default:
		return Config{}, fmt.Errorf("%s: log_level must be 'error', 'warn', 'info' or 'debug'", invalidConfigPrefix)
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.SkewSoft <= 0 {
		cfg.SkewSoft = 15 * time.Second
	}
	if cfg.SkewHard <= 0 {
		cfg.SkewHard = 30 * time.Second
	}
	if cfg.ReplayWindow <= 0 {
		cfg.ReplayWindow = 30 * time.Second
	}
	if cfg.ReplayCacheSize <= 0 {
		cfg.ReplayCacheSize = 4096
	}
	if cfg.RequireTimestamp && !cfg.SignatureValidate {
		return Config{}, fmt.Errorf("%s: signature validation required when timestamps are enforced", invalidConfigPrefix)
	}
	if cfg.RequireEncryptedTimestamp && !cfg.EncryptedTimestamp {
		return Config{}, fmt.Errorf("%s: encrypted timestamp required but disabled", invalidConfigPrefix)
	}
	if cfg.LegacyModeEnabled {
		if cfg.LegacyModeMaxDays > 0 && cfg.LegacyModeSunset.IsZero() {
			cfg.LegacyModeSunset = time.Now().Add(time.Duration(cfg.LegacyModeMaxDays) * 24 * time.Hour)
		}
		if cfg.LegacyModeSunset.IsZero() {
			return Config{}, fmt.Errorf("%s: legacy mode requires sunset", invalidConfigPrefix)
		}
		if time.Now().After(cfg.LegacyModeSunset) {
			return Config{}, fmt.Errorf("%s: legacy mode sunset reached", invalidConfigPrefix)
		}
	}
	if cfg.Obfuscator == nil {
		return Config{}, fmt.Errorf("%s: obfuscation required", invalidConfigPrefix)
	}
	obfAdapter, ok := cfg.Obfuscator.(*AWGObfuscator)
	if !ok || obfAdapter == nil || !obfAdapter.Enabled() {
		return Config{}, fmt.Errorf("%s: obfuscation required", invalidConfigPrefix)
	}
	overhead := obfAdapter.Framer().Config().S4 + 4 + 2
	if cfg.TransportReplay {
		overhead += 8
	}
	maxBudget := cfg.Quic.MaxPacketSize - overhead
	if maxBudget < 1200 {
		return Config{}, fmt.Errorf("%s: max_packet_size too small for QUIC payload budget", invalidConfigPrefix)
	}
	if cfg.Quic.MaxPayload > 0 {
		if cfg.Quic.MaxPayload < 1200 {
			return Config{}, fmt.Errorf("%s: quic max_payload must be >= 1200", invalidConfigPrefix)
		}
		if cfg.Quic.MaxPayload > maxBudget {
			return Config{}, fmt.Errorf("%s: quic max_payload exceeds transport payload budget", invalidConfigPrefix)
		}
		if cfg.Quic.MaxPayload > 1452 {
			return Config{}, fmt.Errorf("%s: quic max_payload must be <= 1452", invalidConfigPrefix)
		}
	}
	effectivePayload := maxBudget
	if cfg.Quic.MaxPayload > 0 && cfg.Quic.MaxPayload < effectivePayload {
		effectivePayload = cfg.Quic.MaxPayload
	}
	headroom := maxBudget - effectivePayload
	if cfg.TransportPadding.Min > headroom {
		return Config{}, fmt.Errorf("%s: transport padding pad_min exceeds headroom (%d > %d); reduce pad_min or increase headroom (raise max_packet_size, lower s4, or lower quic.max_payload)", invalidConfigPrefix, cfg.TransportPadding.Min, headroom)
	}
	if cfg.TransportPadding.Max > headroom {
		slog.Warn("transport padding pad_max exceeds headroom, padding will clamp", "max", cfg.TransportPadding.Max, "headroom", headroom)
	}
	if cfg.TransportPadding.BurstMax > headroom {
		slog.Warn("transport padding pad_burst_max exceeds headroom, padding will clamp", "burst_max", cfg.TransportPadding.BurstMax, "headroom", headroom)
	}
	return cfg, nil
}

func newServerMetrics() *ServerMetrics {
	return &ServerMetrics{
		HandshakeLatency: metrics.NewLatencySampler(latencySampleSize),
	}
}

func (s *Server) startMetricsLogger(ctx context.Context) {
	if s.cfg.MetricsInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.cfg.MetricsInterval)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.logMetrics()
			}
		}
	}()
}

func (s *Server) logMetrics() {
	quantiles := s.metrics.HandshakeLatency.SnapshotQuantiles([]float64{0.95, 0.99})
	junk := s.metrics.JunkPackets.Load()
	sigMismatch := s.metrics.SignatureMismatch.Load()
	badInit := s.metrics.HandshakeBadInit.Load()
	decodeFail := s.metrics.DecodeFailures.Load()
	sigInvalid := int64(0)
	tsInvalid := int64(0)
	replayReject := int64(0)
	replayEvict := int64(0)
	mac1Invalid := int64(0)
	legacyMissing := int64(0)
	transportReplayReject := int64(0)
	rateLimitDrop := int64(0)
	padIn := int64(0)
	padOut := int64(0)
	padClamp := int64(0)
	padDrop := int64(0)
	if s.envMetrics != nil {
		junk = s.envMetrics.PreambleJunk.Load()
		sigMismatch = s.envMetrics.DropSignatureMismatch.Load()
		badInit = s.envMetrics.DropBadInitiation.Load()
		decodeFail = s.envMetrics.DropDecodeFailure.Load()
		sigInvalid = s.envMetrics.SigContentInvalid.Load()
		tsInvalid = s.envMetrics.TimestampInvalid.Load()
		replayReject = s.envMetrics.ReplayReject.Load()
		replayEvict = s.envMetrics.ReplayCacheEvictions.Load()
		mac1Invalid = s.envMetrics.Mac1Invalid.Load()
		legacyMissing = s.envMetrics.LegacyTimestampMissing.Load()
		transportReplayReject = s.envMetrics.TransportReplayReject.Load()
		rateLimitDrop = s.envMetrics.RateLimitDrop.Load()
		padIn = s.envMetrics.TransportPaddingIn.Load()
		padOut = s.envMetrics.TransportPaddingOut.Load()
		padClamp = s.envMetrics.TransportPaddingClamped.Load()
		padDrop = s.envMetrics.TransportPaddingDropped.Load()
	}
	slog.Info("proxy metrics",
		"active", s.metrics.ActiveConns.Load(),
		"hs_ok", s.metrics.HandshakeSuccess.Load(),
		"hs_fail", s.metrics.HandshakeFailures.Load(),
		"reconnects", s.metrics.Reconnects.Load(),
		"bytes_in", s.metrics.BytesIn.Load(),
		"bytes_out", s.metrics.BytesOut.Load(),
		"junk", junk,
		"sig_mismatch", sigMismatch,
		"sig_invalid", sigInvalid,
		"ts_invalid", tsInvalid,
		"replay_reject", replayReject,
		"replay_evict", replayEvict,
		"mac1_invalid", mac1Invalid,
		"legacy_missing", legacyMissing,
		"rate_limit", rateLimitDrop,
		"transport_replay", transportReplayReject,
		"bad_init", badInit,
		"decode_fail", decodeFail,
		"pad_in", padIn,
		"pad_out", padOut,
		"pad_clamp", padClamp,
		"pad_drop", padDrop,
		"p95", quantiles[0.95],
		"p99", quantiles[0.99],
	)
}
