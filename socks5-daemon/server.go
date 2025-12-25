package socks5daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"strings"

	"log/slog"

	"github.com/bridgefall/paniq/commons/metrics"
	"github.com/bridgefall/paniq/envelope"
	"github.com/bridgefall/paniq/obf"
	"github.com/bridgefall/paniq/profile"
)

const (
	socksVersion           = 0x05
	authMethodNoAuth       = 0x00
	authMethodUserPass     = 0x02
	authMethodNoAccept     = 0xFF
	userPassVersion        = 0x01
	proxyVersion           = 0x01
	replySuccess           = 0x00
	replyGeneralFailure    = 0x01
	replyCommandNotSupp    = 0x07
	replyAddressNotSupp    = 0x08
	cmdConnect             = 0x01
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

// Config defines the SOCKS5 server configuration.
type Config struct {
	ListenAddr           string
	ProxyAddr            string
	Username             string
	Password             string
	WorkerCount          int
	MaxConnections       int
	HandshakeTimeout     time.Duration
	HandshakeAttempts    int
	Quic                 QuicConfig
	DialTimeout          time.Duration
	AcceptTimeout        time.Duration
	IdleTimeout          time.Duration
	MetricsInterval      time.Duration
	LogLevel             string
	PreambleDelay        time.Duration
	PreambleJitter       time.Duration
	Obfuscation          ObfConfig
	Mac1Key              *[32]byte
	ServerPublicKey      *[32]byte
	EncryptedTimestamp   bool
	TransportReplay      bool
	TransportReplayLimit uint64
	TransportPadding     profile.PaddingPolicy
}

// QuicConfig defines QUIC transport settings.
type QuicConfig struct {
	MaxPacketSize int
	MaxPayload    int
	KeepAlive     time.Duration
	IdleTimeout   time.Duration
	MaxStreams    int
}

// ServerMetrics captures SOCKS5 daemon metrics.
type ServerMetrics struct {
	ActiveConns       metrics.Gauge
	AuthFailures      metrics.Counter
	HandshakeFailures metrics.Counter
	HandshakeSuccess  metrics.Counter
	Reconnects        metrics.Counter
	BytesIn           metrics.Counter
	BytesOut          metrics.Counter
	ProxyDecodeFail   metrics.Counter
	ProxyRespBad      metrics.Counter
	HandshakeTimeouts metrics.Counter
	HandshakeLatency  *metrics.LatencySampler
}

// Server implements a minimal SOCKS5 daemon with optional auth.
type Server struct {
	cfg        Config
	listener   net.Listener
	connCh     chan net.Conn
	sema       chan struct{}
	readyCh    chan struct{}
	wg         sync.WaitGroup
	mu         sync.RWMutex
	metrics    *ServerMetrics
	framer     *obf.Framer
	envMetrics *envelope.Metrics
	quicMu     sync.Mutex
	quicConn   quicConnection
	quicPC     net.PacketConn
}

// NewServer validates configuration and returns a new Server instance.
func NewServer(cfg Config) (*Server, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}

	framer, err := obf.NewFramer(normalized.Obfuscation.ToObfConfig())
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:     normalized,
		connCh:  make(chan net.Conn, normalized.MaxConnections),
		sema:    make(chan struct{}, normalized.MaxConnections),
		readyCh: make(chan struct{}),
		metrics: newServerMetrics(),
		framer:  framer,
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
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Serve runs the server until the context is canceled.
func (s *Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.listener = listener
	close(s.readyCh)
	s.mu.Unlock()
	s.logTransportInfo()

	for i := 0; i < s.cfg.WorkerCount; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}
	s.startMetricsLogger(ctx)

	acceptErr := s.acceptLoop(ctx)
	_ = listener.Close()
	close(s.connCh)
	s.wg.Wait()
	return acceptErr
}

func (s *Server) logTransportInfo() {
	if s.framer == nil {
		return
	}
	s4 := s.framer.Config().S4
	overhead := s4 + 4 + 2
	if s.cfg.TransportReplay {
		overhead += 8
	}
	maxPacket := s.cfg.Quic.MaxPacketSize
	budget := maxPacket - overhead
	effectivePayload := budget
	maxPayload := s.cfg.Quic.MaxPayload
	if maxPayload > 0 && maxPayload < effectivePayload {
		effectivePayload = maxPayload
	}
	headroom := budget - effectivePayload
	mtuIPv6Risk := maxPacket > 1232
	slog.Info("transport config",
		"max_packet", maxPacket,
		"max_payload", maxPayload,
		"effective_payload", effectivePayload,
		"budget", budget,
		"overhead", overhead,
		"s4", s4,
		"replay", s.cfg.TransportReplay,
		"pad_min", s.cfg.TransportPadding.Min,
		"pad_max", s.cfg.TransportPadding.Max,
		"burst_min", s.cfg.TransportPadding.BurstMin,
		"burst_max", s.cfg.TransportPadding.BurstMax,
		"burst_prob", s.cfg.TransportPadding.BurstProb,
		"headroom", headroom,
		"mtu_ipv6_risk", mtuIPv6Risk,
	)
}

func (s *Server) acceptLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			if err := tcpListener.SetDeadline(time.Now().Add(s.cfg.AcceptTimeout)); err != nil {
				return err
			}
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}

		select {
		case s.sema <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}

		s.metrics.Reconnects.Add(1)

		select {
		case s.connCh <- conn:
			continue
		case <-ctx.Done():
			_ = conn.Close()
			<-s.sema
			return nil
		default:
			_ = conn.Close()
			<-s.sema
		}
	}
}

func (s *Server) worker(ctx context.Context) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case conn, ok := <-s.connCh:
			if !ok {
				return
			}
			if err := s.handleConn(ctx, conn); err != nil {
				_ = conn.Close()
			}
			select {
			case <-s.sema:
			default:
			}
		}
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	start := time.Now()
	s.metrics.ActiveConns.Inc()
	defer s.metrics.ActiveConns.Dec()

	counted := newCountingConn(conn, &s.metrics.BytesIn, &s.metrics.BytesOut)
	if err := conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout)); err != nil {
		return err
	}

	if err := s.negotiate(counted); err != nil {
		s.metrics.HandshakeFailures.Add(1)
		slog.Debug("socks handshake negotiate failed", "remote", conn.RemoteAddr().String(), "err", err)
		return err
	}
	if err := s.authenticate(counted); err != nil {
		s.metrics.HandshakeFailures.Add(1)
		slog.Debug("socks auth failed", "remote", conn.RemoteAddr().String(), "err", err)
		return err
	}

	req, err := readRequest(counted)
	if err != nil {
		_ = writeReply(counted, replyGeneralFailure, addrTypeIPv4, []byte{0, 0, 0, 0}, 0)
		s.metrics.HandshakeFailures.Add(1)
		return err
	}
	if req.command != cmdConnect {
		_ = writeReply(counted, replyCommandNotSupp, addrTypeIPv4, []byte{0, 0, 0, 0}, 0)
		s.metrics.HandshakeFailures.Add(1)
		slog.Debug("socks unsupported command", "remote", conn.RemoteAddr().String(), "cmd", req.command)
		return fmt.Errorf("unsupported command: %d", req.command)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}

	stream, err := s.connectProxyQUIC(ctx, req.address)
	if err != nil {
		_ = writeReply(counted, replyGeneralFailure, addrTypeIPv4, []byte{0, 0, 0, 0}, 0)
		s.metrics.HandshakeFailures.Add(1)
		slog.Debug("socks proxy connect failed", "target", req.address, "err", err)
		return err
	}
	defer stream.Close()

	if err := writeReply(counted, replySuccess, addrTypeIPv4, []byte{0, 0, 0, 0}, 0); err != nil {
		s.metrics.HandshakeFailures.Add(1)
		return err
	}

	s.metrics.HandshakeSuccess.Add(1)
	s.metrics.HandshakeLatency.Add(time.Since(start))
	slog.Debug("socks connect ok", "remote", conn.RemoteAddr().String(), "target", req.address)

	return s.relayQUIC(ctx, counted, stream)
}

func (s *Server) negotiate(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socksVersion {
		return fmt.Errorf("unsupported socks version: %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	authRequired := s.cfg.Username != "" || s.cfg.Password != ""
	if authRequired {
		if !containsMethod(methods, authMethodUserPass) {
			_, _ = conn.Write([]byte{socksVersion, authMethodNoAccept})
			return errors.New("no acceptable auth method")
		}
		_, err := conn.Write([]byte{socksVersion, authMethodUserPass})
		return err
	}

	if !containsMethod(methods, authMethodNoAuth) {
		_, _ = conn.Write([]byte{socksVersion, authMethodNoAccept})
		return errors.New("no acceptable method (no-auth not offered)")
	}
	_, err := conn.Write([]byte{socksVersion, authMethodNoAuth})
	return err
}

func (s *Server) authenticate(conn net.Conn) error {
	if s.cfg.Username == "" && s.cfg.Password == "" {
		return nil
	}
	ver := make([]byte, 2)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return err
	}
	if ver[0] != userPassVersion {
		_ = writeAuthReply(conn, 0x01)
		return fmt.Errorf("unsupported auth version: %d", ver[0])
	}

	userLen := int(ver[1])
	username := make([]byte, userLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	passLen := int(plen[0])
	password := make([]byte, passLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	if string(username) != s.cfg.Username || string(password) != s.cfg.Password {
		s.metrics.AuthFailures.Add(1)
		_ = writeAuthReply(conn, 0x01)
		return errors.New("invalid credentials")
	}

	return writeAuthReply(conn, 0x00)
}

type request struct {
	command byte
	address string
}

func readRequest(conn net.Conn) (request, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return request{}, err
	}
	if header[0] != socksVersion || header[2] != 0x00 {
		return request{}, errors.New("invalid request header")
	}

	atyp := header[3]
	host, err := readAddress(conn, atyp)
	if err != nil {
		return request{}, err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return request{}, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return request{
		command: header[1],
		address: net.JoinHostPort(host, strconv.Itoa(int(port))),
	}, nil
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

func readAddressBytes(reader io.Reader, atyp byte) ([]byte, error) {
	switch atyp {
	case addrTypeIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		return buf, nil
	case addrTypeIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		return buf, nil
	case addrTypeDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(reader, lenBuf); err != nil {
			return nil, err
		}
		domainLen := int(lenBuf[0])
		buf := make([]byte, domainLen)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		out := make([]byte, 0, 1+domainLen)
		out = append(out, byte(domainLen))
		out = append(out, buf...)
		return out, nil
	default:
		return nil, errors.New("unsupported address type")
	}
}

func buildProxyRequestPayload(address string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, 8+len(host))
	buf = append(buf, proxyVersion)

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, addrTypeIPv4)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, addrTypeIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("domain name too long")
		}
		buf = append(buf, addrTypeDomain, byte(len(host)))
		buf = append(buf, []byte(host)...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	buf = append(buf, portBytes...)
	return buf, nil
}

func readProxyReply(reader io.Reader) (byte, byte, []byte, uint16, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, 0, nil, 0, err
	}
	if header[0] != proxyVersion {
		return 0, 0, nil, 0, fmt.Errorf("unsupported proxy version: %d", header[0])
	}
	status := header[1]
	atyp := header[2]
	addrBytes, err := readAddressBytes(reader, atyp)
	if err != nil {
		return 0, 0, nil, 0, err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return 0, 0, nil, 0, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return status, atyp, addrBytes, port, nil
}

func parseProxyResponsePayload(payload []byte) (byte, byte, []byte, uint16, error) {
	if len(payload) < 2 {
		return 0, 0, nil, 0, io.ErrUnexpectedEOF
	}
	status := payload[0]
	atyp := payload[1]
	reader := bytes.NewReader(payload[2:])
	addrBytes, err := readAddressBytes(reader, atyp)
	if err != nil {
		return 0, 0, nil, 0, err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return 0, 0, nil, 0, err
	}
	if reader.Len() != 0 {
		return 0, 0, nil, 0, fmt.Errorf("extra bytes in proxy response payload")
	}
	port := binary.BigEndian.Uint16(portBytes)
	return status, atyp, addrBytes, port, nil
}

func writeAuthReply(conn net.Conn, status byte) error {
	_, err := conn.Write([]byte{userPassVersion, status})
	return err
}

func writeReply(conn net.Conn, reply byte, atyp byte, addr []byte, port uint16) error {
	buf := make([]byte, 0, 6+len(addr))
	buf = append(buf, socksVersion, reply, 0x00, atyp)
	buf = append(buf, addr...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf = append(buf, portBytes...)
	_, err := conn.Write(buf)
	return err
}

func containsMethod(methods []byte, target byte) bool {
	for _, method := range methods {
		if method == target {
			return true
		}
	}
	return false
}

func normalizeConfig(cfg Config) (Config, error) {
	if cfg.ListenAddr == "" {
		return Config{}, fmt.Errorf("%s: listen address required", invalidConfigPrefix)
	}
	if (cfg.Username == "") != (cfg.Password == "") {
		return Config{}, fmt.Errorf("%s: username/password must both be set or both empty", invalidConfigPrefix)
	}
	if len(cfg.Username) > 255 || len(cfg.Password) > 255 {
		return Config{}, fmt.Errorf("%s: username/password too long", invalidConfigPrefix)
	}
	if cfg.ProxyAddr == "" {
		return Config{}, fmt.Errorf("%s: proxy address required", invalidConfigPrefix)
	}
	if _, _, err := net.SplitHostPort(cfg.ProxyAddr); err != nil {
		return Config{}, fmt.Errorf("%s: invalid proxy address", invalidConfigPrefix)
	}
	if !cfg.Obfuscation.Enabled() {
		return Config{}, fmt.Errorf("%s: obfuscation required", invalidConfigPrefix)
	}
	if err := cfg.Obfuscation.ToObfConfig().Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: obfuscation config invalid: %w", invalidConfigPrefix, err)
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
	if cfg.HandshakeAttempts <= 0 {
		cfg.HandshakeAttempts = 3
	}
	if cfg.PreambleDelay < 0 {
		cfg.PreambleDelay = 0
	}
	if cfg.PreambleJitter < 0 {
		cfg.PreambleJitter = 0
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
	overhead := cfg.Obfuscation.S4 + 4 + 2
	if cfg.Obfuscation.TransportReplay {
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
	if cfg.Obfuscation.ServerPublicKey != "" {
		pubKey, err := obf.DecodeKeyBase64(cfg.Obfuscation.ServerPublicKey)
		if err != nil {
			return Config{}, fmt.Errorf("%s: server public key invalid: %w", invalidConfigPrefix, err)
		}
		mac1Key, err := obf.DeriveMac1Key(pubKey)
		if err != nil {
			return Config{}, fmt.Errorf("%s: mac1 derivation failed: %w", invalidConfigPrefix, err)
		}
		cfg.Mac1Key = &mac1Key
		cfg.ServerPublicKey = &pubKey
		enabled := resolveBoolPtr(cfg.Obfuscation.EncryptedTimestamp, true)
		cfg.EncryptedTimestamp = enabled
	}
	if cfg.EncryptedTimestamp && cfg.ServerPublicKey == nil {
		return Config{}, fmt.Errorf("%s: encrypted_timestamp needs server public key", invalidConfigPrefix)
	}
	cfg.TransportReplay = cfg.Obfuscation.TransportReplay
	cfg.TransportReplayLimit = cfg.Obfuscation.TransportReplayLimit
	return cfg, nil
}

func resolveBoolPtr(val *bool, fallback bool) bool {
	if val == nil {
		return fallback
	}
	return *val
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
	var padIn, padOut, padClamp, padDrop int64
	var junk, sigMismatch, sigInvalid, tsInvalid, replayReject, replayEvict, mac1Invalid, legacyMissing, rateLimitDrop, transportReplayReject, badInit, decodeFail int64
	if s.envMetrics != nil {
		padIn = s.envMetrics.TransportPaddingIn.Load()
		padOut = s.envMetrics.TransportPaddingOut.Load()
		padClamp = s.envMetrics.TransportPaddingClamped.Load()
		padDrop = s.envMetrics.TransportPaddingDropped.Load()
		junk = s.envMetrics.PreambleJunk.Load()
		sigMismatch = s.envMetrics.DropSignatureMismatch.Load()
		sigInvalid = s.envMetrics.SigContentInvalid.Load()
		tsInvalid = s.envMetrics.TimestampInvalid.Load()
		replayReject = s.envMetrics.ReplayReject.Load()
		replayEvict = s.envMetrics.ReplayCacheEvictions.Load()
		mac1Invalid = s.envMetrics.Mac1Invalid.Load()
		legacyMissing = s.envMetrics.LegacyTimestampMissing.Load()
		rateLimitDrop = s.envMetrics.RateLimitDrop.Load()
		transportReplayReject = s.envMetrics.TransportReplayReject.Load()
		badInit = s.envMetrics.DropBadInitiation.Load()
		decodeFail = s.envMetrics.DropDecodeFailure.Load()
	}
	slog.Info("proxy metrics",
		"active", s.metrics.ActiveConns.Load(),
		"auth_fail", s.metrics.AuthFailures.Load(),
		"hs_ok", s.metrics.HandshakeSuccess.Load(),
		"hs_fail", s.metrics.HandshakeFailures.Load(),
		"reconnects", s.metrics.Reconnects.Load(),
		"bytes_in", s.metrics.BytesIn.Load(),
		"bytes_out", s.metrics.BytesOut.Load(),
		"proxy_decode_fail", s.metrics.ProxyDecodeFail.Load(),
		"proxy_resp_bad", s.metrics.ProxyRespBad.Load(),
		"hs_timeouts", s.metrics.HandshakeTimeouts.Load(),
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

func (s *Server) sleepPreamble() {
	delay := s.cfg.PreambleDelay
	if delay <= 0 && s.cfg.PreambleJitter <= 0 {
		return
	}
	if s.cfg.PreambleJitter > 0 {
		jitter, err := randDuration(s.cfg.PreambleJitter)
		if err == nil {
			delay += jitter
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

type countingConn struct {
	net.Conn
	bytesIn  *metrics.Counter
	bytesOut *metrics.Counter
}

func newCountingConn(conn net.Conn, bytesIn *metrics.Counter, bytesOut *metrics.Counter) net.Conn {
	return &countingConn{
		Conn:     conn,
		bytesIn:  bytesIn,
		bytesOut: bytesOut,
	}
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.bytesIn.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.bytesOut.Add(int64(n))
	}
	return n, err
}
