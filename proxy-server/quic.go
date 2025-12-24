package proxyserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/bridgefall/paniq/envelope"
	"github.com/bridgefall/paniq/obf"
	"github.com/quic-go/quic-go"
)

const quicALPN = "bridgefall-transport"

func (s *Server) serveQUIC(ctx context.Context) error {
	udpConn, err := net.ListenPacket("udp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	framer, err := s.requireFramer()
	if err != nil {
		_ = udpConn.Close()
		return err
	}
	s.envMetrics = &envelope.Metrics{}
	var logger *log.Logger
	logInterval := 10 * time.Second
	if s.cfg.LogLevel == "debug" {
		logger = log.Default()
		logInterval = time.Second
	}
	envConn := envelope.NewServerConn(udpConn, framer, envelope.ServerOptions{
		HandshakeTimeout:          s.cfg.HandshakeTimeout,
		MaxPacketSize:             s.cfg.Quic.MaxPacketSize,
		Metrics:                   s.envMetrics,
		SignatureValidate:         s.cfg.SignatureValidate,
		RequireTimestamp:          s.cfg.RequireTimestamp,
		EncryptedTimestamp:        s.cfg.EncryptedTimestamp,
		RequireEncryptedTimestamp: s.cfg.RequireEncryptedTimestamp,
		LegacyModeEnabled:         s.cfg.LegacyModeEnabled,
		LegacyModeSunset:          s.cfg.LegacyModeSunset,
		SkewSoft:                  s.cfg.SkewSoft,
		SkewHard:                  s.cfg.SkewHard,
		ReplayWindow:              s.cfg.ReplayWindow,
		ReplayCacheSize:           s.cfg.ReplayCacheSize,
		Mac1Key:                   s.cfg.Mac1Key,
		ServerPrivateKey:          s.cfg.ServerPrivateKey,
		TransportReplay:           s.cfg.TransportReplay,
		TransportReplayLimit:      s.cfg.TransportReplayLimit,
		RateLimitPPS:              s.cfg.RateLimitPPS,
		RateLimitBurst:            s.cfg.RateLimitBurst,
		Logger:                    logger,
		LogInterval:               logInterval,
		PaddingPolicy:             s.cfg.TransportPadding,
		Debug:                     s.cfg.LogLevel == "debug",
	})
	tlsConf, err := serverTLSConfig()
	if err != nil {
		_ = udpConn.Close()
		return err
	}
	quicConf := &quic.Config{
		MaxIncomingStreams:    int64(s.cfg.Quic.MaxStreams),
		MaxIncomingUniStreams: 0,
		KeepAlivePeriod:       s.cfg.Quic.KeepAlive,
		MaxIdleTimeout:        s.cfg.Quic.IdleTimeout,
	}
	applyQUICPacketSizing(quicConf, s.cfg.Quic.MaxPacketSize, framer, s.cfg.TransportReplay, s.cfg.Quic.MaxPayload)
	listener, err := quic.Listen(envConn, tlsConf, quicConf)
	if err != nil {
		_ = udpConn.Close()
		return err
	}

	s.mu.Lock()
	s.conn = udpConn
	close(s.readyCh)
	s.mu.Unlock()
	logTransportInfo(s.cfg, framer)

	s.startMetricsLogger(ctx)

	for {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			_ = udpConn.Close()
			s.wg.Wait()
			return nil
		default:
		}

		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				_ = listener.Close()
				_ = udpConn.Close()
				s.wg.Wait()
				return nil
			}
			return err
		}
		s.wg.Add(1)
		go s.handleQUICConn(ctx, conn)
	}
}

func logTransportInfo(cfg Config, framer *obf.Framer) {
	if framer == nil {
		return
	}
	s4 := framer.Config().S4
	overhead := s4 + 4 + 2
	if cfg.TransportReplay {
		overhead += 8
	}
	maxPacket := cfg.Quic.MaxPacketSize
	budget := maxPacket - overhead
	effectivePayload := budget
	maxPayload := cfg.Quic.MaxPayload
	if maxPayload > 0 && maxPayload < effectivePayload {
		effectivePayload = maxPayload
	}
	headroom := budget - effectivePayload
	mtuIPv6Risk := maxPacket > 1232
	log.Printf(
		"transport config max_packet=%d max_payload=%d effective_payload=%d budget=%d overhead=%d s4=%d replay=%t pad=[%d..%d] burst=[%d..%d] p=%.3f headroom=%d mtu_ipv6_risk=%t",
		maxPacket,
		maxPayload,
		effectivePayload,
		budget,
		overhead,
		s4,
		cfg.TransportReplay,
		cfg.TransportPadding.Min,
		cfg.TransportPadding.Max,
		cfg.TransportPadding.BurstMin,
		cfg.TransportPadding.BurstMax,
		cfg.TransportPadding.BurstProb,
		headroom,
		mtuIPv6Risk,
	)
}

func (s *Server) handleQUICConn(ctx context.Context, conn quic.Connection) {
	defer s.wg.Done()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.handleQUICStream(ctx, stream)
	}
}

func (s *Server) handleQUICStream(ctx context.Context, stream quic.Stream) {
	defer s.wg.Done()
	start := time.Now()
	s.metrics.ActiveConns.Inc()
	defer s.metrics.ActiveConns.Dec()
	defer stream.Close()
	s.metrics.Reconnects.Add(1)

	if s.cfg.HandshakeTimeout > 0 {
		setStreamReadDeadline(stream, time.Now().Add(s.cfg.HandshakeTimeout))
	}
	req, err := readRequest(stream)
	if err != nil {
		s.metrics.HandshakeFailures.Add(1)
		return
	}

	if s.cfg.Verbose {
		log.Printf("proxy dial upstream %s (quic)", req.address)
	}
	upstream, err := s.dial(ctx, req.address)
	if err != nil {
		_ = writeProxyReply(stream, statusFailure, addrTypeIPv4, []byte{0, 0, 0, 0}, 0)
		s.metrics.HandshakeFailures.Add(1)
		return
	}
	defer upstream.Close()

	atyp, addrBytes, port, err := addrToReply(upstream.LocalAddr())
	if err != nil {
		_ = writeProxyReply(stream, statusFailure, addrTypeIPv4, []byte{0, 0, 0, 0}, 0)
		s.metrics.HandshakeFailures.Add(1)
		return
	}
	if err := writeProxyReply(stream, statusSuccess, atyp, addrBytes, port); err != nil {
		s.metrics.HandshakeFailures.Add(1)
		return
	}

	setStreamReadDeadline(stream, time.Time{})
	s.metrics.HandshakeSuccess.Add(1)
	s.metrics.HandshakeLatency.Add(time.Since(start))

	errCh := make(chan error, 2)

	go func() {
		buf := make([]byte, maxDatagramSize)
		for {
			if s.cfg.IdleTimeout > 0 {
				setStreamReadDeadline(stream, time.Now().Add(s.cfg.IdleTimeout))
			}
			n, err := stream.Read(buf)
			if n > 0 {
				s.metrics.BytesIn.Add(int64(n))
				if _, err := upstream.Write(buf[:n]); err != nil {
					errCh <- err
					return
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, maxDatagramSize)
		for {
			if s.cfg.IdleTimeout > 0 {
				_ = upstream.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
			}
			n, err := upstream.Read(buf)
			if n > 0 {
				s.metrics.BytesOut.Add(int64(n))
				if _, err := stream.Write(buf[:n]); err != nil {
					errCh <- err
					return
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return
	case <-errCh:
		return
	}
}

func applyQUICPacketSizing(cfg *quic.Config, maxPacket int, framer *obf.Framer, transportReplay bool, maxPayload int) {
	if cfg == nil || framer == nil {
		return
	}
	overhead := framer.Config().S4 + 4 + 2
	if transportReplay {
		overhead += 8
	}
	maxBudget := maxPacket - overhead
	if maxBudget < 1200 {
		return
	}
	target := maxBudget
	if maxPayload > 0 && maxPayload < target {
		target = maxPayload
	}
	if target < 1200 {
		return
	}
	if target > 1452 {
		target = 1452
	}
	cfg.InitialPacketSize = uint16(target)
	cfg.DisablePathMTUDiscovery = true
}

func writeProxyReply(w io.Writer, status byte, atyp byte, addr []byte, port uint16) error {
	buf := make([]byte, 0, 6+len(addr))
	buf = append(buf, proxyVersion, status, atyp)
	buf = append(buf, addr...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf = append(buf, portBytes...)
	_, err := w.Write(buf)
	return err
}

func setStreamReadDeadline(stream quic.Stream, t time.Time) {
	if setter, ok := any(stream).(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = setter.SetReadDeadline(t)
	}
}

func serverTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  key,
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicALPN},
	}, nil
}
