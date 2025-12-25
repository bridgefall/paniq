package socks5daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/bridgefall/paniq/envelope"
	"github.com/bridgefall/paniq/obf"
	"github.com/quic-go/quic-go"
)

const quicALPN = "bridgefall-paniq"

type quicConnection interface {
	OpenStreamSync(ctx context.Context) (quic.Stream, error)
	Context() context.Context
	CloseWithError(code quic.ApplicationErrorCode, msg string) error
}

func (s *Server) connectProxyQUIC(ctx context.Context, address string) (quic.Stream, error) {
	conn, err := s.getQUICConn(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := s.openProxyStream(ctx, conn, address)
	if err == nil {
		return stream, nil
	}
	s.resetQUICConn("open stream failed")
	conn, dialErr := s.getQUICConn(ctx)
	if dialErr != nil {
		return nil, err
	}
	return s.openProxyStream(ctx, conn, address)
}

func (s *Server) writeProxyRequest(stream quic.Stream, address string) error {
	payload, err := buildProxyRequestPayload(address)
	if err != nil {
		return err
	}
	if s.cfg.HandshakeTimeout > 0 {
		setStreamDeadline(stream, time.Now().Add(s.cfg.HandshakeTimeout))
	}
	if _, err := stream.Write(payload); err != nil {
		return err
	}
	return nil
}

func (s *Server) openProxyStream(
	ctx context.Context,
	conn quicConnection,
	address string,
) (quic.Stream, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.writeProxyRequest(stream, address); err != nil {
		_ = stream.Close()
		return nil, err
	}

	status, _, _, _, err := readProxyReply(stream)
	if err != nil {
		if isTimeout(err) {
			s.metrics.HandshakeTimeouts.Add(1)
		}
		_ = stream.Close()
		return nil, err
	}
	if status != replySuccess {
		_ = stream.Close()
		return nil, fmt.Errorf("proxy rejected request: %d", status)
	}
	setStreamDeadline(stream, time.Time{})
	return stream, nil
}

func (s *Server) relayQUIC(ctx context.Context, client net.Conn, stream quic.Stream) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	go func() {
		buf := make([]byte, maxDatagramSize)
		for {
			if s.cfg.IdleTimeout > 0 {
				setStreamReadDeadline(stream, time.Now().Add(s.cfg.IdleTimeout))
			}
			n, err := stream.Read(buf)
			if n > 0 {
				_, _ = client.Write(buf[:n])
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
				_ = client.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
			}
			n, err := client.Read(buf)
			if n > 0 {
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
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) getQUICConn(ctx context.Context) (quicConnection, error) {
	s.quicMu.Lock()
	defer s.quicMu.Unlock()

	if s.quicConn != nil && s.quicConn.Context().Err() == nil {
		return s.quicConn, nil
	}
	if s.quicConn != nil {
		_ = s.quicConn.CloseWithError(0, "reconnect")
		s.quicConn = nil
	}
	if s.quicPC != nil {
		_ = s.quicPC.Close()
		s.quicPC = nil
	}

	conn, pc, err := s.dialQUIC(ctx)
	if err != nil {
		return nil, err
	}
	s.quicConn = conn
	s.quicPC = pc
	go func(c quicConnection, pc net.PacketConn) {
		<-c.Context().Done()
		_ = pc.Close()
	}(conn, pc)
	return conn, nil
}

func (s *Server) dialQUIC(ctx context.Context) (quicConnection, net.PacketConn, error) {
	if s.cfg.ProxyAddr == "" {
		return nil, nil, errors.New("proxy address required for QUIC transport")
	}
	remote, err := net.ResolveUDPAddr("udp", s.cfg.ProxyAddr)
	if err != nil {
		return nil, nil, err
	}
	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, nil, err
	}
	opts := envelope.HandshakeOptions{
		Attempts:           s.cfg.HandshakeAttempts,
		Timeout:            s.cfg.HandshakeTimeout,
		PreambleDelay:      s.cfg.PreambleDelay,
		PreambleJitter:     s.cfg.PreambleJitter,
		Mac1Key:            s.cfg.Mac1Key,
		EncryptedTimestamp: s.cfg.EncryptedTimestamp,
		ServerPublicKey:    s.cfg.ServerPublicKey,
	}
	if err := envelope.ClientHandshake(ctx, pc, remote, s.framer, opts, nil); err != nil {
		_ = pc.Close()
		return nil, nil, err
	}
	s.envMetrics = &envelope.Metrics{}
	// Use nil logger to use slog.Default() dynamically
	logInterval := 10 * time.Second
	envConn := envelope.NewClientConn(pc, s.framer, envelope.ClientOptions{
		Remote:               remote,
		MaxPacketSize:        s.cfg.Quic.MaxPacketSize,
		Metrics:              s.envMetrics,
		Logger:               nil, // Use logging default dynamically
		LogInterval:          logInterval,
		TransportReplay:      s.cfg.TransportReplay,
		TransportReplayLimit: s.cfg.TransportReplayLimit,
		PaddingPolicy:        s.cfg.TransportPadding,
	})
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{quicALPN},
	}
	quicConf := &quic.Config{
		MaxIncomingStreams:    int64(s.cfg.Quic.MaxStreams),
		MaxIncomingUniStreams: 0,
		KeepAlivePeriod:       s.cfg.Quic.KeepAlive,
		MaxIdleTimeout:        s.cfg.Quic.IdleTimeout,
	}
	applyQUICPacketSizing(quicConf, s.cfg.Quic.MaxPacketSize, s.framer, s.cfg.TransportReplay, s.cfg.Quic.MaxPayload)
	conn, err := quic.Dial(ctx, envConn, remote, tlsConf, quicConf)
	if err != nil {
		_ = pc.Close()
		return nil, nil, err
	}
	return conn, pc, nil
}

func (s *Server) resetQUICConn(reason string) {
	s.quicMu.Lock()
	defer s.quicMu.Unlock()

	if s.quicConn != nil {
		_ = s.quicConn.CloseWithError(0, reason)
		s.quicConn = nil
	}
	if s.quicPC != nil {
		_ = s.quicPC.Close()
		s.quicPC = nil
	}
}

func setStreamReadDeadline(stream quic.Stream, t time.Time) {
	if setter, ok := any(stream).(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = setter.SetReadDeadline(t)
	}
}

func setStreamDeadline(stream quic.Stream, t time.Time) {
	if setter, ok := any(stream).(interface{ SetDeadline(time.Time) error }); ok {
		_ = setter.SetDeadline(t)
		return
	}
	if setter, ok := any(stream).(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = setter.SetReadDeadline(t)
	}
	if setter, ok := any(stream).(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = setter.SetWriteDeadline(t)
	}
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
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
