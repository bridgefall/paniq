package socks5daemon

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

const testTimeout = 2 * time.Second

func TestAuthFailure(t *testing.T) {
	server, addr, stop := startTestServer(t)
	defer stop()

	_ = server

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(testTimeout))

	_, err = conn.Write([]byte{socksVersion, 0x01, 0x00})
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if resp[1] != authMethodNoAccept {
		t.Fatalf("expected no acceptable method, got %d", resp[1])
	}
}

func startTestServer(t *testing.T) (*Server, string, func()) {
	t.Helper()

	cfg := Config{
		ListenAddr:       "127.0.0.1:0",
		ProxyAddr:        "127.0.0.1:1",
		Username:         "user",
		Password:         "pass",
		WorkerCount:      2,
		MaxConnections:   8,
		HandshakeTimeout: testTimeout,
		DialTimeout:      testTimeout,
		AcceptTimeout:    200 * time.Millisecond,
		Obfuscation: ObfConfig{
			S1: 0, S2: 0, S3: 0, S4: 0,
			H1: "100", H2: "200", H3: "300", H4: "400",
		},
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = server.Serve(ctx)
	}()

	select {
	case <-server.Ready():
	case <-time.After(testTimeout):
		cancel()
		t.Fatalf("server did not start")
	}

	addr := server.Addr().String()
	return server, addr, func() {
		cancel()
	}
}

func socks5Handshake(conn net.Conn, username string, password string) error {
	if _, err := conn.Write([]byte{socksVersion, 0x01, authMethodUserPass}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != authMethodUserPass {
		return io.ErrUnexpectedEOF
	}

	userLen := len(username)
	passLen := len(password)
	buf := make([]byte, 0, 3+userLen+passLen)
	buf = append(buf, userPassVersion, byte(userLen))
	buf = append(buf, []byte(username)...)
	buf = append(buf, byte(passLen))
	buf = append(buf, []byte(password)...)
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		return err
	}
	if authResp[1] != 0x00 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func socks5Connect(conn net.Conn, address string) error {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	ip := net.ParseIP(host).To4()
	if ip == nil {
		return io.ErrUnexpectedEOF
	}

	buf := make([]byte, 0, 10)
	buf = append(buf, socksVersion, cmdConnect, 0x00, addrTypeIPv4)
	buf = append(buf, ip...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	buf = append(buf, portBytes...)

	if _, err := conn.Write(buf); err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	resp := make([]byte, 4)
	if _, err := io.ReadFull(reader, resp); err != nil {
		return err
	}
	if resp[1] != replySuccess {
		return io.ErrUnexpectedEOF
	}

	_, err = readAddress(reader, resp[3])
	if err != nil {
		return err
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBuf); err != nil {
		return err
	}

	return nil
}
