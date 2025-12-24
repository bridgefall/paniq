//go:build integration

package socks5daemon

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	proxyserver "github.com/bridgefall/paniq/proxy-server"
)

func TestSocks5ProxyObfuscated(t *testing.T) {
	obfCfg := ObfConfig{
		S1: 0, S2: 0, S3: 0, S4: 0,
		H1: "100", H2: "200", H3: "300", H4: "400",
	}

	proxyObfCfg := proxyserver.ObfConfig{
		S1: 0, S2: 0, S3: 0, S4: 0,
		H1: "100", H2: "200", H3: "300", H4: "400",
	}
	adapter, err := proxyserver.NewAWGObfuscator(proxyObfCfg)
	if err != nil {
		t.Fatalf("new proxy obfuscator failed: %v", err)
	}

	proxyCfg := proxyserver.Config{
		ListenAddr:       "127.0.0.1:0",
		WorkerCount:      2,
		MaxConnections:   8,
		HandshakeTimeout: testTimeout,
		DialTimeout:      testTimeout,
		AcceptTimeout:    200 * time.Millisecond,
		IdleTimeout:      testTimeout,
		Obfuscator:       adapter,
	}

	_, proxyAddr, stopProxy := startProxyServer(t, proxyCfg)
	defer stopProxy()

	socksCfg := Config{
		ListenAddr:       "127.0.0.1:0",
		ProxyAddr:        proxyAddr,
		Username:         "user",
		Password:         "pass",
		WorkerCount:      2,
		MaxConnections:   8,
		HandshakeTimeout: testTimeout,
		DialTimeout:      testTimeout,
		AcceptTimeout:    200 * time.Millisecond,
		Obfuscation:      obfCfg,
	}

	_, socksAddr, stopSocks := startSocksServer(t, socksCfg)
	defer stopSocks()

	echoAddr, shutdownEcho := startEchoServer(t)
	defer shutdownEcho()

	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(testTimeout))

	if err := socks5Handshake(conn, "user", "pass"); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if err := socks5Connect(conn, echoAddr); err != nil {
		t.Fatalf("connect failed: %v", err)
	}

	payload := []byte("ping")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	resp := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(resp) != string(payload) {
		t.Fatalf("unexpected response: %q", resp)
	}
}

func startProxyServer(t *testing.T, cfg proxyserver.Config) (*proxyserver.Server, string, func()) {
	t.Helper()

	server, err := proxyserver.NewServer(cfg)
	if err != nil {
		t.Fatalf("new proxy server failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = server.Serve(ctx)
	}()

	select {
	case <-server.Ready():
	case <-time.After(testTimeout):
		cancel()
		t.Fatalf("proxy server did not start")
	}

	addr := server.Addr().String()
	return server, addr, func() {
		cancel()
	}
}

func startSocksServer(t *testing.T, cfg Config) (*Server, string, func()) {
	t.Helper()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new socks server failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = server.Serve(ctx)
	}()

	select {
	case <-server.Ready():
	case <-time.After(testTimeout):
		cancel()
		t.Fatalf("socks server did not start")
	}

	addr := server.Addr().String()
	return server, addr, func() {
		cancel()
	}
}
