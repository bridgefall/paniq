//go:build integration

package socks5daemon

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	proxyserver "github.com/bridgefall/paniq/internal/proxyserver"
)

func TestIntegrationQUIC(t *testing.T) {
	obfCfg := ObfConfig{
		H1: "1", H2: "2", H3: "3", H4: "4",
	}
	proxyObfCfg := proxyserver.ObfConfig{
		H1: "1", H2: "2", H3: "3", H4: "4",
	}
	adapter, err := proxyserver.NewAWGObfuscator(proxyObfCfg)
	if err != nil {
		t.Fatalf("new proxy obfuscator failed: %v", err)
	}

	proxyCfg := proxyserver.Config{
		ListenAddr:       "127.0.0.1:0",
		WorkerCount:      2,
		MaxConnections:   16,
		HandshakeTimeout: testTimeout,
		DialTimeout:      testTimeout,
		AcceptTimeout:    200 * time.Millisecond,
		IdleTimeout:      testTimeout,
		Obfuscator:       adapter,
		Quic: proxyserver.QuicConfig{
			MaxPacketSize: 1350,
			MaxPayload:    1200,
		},
	}

	_, proxyAddr, stopProxy := startProxyServer(t, proxyCfg)
	defer stopProxy()

	socksCfg := Config{
		ListenAddr:       "127.0.0.1:0",
		ProxyAddr:        proxyAddr,
		Username:         "user",
		Password:         "pass",
		WorkerCount:      2,
		MaxConnections:   16,
		HandshakeTimeout: testTimeout,
		DialTimeout:      testTimeout,
		AcceptTimeout:    200 * time.Millisecond,
		IdleTimeout:      testTimeout,
		Obfuscation:      obfCfg,
		Quic: QuicConfig{
			MaxPacketSize: 1350,
			MaxPayload:    1200,
		},
	}

	_, socksAddr, stopSocks := startSocksServer(t, socksCfg)
	defer stopSocks()

	httpAddr, stopHTTP := startHTTPServer(t)
	defer stopHTTP()

	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * testTimeout))

	if err := socks5Handshake(conn, "user", "pass"); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if err := socks5Connect(conn, httpAddr); err != nil {
		t.Fatalf("connect failed: %v", err)
	}

	host, _, err := net.SplitHostPort(httpAddr)
	if err != nil {
		t.Fatalf("split http addr failed: %v", err)
	}
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	body := string(resp)
	if !strings.Contains(body, "200 OK") || !strings.Contains(body, "ok") {
		t.Fatalf("unexpected response: %q", body)
	}
}

func startHTTPServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("http listen failed: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.Listener = ln
	srv.Start()
	return ln.Addr().String(), srv.Close
}
