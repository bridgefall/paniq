//go:build soak

package socks5daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bridgefall/transport/obf"
	vegeta "github.com/tsenart/vegeta/v12/lib"
	"golang.org/x/net/proxy"
)

func TestSoakObfuscatedQUIC(t *testing.T) {
	runSoak(t)
}

func runSoak(t *testing.T) {
	soakSeconds := envDuration("SOAK_SECONDS", 60*time.Second)
	if testing.Short() {
		soakSeconds = 5 * time.Second
	}

	rootDir := repoRoot(t)
	tmpDir := soakTempDir(t)

	httpPort := freeTCPPort(t)
	proxyPort := freeUDPPort(t)
	socksPort := freeTCPPort(t)

	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)

	payload := bytes.Repeat([]byte("a"), 1024*512)
	httpSrv := startHTTPServer(t, httpAddr, payload)
	defer httpSrv.Close()

	obfCfg := ObfConfig{
		Jc: 4, Jmin: 10, Jmax: 50,
		S1: 39, S2: 32, S3: 0, S4: 0,
		H1: "1662442204", H2: "793654571", H3: "468452595", H4: "1578142977",
		I1: "<t>",
	}
	privKey, pubKey := generateKeypair(t)
	privB64 := base64.StdEncoding.EncodeToString(privKey[:])
	pubB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	proxyCfgPath := filepath.Join(tmpDir, "proxy-server.json")
	verbose := envBool("SOAK_VERBOSE", false)
	writeJSONConfig(t, proxyCfgPath, map[string]any{
		"listen_addr":      proxyAddr,
		"workers":          8,
		"max_connections":  128,
		"dial_timeout":     "5s",
		"accept_timeout":   "500ms",
		"idle_timeout":     "2m",
		"metrics_interval": "10s",
		"verbose":          verbose,
	})

	socksCfgPath := filepath.Join(tmpDir, "socks5d.json")
	writeJSONConfig(t, socksCfgPath, map[string]any{
		"listen_addr":      socksAddr,
		"username":         "user",
		"password":         "pass",
		"workers":          100,
		"max_connections":  1000,
		"dial_timeout":     "5s",
		"accept_timeout":   "500ms",
		"idle_timeout":     "2m",
		"metrics_interval": "10s",
		"verbose":          verbose,
	})

	profilePath := filepath.Join(tmpDir, "profile.json")
	writeJSONConfig(t, profilePath, map[string]any{
		"proxy_addr":         proxyAddr,
		"handshake_timeout":  "5s",
		"handshake_attempts": 3,
		"quic": map[string]any{
			"max_packet_size": 1350,
			"keepalive":       "20s",
			"idle_timeout":    "2m",
			"max_streams":     256,
		},
		"obfuscation": map[string]any{
			"jc": obfCfg.Jc, "jmin": obfCfg.Jmin, "jmax": obfCfg.Jmax,
			"s1": obfCfg.S1, "s2": obfCfg.S2, "s3": obfCfg.S3, "s4": obfCfg.S4,
			"h1": obfCfg.H1, "h2": obfCfg.H2, "h3": obfCfg.H3, "h4": obfCfg.H4,
			"i1":                          obfCfg.I1,
			"server_private_key":          privB64,
			"server_public_key":           pubB64,
			"encrypted_timestamp":         true,
			"require_encrypted_timestamp": true,
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyLog := filepath.Join(tmpDir, "proxy.log")
	socksLog := filepath.Join(tmpDir, "socks.log")

	proxyExit := startCmd(
		t,
		ctx,
		filepath.Join(rootDir, "proxy-server"),
		[]string{"go", "run", "./cmd/proxy-server", "--config", proxyCfgPath, "--profile", profilePath},
		proxyLog,
	)
	if err := waitForTCP(httpAddr, 10*time.Second); err != nil {
		t.Fatalf("http server not ready: %v", err)
	}

	socksExit := startCmd(
		t,
		ctx,
		filepath.Join(rootDir, "socks5-daemon"),
		[]string{"go", "run", "./cmd/socks5d", "--config", socksCfgPath, "--profile", profilePath},
		socksLog,
	)
	if err := waitForTCP(socksAddr, 10*time.Second); err != nil {
		t.Fatalf(
			"socks5 not ready: %v\nproxy log:\n%s\nsocks log:\n%s",
			err,
			readLog(proxyLog),
			readLog(socksLog),
		)
	}
	select {
	case err := <-proxyExit:
		if err != nil {
			t.Fatalf("proxy exited early: %v\nproxy log:\n%s", err, readLog(proxyLog))
		}
	default:
	}
	select {
	case err := <-socksExit:
		if err != nil {
			t.Fatalf("socks exited early: %v\nsocks log:\n%s", err, readLog(socksLog))
		}
	default:
	}

	client := socksHTTPClient(t, socksAddr, "user", "pass")
	rps := envInt("SOAK_RPS", 5)
	targeter := vegeta.NewStaticTargeter(vegeta.Target{
		Method: http.MethodGet,
		URL:    "http://" + httpAddr + "/large.bin",
	})

	workers := envInt("SOAK_WORKERS", 10)
	maxWorkers := envInt("SOAK_MAX_WORKERS", 100)
	attacker := vegeta.NewAttacker(
		vegeta.Client(client),
		vegeta.Timeout(10*time.Second),
		vegeta.Workers(uint64(workers)),
		vegeta.MaxWorkers(uint64(maxWorkers)),
	)
	rate := vegeta.Rate{Freq: rps, Per: time.Second}

	var metrics vegeta.Metrics
	for res := range attacker.Attack(targeter, rate, soakSeconds, "socks5-soak") {
		metrics.Add(res)
	}
	metrics.Close()

	t.Logf(
		"soak done requests=%d success=%.2f bytes_in=%d p50=%s p95=%s p99=%s",
		metrics.Requests,
		metrics.Success,
		metrics.BytesIn.Total,
		metrics.Latencies.P50,
		metrics.Latencies.P95,
		metrics.Latencies.P99,
	)
	if metrics.Requests == 0 {
		t.Fatalf(
			"no successful requests; logs: %s %s\nproxy log:\n%s\nsocks log:\n%s",
			proxyLog,
			socksLog,
			readLog(proxyLog),
			readLog(socksLog),
		)
	}
	if metrics.Success < 1.0 {
		t.Fatalf(
			"soak success=%.2f (errors=%d); logs: %s %s\nproxy log:\n%s\nsocks log:\n%s",
			metrics.Success,
			len(metrics.Errors),
			proxyLog,
			socksLog,
			readLog(proxyLog),
			readLog(socksLog),
		)
	}
	assertNoSizeViolations(t, proxyLog, socksLog)
}

func generateKeypair(t *testing.T) ([32]byte, [32]byte) {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	pub, err := obf.DerivePublicKey(priv)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	return priv, pub
}

func soakTempDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("SOAK_TMPDIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir soak tmpdir: %v", err)
		}
		return dir
	}
	return t.TempDir()
}

func startHTTPServer(t *testing.T, addr string, payload []byte) *http.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/large.bin", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	return srv
}

func socksHTTPClient(t *testing.T, addr, user, pass string) *http.Client {
	t.Helper()
	auth := &proxy.Auth{User: user, Password: pass}
	dialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		t.Fatalf("socks dialer: %v", err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.Dial(network, address)
			},
		},
	}
}

func startCmd(
	t *testing.T,
	ctx context.Context,
	dir string,
	args []string,
	logPath string,
) <-chan error {
	t.Helper()
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("log file: %v", err)
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", args[0], err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return done
}

func waitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free tcp port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free udp port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("cwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, ".."))
}

func writeJSONConfig(t *testing.T, path string, cfg interface{}) {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func envDuration(key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return val
}

func envBool(key string, fallback bool) bool {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	val, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return val
}

func readLog(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("log read error: %v", err)
	}
	return string(data)
}

func assertNoSizeViolations(t *testing.T, proxyLog, socksLog string) {
	t.Helper()
	proxyText := readLog(proxyLog)
	socksText := readLog(socksLog)
	if strings.Contains(proxyText, "payload exceeds max packet size") ||
		strings.Contains(socksText, "payload exceeds max packet size") {
		t.Fatalf("payload size violations detected\nproxy log:\n%s\nsocks log:\n%s", proxyText, socksText)
	}
	if hasNonZeroPadDrop(proxyText) || hasNonZeroPadDrop(socksText) {
		t.Fatalf("padding drops detected (pad_drop>0)\nproxy log:\n%s\nsocks log:\n%s", proxyText, socksText)
	}
}

func hasNonZeroPadDrop(logText string) bool {
	re := regexp.MustCompile(`pad_drop=(\d+)`)
	matches := re.FindAllStringSubmatch(logText, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		val, err := strconv.ParseInt(match[1], 10, 64)
		if err == nil && val > 0 {
			return true
		}
	}
	return false
}
