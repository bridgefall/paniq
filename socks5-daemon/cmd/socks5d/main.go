package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bridgefall/paniq/commons/logger"
	socks5daemon "github.com/bridgefall/paniq/socks5-daemon"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:1080", "listen address")
	proxyAddr := flag.String("proxy-addr", "", "proxy server address (host:port)")
	username := flag.String("username", "", "socks5 username (required)")
	password := flag.String("password", "", "socks5 password (required)")
	workerCount := flag.Int("workers", 8, "number of worker goroutines")
	maxConns := flag.Int("max-conns", 128, "max queued connections")
	handshakeTimeout := flag.Duration("handshake-timeout", 5*time.Second, "handshake timeout")
	dialTimeout := flag.Duration("dial-timeout", 5*time.Second, "upstream dial timeout")
	idleTimeout := flag.Duration("idle-timeout", 2*time.Minute, "idle timeout for active connections")
	metricsInterval := flag.Duration("metrics-interval", 10*time.Second, "metrics log interval (0s to disable)")
	verbose := flag.Bool("verbose", false, "enable verbose diagnostic logging")
	logLevel := flag.String("log-level", "", "log level (info|debug)")
	quicMaxPacket := flag.Int("quic-max-packet-size", 1200, "maximum QUIC packet size (bytes)")
	quicKeepAlive := flag.Duration("quic-keepalive", 20*time.Second, "QUIC keepalive period")
	quicIdleTimeout := flag.Duration("quic-idle-timeout", 2*time.Minute, "QUIC idle timeout")
	quicMaxStreams := flag.Int("quic-max-streams", 256, "maximum concurrent QUIC streams")
	handshakeAttempts := flag.Int("handshake-attempts", 3, "number of UDP handshake attempts")
	preambleDelay := flag.Int("preamble-delay-ms", 0, "delay between preamble packets (ms)")
	preambleJitter := flag.Int("preamble-jitter-ms", 0, "random jitter added to preamble delay (ms)")
	configPath := flag.String("config", "", "path to JSON config file")
	profilePath := flag.String("profile", "", "path to JSON profile file")
	obfEnabled := flag.Bool("obfuscation", false, "enable AWG obfuscation config from flags")
	obfJc := flag.Int("obf-jc", 0, "junk packet count")
	obfJmin := flag.Int("obf-jmin", 0, "junk min size")
	obfJmax := flag.Int("obf-jmax", 0, "junk max size")
	obfS1 := flag.Int("obf-s1", 0, "padding for handshake init")
	obfS2 := flag.Int("obf-s2", 0, "padding for handshake response")
	obfS3 := flag.Int("obf-s3", 0, "padding for handshake cookie")
	obfS4 := flag.Int("obf-s4", 0, "padding for transport")
	obfH1 := flag.String("obf-h1", "", "header range for handshake init")
	obfH2 := flag.String("obf-h2", "", "header range for handshake response")
	obfH3 := flag.String("obf-h3", "", "header range for handshake cookie")
	obfH4 := flag.String("obf-h4", "", "header range for transport")
	obfI1 := flag.String("obf-i1", "", "custom signature packet 1")
	obfI2 := flag.String("obf-i2", "", "custom signature packet 2")
	obfI3 := flag.String("obf-i3", "", "custom signature packet 3")
	obfI4 := flag.String("obf-i4", "", "custom signature packet 4")
	obfI5 := flag.String("obf-i5", "", "custom signature packet 5")
	flag.Parse()

	var cfg socks5daemon.Config
	if *configPath != "" {
		if *profilePath == "" {
			slog.Error("config error: profile path required with --config")
			os.Exit(1)
		}
		loaded, err := socks5daemon.LoadConfig(*configPath, *profilePath)
		if err != nil {
			slog.Error("config error", "err", err)
			os.Exit(1)
		}
		cfg = loaded
		overrideObf := func() {
			cfg.Obfuscation = socks5daemon.ObfConfig{
				Jc:   *obfJc,
				Jmin: *obfJmin,
				Jmax: *obfJmax,
				S1:   *obfS1,
				S2:   *obfS2,
				S3:   *obfS3,
				S4:   *obfS4,
				H1:   *obfH1,
				H2:   *obfH2,
				H3:   *obfH3,
				H4:   *obfH4,
				I1:   *obfI1,
				I2:   *obfI2,
				I3:   *obfI3,
				I4:   *obfI4,
				I5:   *obfI5,
			}
		}

		overrides := map[string]func(){
			"listen":            func() { cfg.ListenAddr = *listenAddr },
			"proxy-addr":        func() { cfg.ProxyAddr = *proxyAddr },
			"username":          func() { cfg.Username = *username },
			"password":          func() { cfg.Password = *password },
			"workers":           func() { cfg.WorkerCount = *workerCount },
			"max-conns":         func() { cfg.MaxConnections = *maxConns },
			"handshake-timeout": func() { cfg.HandshakeTimeout = *handshakeTimeout },
			"dial-timeout":      func() { cfg.DialTimeout = *dialTimeout },
			"idle-timeout":      func() { cfg.IdleTimeout = *idleTimeout },
			"metrics-interval":  func() { cfg.MetricsInterval = *metricsInterval },
			"log-level":         func() { cfg.LogLevel = *logLevel },
			"verbose": func() {
				if *verbose && cfg.LogLevel == "" {
					cfg.LogLevel = "debug"
				}
			},
			"quic-max-packet-size": func() {
				cfg.Quic.MaxPacketSize = *quicMaxPacket
			},
			"quic-keepalive": func() { cfg.Quic.KeepAlive = *quicKeepAlive },
			"quic-idle-timeout": func() {
				cfg.Quic.IdleTimeout = *quicIdleTimeout
			},
			"quic-max-streams":   func() { cfg.Quic.MaxStreams = *quicMaxStreams },
			"handshake-attempts": func() { cfg.HandshakeAttempts = *handshakeAttempts },
			"preamble-delay-ms":  func() { cfg.PreambleDelay = time.Duration(*preambleDelay) * time.Millisecond },
			"preamble-jitter-ms": func() { cfg.PreambleJitter = time.Duration(*preambleJitter) * time.Millisecond },
			"obfuscation":        overrideObf,
			"obf-jc":             overrideObf,
			"obf-jmin":           overrideObf,
			"obf-jmax":           overrideObf,
			"obf-s1":             overrideObf,
			"obf-s2":             overrideObf,
			"obf-s3":             overrideObf,
			"obf-s4":             overrideObf,
			"obf-h1":             overrideObf,
			"obf-h2":             overrideObf,
			"obf-h3":             overrideObf,
			"obf-h4":             overrideObf,
			"obf-i1":             overrideObf,
			"obf-i2":             overrideObf,
			"obf-i3":             overrideObf,
			"obf-i4":             overrideObf,
			"obf-i5":             overrideObf,
		}

		flag.CommandLine.Visit(func(f *flag.Flag) {
			if apply, ok := overrides[f.Name]; ok {
				apply()
			}
		})
	} else if *profilePath != "" {
		slog.Error("config error: --profile requires --config")
		os.Exit(1)
	} else {
		obfCfg := socks5daemon.ObfConfig{}
		if *obfEnabled {
			obfCfg = socks5daemon.ObfConfig{
				Jc:   *obfJc,
				Jmin: *obfJmin,
				Jmax: *obfJmax,
				S1:   *obfS1,
				S2:   *obfS2,
				S3:   *obfS3,
				S4:   *obfS4,
				H1:   *obfH1,
				H2:   *obfH2,
				H3:   *obfH3,
				H4:   *obfH4,
				I1:   *obfI1,
				I2:   *obfI2,
				I3:   *obfI3,
				I4:   *obfI4,
				I5:   *obfI5,
			}
		}
		cfg = socks5daemon.Config{
			ListenAddr:       *listenAddr,
			ProxyAddr:        *proxyAddr,
			Username:         *username,
			Password:         *password,
			WorkerCount:      *workerCount,
			MaxConnections:   *maxConns,
			HandshakeTimeout: *handshakeTimeout,
			Quic: socks5daemon.QuicConfig{
				MaxPacketSize: *quicMaxPacket,
				KeepAlive:     *quicKeepAlive,
				IdleTimeout:   *quicIdleTimeout,
				MaxStreams:    *quicMaxStreams,
			},
			DialTimeout:       *dialTimeout,
			IdleTimeout:       *idleTimeout,
			MetricsInterval:   *metricsInterval,
			LogLevel:          *logLevel,
			HandshakeAttempts: *handshakeAttempts,
			PreambleDelay:     time.Duration(*preambleDelay) * time.Millisecond,
			PreambleJitter:    time.Duration(*preambleJitter) * time.Millisecond,
			Obfuscation:       obfCfg,
		}
	}
	if cfg.LogLevel == "" && *verbose {
		cfg.LogLevel = "debug"
	}

	logger.Setup(cfg.LogLevel)

	server, err := socks5daemon.NewServer(cfg)
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-server.Ready()
		slog.Info("socks5 daemon listening", "addr", server.Addr())
	}()

	if err := server.Serve(ctx); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
