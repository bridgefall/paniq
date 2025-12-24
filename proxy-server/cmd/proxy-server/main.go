package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bridgefall/transport/commons/config"
	"github.com/bridgefall/transport/proxy-server"
	"github.com/bridgefall/transport/profile"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:9000", "listen address")
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
	configPath := flag.String("config", "", "path to JSON config file")
	profilePath := flag.String("profile", "", "path to JSON profile file")
	serverPrivateKeyFile := flag.String("server-private-key-file", "", "path to file containing server private key (base64)")
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

	var cfg proxyserver.Config
	if *configPath != "" {
		if *profilePath == "" {
			log.Fatalf("config error: profile path required with --config")
		}
		var fileCfg proxyserver.FileConfig
		if err := config.LoadJSONFile(*configPath, &fileCfg); err != nil {
			log.Fatalf("config error: %v", err)
		}
		var profileCfg profile.Profile
		if err := config.LoadJSONFile(*profilePath, &profileCfg); err != nil {
			log.Fatalf("config error: %v", err)
		}
		if err := resolveServerPrivateKey(&profileCfg, *serverPrivateKeyFile); err != nil {
			log.Fatalf("config error: %v", err)
		}
		loaded, err := fileCfg.ToServerConfig(profileCfg)
		if err != nil {
			log.Fatalf("config error: %v", err)
		}
		cfg = loaded

		overrideObf := func() {
			obfCfg := proxyserver.ObfConfig{
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
			adapter, err := proxyserver.NewAWGObfuscator(obfCfg)
			if err != nil {
				log.Fatalf("obfuscation config error: %v", err)
			}
			cfg.Obfuscator = adapter
		}

		overrides := map[string]func(){
			"listen":            func() { cfg.ListenAddr = *listenAddr },
			"workers":           func() { cfg.WorkerCount = *workerCount },
			"max-conns":         func() { cfg.MaxConnections = *maxConns },
			"handshake-timeout": func() { cfg.HandshakeTimeout = *handshakeTimeout },
			"dial-timeout":      func() { cfg.DialTimeout = *dialTimeout },
			"idle-timeout":      func() { cfg.IdleTimeout = *idleTimeout },
			"metrics-interval":  func() { cfg.MetricsInterval = *metricsInterval },
			"verbose":           func() { cfg.Verbose = *verbose },
			"log-level":         func() { cfg.LogLevel = *logLevel },
			"quic-max-packet-size": func() {
				cfg.Quic.MaxPacketSize = *quicMaxPacket
			},
			"quic-keepalive": func() { cfg.Quic.KeepAlive = *quicKeepAlive },
			"quic-idle-timeout": func() {
				cfg.Quic.IdleTimeout = *quicIdleTimeout
			},
			"quic-max-streams": func() { cfg.Quic.MaxStreams = *quicMaxStreams },
			"obfuscation":      overrideObf,
			"obf-jc":           overrideObf,
			"obf-jmin":         overrideObf,
			"obf-jmax":         overrideObf,
			"obf-s1":           overrideObf,
			"obf-s2":           overrideObf,
			"obf-s3":           overrideObf,
			"obf-s4":           overrideObf,
			"obf-h1":           overrideObf,
			"obf-h2":           overrideObf,
			"obf-h3":           overrideObf,
			"obf-h4":           overrideObf,
			"obf-i1":           overrideObf,
			"obf-i2":           overrideObf,
			"obf-i3":           overrideObf,
			"obf-i4":           overrideObf,
			"obf-i5":           overrideObf,
		}

		flag.CommandLine.Visit(func(f *flag.Flag) {
			if apply, ok := overrides[f.Name]; ok {
				apply()
			}
		})
	} else if *profilePath != "" {
		log.Fatalf("config error: --profile requires --config")
	} else {
		obfCfg := proxyserver.ObfConfig{}
		if *obfEnabled {
			obfCfg = proxyserver.ObfConfig{
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
		cfg = proxyserver.Config{
			ListenAddr:       *listenAddr,
			WorkerCount:      *workerCount,
			MaxConnections:   *maxConns,
			HandshakeTimeout: *handshakeTimeout,
			Quic: proxyserver.QuicConfig{
				MaxPacketSize: *quicMaxPacket,
				KeepAlive:     *quicKeepAlive,
				IdleTimeout:   *quicIdleTimeout,
				MaxStreams:    *quicMaxStreams,
			},
			DialTimeout:     *dialTimeout,
			IdleTimeout:     *idleTimeout,
			MetricsInterval: *metricsInterval,
			LogLevel:        *logLevel,
			Verbose:         *verbose,
		}
		if *obfEnabled {
			adapter, err := proxyserver.NewAWGObfuscator(obfCfg)
			if err != nil {
				log.Fatalf("obfuscation config error: %v", err)
			}
			cfg.Obfuscator = adapter
		}
	}

	server, err := proxyserver.NewServer(cfg)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-server.Ready()
		log.Printf("proxy server listening on %s", server.Addr())
	}()

	if err := server.Serve(ctx); err != nil {
		log.Printf("server stopped: %v", err)
		os.Exit(1)
	}
}

func resolveServerPrivateKey(profileCfg *profile.Profile, keyFile string) error {
	if profileCfg.Obfuscation.ServerPrivateKey != "" {
		return nil
	}
	if envVal := strings.TrimSpace(os.Getenv("BF_SERVER_PRIVATE_KEY")); envVal != "" {
		profileCfg.Obfuscation.ServerPrivateKey = envVal
		return nil
	}
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("read server private key file: %w", err)
		}
		val := strings.TrimSpace(string(data))
		if val == "" {
			return fmt.Errorf("server private key file empty")
		}
		profileCfg.Obfuscation.ServerPrivateKey = val
		return nil
	}
	return fmt.Errorf("server private key required (set profile.obfuscation.server_private_key, BF_SERVER_PRIVATE_KEY, or --server-private-key-file)")
}
