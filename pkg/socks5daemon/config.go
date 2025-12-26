package socks5daemon

import (
	"fmt"
	"time"

	"github.com/bridgefall/paniq/pkg/commons/config"
	"github.com/bridgefall/paniq/pkg/profile"
)

// FileConfig defines the JSON config for the SOCKS5 daemon.
type FileConfig struct {
	ListenAddr      string          `json:"listen_addr"`
	Username        string          `json:"username"`
	Password        string          `json:"password"`
	WorkerCount     int             `json:"workers"`
	MaxConnections  int             `json:"max_connections"`
	DialTimeout     config.Duration `json:"dial_timeout"`
	AcceptTimeout   config.Duration `json:"accept_timeout"`
	IdleTimeout     config.Duration `json:"idle_timeout"`
	MetricsInterval config.Duration `json:"metrics_interval"`
	LogLevel        string          `json:"log_level"`
	Verbose         bool            `json:"verbose"`
}

// ToServerConfig converts the file config into a Server Config.
func (c FileConfig) ToServerConfig(p profile.Profile) (Config, error) {
	logLevel := c.LogLevel
	if logLevel == "" && c.Verbose {
		logLevel = "debug"
	}

	cfg := Config{
		ListenAddr:       c.ListenAddr,
		ProxyAddr:        p.ProxyAddr,
		Username:         c.Username,
		Password:         c.Password,
		WorkerCount:      c.WorkerCount,
		MaxConnections:   c.MaxConnections,
		HandshakeTimeout: p.HandshakeTimeout.Duration,
		Quic: QuicConfig{
			MaxPacketSize: p.Quic.MaxPacketSize,
			MaxPayload:    p.Quic.MaxPayload,
			KeepAlive:     p.Quic.KeepAlive.Duration,
			IdleTimeout:   p.Quic.IdleTimeout.Duration,
			MaxStreams:    p.Quic.MaxStreams,
		},
		DialTimeout:       c.DialTimeout.Duration,
		AcceptTimeout:     c.AcceptTimeout.Duration,
		IdleTimeout:       c.IdleTimeout.Duration,
		MetricsInterval:   c.MetricsInterval.Duration,
		LogLevel:          logLevel,
		HandshakeAttempts: p.HandshakeAttempts,
		PreambleDelay:     time.Duration(p.PreambleDelayMs) * time.Millisecond,
		PreambleJitter:    time.Duration(p.PreambleJitterMs) * time.Millisecond,
		Obfuscation:       p.Obfuscation,
	}
	paddingPolicy, err := p.TransportPadding.Resolve()
	if err != nil {
		return Config{}, err
	}
	cfg.TransportPadding = paddingPolicy
	if _, err := normalizeConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// LoadConfig reads and validates a JSON config file.
func LoadConfig(path string, profilePath string) (Config, error) {
	var fileCfg FileConfig
	if err := config.LoadJSONFile(path, &fileCfg); err != nil {
		return Config{}, err
	}
	var profileCfg profile.Profile
	if err := config.LoadJSONFile(profilePath, &profileCfg); err != nil {
		return Config{}, err
	}
	cfg, err := fileCfg.ToServerConfig(profileCfg)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", invalidConfigPrefix, err)
	}
	return cfg, nil
}
