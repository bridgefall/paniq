package proxyserver

import (
	"fmt"
	"strings"
	"time"

	"github.com/bridgefall/paniq/commons/config"
	"github.com/bridgefall/paniq/obf"
	"github.com/bridgefall/paniq/profile"
)

// FileConfig defines the JSON config for the proxy server.
type FileConfig struct {
	ListenAddr      string          `json:"listen_addr"`
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

	legacySunset, err := parseLegacySunset(p.Obfuscation.LegacyModeSunset)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		ListenAddr:       c.ListenAddr,
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
		DialTimeout:               c.DialTimeout.Duration,
		AcceptTimeout:             c.AcceptTimeout.Duration,
		IdleTimeout:               c.IdleTimeout.Duration,
		MetricsInterval:           c.MetricsInterval.Duration,
		LogLevel:                  logLevel,
		SignatureValidate:         resolveBool(p.Obfuscation.SignatureValidate, true),
		RequireTimestamp:          resolveBool(p.Obfuscation.RequireTimestamp, true),
		EncryptedTimestamp:        resolveBool(p.Obfuscation.EncryptedTimestamp, p.Obfuscation.ServerPrivateKey != ""),
		RequireEncryptedTimestamp: resolveBool(p.Obfuscation.RequireEncryptedTimestamp, false),
		LegacyModeEnabled:         resolveBool(p.Obfuscation.LegacyModeEnabled, false),
		LegacyModeSunset:          legacySunset,
		LegacyModeMaxDays:         p.Obfuscation.LegacyModeMaxDays,
		SkewSoft:                  time.Duration(p.Obfuscation.SkewSoftSeconds) * time.Second,
		SkewHard:                  time.Duration(p.Obfuscation.SkewHardSeconds) * time.Second,
		ReplayWindow:              time.Duration(p.Obfuscation.ReplayWindowSeconds) * time.Second,
		ReplayCacheSize:           p.Obfuscation.ReplayCacheSize,
		TransportReplay:           p.Obfuscation.TransportReplay,
		TransportReplayLimit:      p.Obfuscation.TransportReplayLimit,
		RateLimitPPS:              p.Obfuscation.RateLimitPPS,
		RateLimitBurst:            p.Obfuscation.RateLimitBurst,
	}
	paddingPolicy, err := p.TransportPadding.Resolve()
	if err != nil {
		return Config{}, err
	}
	cfg.TransportPadding = paddingPolicy
	if !isObfuscationEmpty(p.Obfuscation) {
		adapter, err := NewAWGObfuscator(p.Obfuscation)
		if err != nil {
			return Config{}, err
		}
		cfg.Obfuscator = adapter
	}
	if p.Obfuscation.ServerPrivateKey != "" {
		privKey, err := obf.DecodeKeyBase64(p.Obfuscation.ServerPrivateKey)
		if err != nil {
			return Config{}, fmt.Errorf("%s: server private key invalid: %w", invalidConfigPrefix, err)
		}
		pubKey, err := obf.DerivePublicKey(privKey)
		if err != nil {
			return Config{}, fmt.Errorf("%s: server private key invalid: %w", invalidConfigPrefix, err)
		}
		mac1Key, err := obf.DeriveMac1Key(pubKey)
		if err != nil {
			return Config{}, fmt.Errorf("%s: mac1 derivation failed: %w", invalidConfigPrefix, err)
		}
		cfg.Mac1Key = &mac1Key
		cfg.ServerPrivateKey = &privKey
	}
	if cfg.RequireEncryptedTimestamp {
		if cfg.ServerPrivateKey == nil {
			return Config{}, fmt.Errorf("%s: require_encrypted_timestamp needs server private key", invalidConfigPrefix)
		}
		cfg.EncryptedTimestamp = true
	}
	if cfg.RequireTimestamp && !cfg.RequireEncryptedTimestamp && !hasTimestampTag(p.Obfuscation) {
		return Config{}, fmt.Errorf("%s: require_timestamp needs <t> in signature chain", invalidConfigPrefix)
	}
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

func isObfuscationEmpty(cfg ObfConfig) bool {
	return cfg == (ObfConfig{})
}

func resolveBool(val *bool, fallback bool) bool {
	if val == nil {
		return fallback
	}
	return *val
}

func parseLegacySunset(val string) (time.Time, error) {
	if val == "" {
		return time.Time{}, nil
	}
	if ts, err := time.Parse("2006-01-02", val); err == nil {
		return ts, nil
	}
	ts, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: invalid legacy_mode_sunset", invalidConfigPrefix)
	}
	return ts, nil
}

func hasTimestampTag(cfg ObfConfig) bool {
	specs := []string{cfg.I1, cfg.I2, cfg.I3, cfg.I4, cfg.I5}
	for _, spec := range specs {
		if strings.Contains(spec, "<t") {
			return true
		}
	}
	return false
}
