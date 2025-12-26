package proxyserver

import (
	"net"

	"github.com/bridgefall/paniq/pkg/obf"
	"github.com/bridgefall/paniq/pkg/profile"
)

// ObfConfig aliases the shared profile ObfConfig.
type ObfConfig = profile.ObfConfig

// AWGObfuscator validates the config and wraps conns (no-op for now).
type AWGObfuscator struct {
	cfg    obf.Config
	framer *obf.Framer
}

// NewAWGObfuscator validates and constructs an AWGObfuscator.
func NewAWGObfuscator(cfg ObfConfig) (*AWGObfuscator, error) {
	obfCfg := cfg.ToObfConfig()
	if err := obfCfg.Validate(); err != nil {
		return nil, err
	}
	framer, err := obf.NewFramer(obfCfg)
	if err != nil {
		return nil, err
	}
	return &AWGObfuscator{cfg: obfCfg, framer: framer}, nil
}

// Wrap currently returns the original connection (placeholder until transport framing is defined).
func (o *AWGObfuscator) Wrap(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

// Framer returns the configured transport framer.
func (o *AWGObfuscator) Framer() *obf.Framer {
	return o.framer
}

// Enabled returns true if obfuscation parameters are set.
func (o *AWGObfuscator) Enabled() bool {
	return o.cfg != (obf.Config{})
}
