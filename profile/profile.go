package profile

import "github.com/bridgefall/transport/commons/config"

// Profile defines the portable connection/obfuscation profile shared by client and server.
type Profile struct {
	Name              string           `json:"name"`
	ProxyAddr         string           `json:"proxy_addr"`
	HandshakeTimeout  config.Duration  `json:"handshake_timeout"`
	HandshakeAttempts int              `json:"handshake_attempts"`
	PreambleDelayMs   int              `json:"preamble_delay_ms"`
	PreambleJitterMs  int              `json:"preamble_jitter_ms"`
	Quic              QuicConfig       `json:"quic"`
	Obfuscation       ObfConfig        `json:"obfuscation"`
	TransportPadding  TransportPadding `json:"transport_padding"`
}

// QuicConfig defines QUIC transport settings.
type QuicConfig struct {
	MaxPacketSize int             `json:"max_packet_size"`
	MaxPayload    int             `json:"max_payload"`
	KeepAlive     config.Duration `json:"keepalive"`
	IdleTimeout   config.Duration `json:"idle_timeout"`
	MaxStreams    int             `json:"max_streams"`
}
