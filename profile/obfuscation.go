package profile

import "github.com/bridgefall/paniq/obf"

// ObfConfig defines AWG obfuscation parameters and hardening options.
type ObfConfig struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	S3   int    `json:"s3"`
	S4   int    `json:"s4"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
	I1   string `json:"i1"`
	I2   string `json:"i2"`
	I3   string `json:"i3"`
	I4   string `json:"i4"`
	I5   string `json:"i5"`

	// Client/server keys (optional, use only on the relevant side).
	ServerPrivateKey string `json:"server_private_key"`
	ServerPublicKey  string `json:"server_public_key"`

	// Security hardening options (server-side).
	SignatureValidate         *bool  `json:"signature_validate"`
	RequireTimestamp          *bool  `json:"require_timestamp"`
	EncryptedTimestamp        *bool  `json:"encrypted_timestamp"`
	RequireEncryptedTimestamp *bool  `json:"require_encrypted_timestamp"`
	LegacyModeEnabled         *bool  `json:"legacy_mode_enabled"`
	LegacyModeSunset          string `json:"legacy_mode_sunset"`
	LegacyModeMaxDays         int    `json:"legacy_mode_max_days"`
	SkewSoftSeconds           int    `json:"skew_soft_seconds"`
	SkewHardSeconds           int    `json:"skew_hard_seconds"`
	ReplayWindowSeconds       int    `json:"replay_window_seconds"`
	ReplayCacheSize           int    `json:"replay_cache_size"`
	TransportReplay           bool   `json:"transport_replay"`
	TransportReplayLimit      uint64 `json:"transport_replay_limit"`
	RateLimitPPS              int    `json:"rate_limit_pps"`
	RateLimitBurst            int    `json:"rate_limit_burst"`
}

// Enabled returns true if obfuscation parameters are set.
func (c ObfConfig) Enabled() bool {
	return c != (ObfConfig{})
}

// ToObfConfig converts to the shared obf.Config.
func (c ObfConfig) ToObfConfig() obf.Config {
	return obf.Config{
		Jc:   c.Jc,
		Jmin: c.Jmin,
		Jmax: c.Jmax,
		S1:   c.S1,
		S2:   c.S2,
		S3:   c.S3,
		S4:   c.S4,
		H1:   c.H1,
		H2:   c.H2,
		H3:   c.H3,
		H4:   c.H4,
		I1:   c.I1,
		I2:   c.I2,
		I3:   c.I3,
		I4:   c.I4,
		I5:   c.I5,
	}
}
