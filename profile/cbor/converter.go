package cborprofile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bridgefall/transport/commons/config"
	"github.com/bridgefall/transport/profile"
	"github.com/fxamacker/cbor/v2"
)

const (
	Version = 1
)

const (
	keyVersion           uint64 = 0
	keyName              uint64 = 1
	keyProxyAddr         uint64 = 2
	keyHandshakeTimeout  uint64 = 3
	keyHandshakeAttempts uint64 = 4
	keyPreambleDelay     uint64 = 5
	keyPreambleJitter    uint64 = 6
	keyQuic              uint64 = 7
	keyObfuscation       uint64 = 8
	keyTransportPadding  uint64 = 9
)

const (
	keyQuicMaxPacketSize uint64 = 1
	keyQuicMaxPayload    uint64 = 2
	keyQuicKeepAlive     uint64 = 3
	keyQuicIdleTimeout   uint64 = 4
	keyQuicMaxStreams    uint64 = 5
)

const (
	keyObfJc   uint64 = 1
	keyObfJmin uint64 = 2
	keyObfJmax uint64 = 3
	keyObfS1   uint64 = 4
	keyObfS2   uint64 = 5
	keyObfS3   uint64 = 6
	keyObfS4   uint64 = 7
	keyObfH1   uint64 = 8
	keyObfH2   uint64 = 9
	keyObfH3   uint64 = 10
	keyObfH4   uint64 = 11
	keyObfI1   uint64 = 12
	keyObfI2   uint64 = 13
	keyObfI3   uint64 = 14
	keyObfI4   uint64 = 15
	keyObfI5   uint64 = 16

	keyObfServerPrivateKey uint64 = 17
	keyObfServerPublicKey  uint64 = 18

	keyObfSignatureValidate         uint64 = 19
	keyObfRequireTimestamp          uint64 = 20
	keyObfEncryptedTimestamp        uint64 = 21
	keyObfRequireEncryptedTimestamp uint64 = 22
	keyObfLegacyModeEnabled         uint64 = 23
	keyObfLegacyModeSunset          uint64 = 24
	keyObfLegacyModeMaxDays         uint64 = 25
	keyObfSkewSoftSeconds           uint64 = 26
	keyObfSkewHardSeconds           uint64 = 27
	keyObfReplayWindowSeconds       uint64 = 28
	keyObfReplayCacheSize           uint64 = 29
	keyObfTransportReplay           uint64 = 30
	keyObfTransportReplayLimit      uint64 = 31
	keyObfRateLimitPPS              uint64 = 32
	keyObfRateLimitBurst            uint64 = 33
)

const (
	keyPadMin       uint64 = 1
	keyPadMax       uint64 = 2
	keyPadBurstMin  uint64 = 3
	keyPadBurstMax  uint64 = 4
	keyPadBurstProb uint64 = 5
)

const (
	defaultHandshakeAttempts = 3
	defaultHandshakeTimeout  = 5 * time.Second
	defaultQuicMaxPacketSize = 1350
	defaultQuicKeepAlive     = 20 * time.Second
	defaultQuicIdleTimeout   = 2 * time.Minute
	defaultQuicMaxStreams    = 256
	defaultPreambleDelayMs   = 0
	defaultPreambleJitterMs  = 0
)

var (
	defaultPadding = profile.DefaultPaddingPolicy()
)

// EncodeProfile converts a profile into deterministic CBOR bytes.
func EncodeProfile(p profile.Profile) ([]byte, error) {
	if p.ProxyAddr == "" {
		return nil, fmt.Errorf("proxy_addr required")
	}
	payload := map[uint64]any{
		keyVersion: uint64(Version),
	}
	if p.Name != "" {
		payload[keyName] = p.Name
	}
	payload[keyProxyAddr] = p.ProxyAddr
	if shouldIncludeDuration(p.HandshakeTimeout.Duration, defaultHandshakeTimeout) {
		payload[keyHandshakeTimeout] = uint64(p.HandshakeTimeout.Duration / time.Millisecond)
	}
	if shouldIncludeInt(p.HandshakeAttempts, defaultHandshakeAttempts) {
		payload[keyHandshakeAttempts] = uint64(p.HandshakeAttempts)
	}
	if p.PreambleDelayMs != defaultPreambleDelayMs && p.PreambleDelayMs > 0 {
		payload[keyPreambleDelay] = uint64(p.PreambleDelayMs)
	}
	if p.PreambleJitterMs != defaultPreambleJitterMs && p.PreambleJitterMs > 0 {
		payload[keyPreambleJitter] = uint64(p.PreambleJitterMs)
	}
	if quic := encodeQuic(p.Quic); len(quic) > 0 {
		payload[keyQuic] = quic
	}
	if obf, err := encodeObfuscation(p.Obfuscation); err != nil {
		return nil, err
	} else if len(obf) > 0 {
		payload[keyObfuscation] = obf
	}
	if pad := encodePadding(p.TransportPadding); len(pad) > 0 {
		payload[keyTransportPadding] = pad
	}

	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return mode.Marshal(payload)
}

// DecodeProfile parses CBOR bytes into a profile.
func DecodeProfile(data []byte) (profile.Profile, error) {
	mode, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		return profile.Profile{}, err
	}
	var raw map[uint64]any
	if err := mode.Unmarshal(data, &raw); err != nil {
		return profile.Profile{}, err
	}
	version, ok := raw[keyVersion]
	if !ok {
		return profile.Profile{}, fmt.Errorf("cbor profile missing version")
	}
	versionInt, err := asUint(version)
	if err != nil {
		return profile.Profile{}, fmt.Errorf("cbor profile version invalid: %w", err)
	}
	if versionInt != Version {
		return profile.Profile{}, fmt.Errorf("unsupported cbor profile version %d", versionInt)
	}

	var out profile.Profile
	if v, ok := raw[keyName]; ok {
		out.Name, err = asString(v)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("name: %w", err)
		}
	}
	if v, ok := raw[keyProxyAddr]; ok {
		out.ProxyAddr, err = asString(v)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("proxy_addr: %w", err)
		}
	}
	if v, ok := raw[keyHandshakeTimeout]; ok {
		ms, err := asUint(v)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("handshake_timeout: %w", err)
		}
		out.HandshakeTimeout = config.Duration{Duration: time.Duration(ms) * time.Millisecond}
	}
	if v, ok := raw[keyHandshakeAttempts]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("handshake_attempts: %w", err)
		}
		out.HandshakeAttempts = int(val)
	}
	if v, ok := raw[keyPreambleDelay]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("preamble_delay_ms: %w", err)
		}
		out.PreambleDelayMs = int(val)
	}
	if v, ok := raw[keyPreambleJitter]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("preamble_jitter_ms: %w", err)
		}
		out.PreambleJitterMs = int(val)
	}
	if v, ok := raw[keyQuic]; ok {
		quic, err := decodeQuic(v)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("quic: %w", err)
		}
		out.Quic = quic
	}
	if v, ok := raw[keyObfuscation]; ok {
		obf, err := decodeObfuscation(v)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("obfuscation: %w", err)
		}
		out.Obfuscation = obf
	}
	if v, ok := raw[keyTransportPadding]; ok {
		pad, err := decodePadding(v)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("transport_padding: %w", err)
		}
		out.TransportPadding = pad
	}
	return out, nil
}

// EncodeJSONProfile converts a JSON profile into CBOR bytes.
func EncodeJSONProfile(jsonData []byte) ([]byte, error) {
	var p profile.Profile
	if err := json.Unmarshal(jsonData, &p); err != nil {
		return nil, err
	}
	return EncodeProfile(p)
}

// DecodeCBORToJSON converts CBOR bytes into a JSON profile.
func DecodeCBORToJSON(data []byte) ([]byte, error) {
	p, err := DecodeProfile(data)
	if err != nil {
		return nil, err
	}
	out := profileToJSON(p)
	return json.MarshalIndent(out, "", "  ")
}

type jsonProfile struct {
	Name              string          `json:"name,omitempty"`
	ProxyAddr         string          `json:"proxy_addr,omitempty"`
	HandshakeTimeout  string          `json:"handshake_timeout,omitempty"`
	HandshakeAttempts int             `json:"handshake_attempts,omitempty"`
	PreambleDelayMs   int             `json:"preamble_delay_ms,omitempty"`
	PreambleJitterMs  int             `json:"preamble_jitter_ms,omitempty"`
	Quic              *jsonQuicConfig `json:"quic,omitempty"`
	Obfuscation       *jsonObfConfig  `json:"obfuscation,omitempty"`
	TransportPadding  *jsonPadding    `json:"transport_padding,omitempty"`
}

type jsonQuicConfig struct {
	MaxPacketSize int    `json:"max_packet_size,omitempty"`
	MaxPayload    int    `json:"max_payload,omitempty"`
	KeepAlive     string `json:"keepalive,omitempty"`
	IdleTimeout   string `json:"idle_timeout,omitempty"`
	MaxStreams    int    `json:"max_streams,omitempty"`
}

type jsonObfConfig struct {
	Jc   int    `json:"jc,omitempty"`
	Jmin int    `json:"jmin,omitempty"`
	Jmax int    `json:"jmax,omitempty"`
	S1   int    `json:"s1,omitempty"`
	S2   int    `json:"s2,omitempty"`
	S3   int    `json:"s3,omitempty"`
	S4   int    `json:"s4,omitempty"`
	H1   string `json:"h1,omitempty"`
	H2   string `json:"h2,omitempty"`
	H3   string `json:"h3,omitempty"`
	H4   string `json:"h4,omitempty"`
	I1   string `json:"i1,omitempty"`
	I2   string `json:"i2,omitempty"`
	I3   string `json:"i3,omitempty"`
	I4   string `json:"i4,omitempty"`
	I5   string `json:"i5,omitempty"`

	ServerPrivateKey string `json:"server_private_key,omitempty"`
	ServerPublicKey  string `json:"server_public_key,omitempty"`

	SignatureValidate         *bool  `json:"signature_validate,omitempty"`
	RequireTimestamp          *bool  `json:"require_timestamp,omitempty"`
	EncryptedTimestamp        *bool  `json:"encrypted_timestamp,omitempty"`
	RequireEncryptedTimestamp *bool  `json:"require_encrypted_timestamp,omitempty"`
	LegacyModeEnabled         *bool  `json:"legacy_mode_enabled,omitempty"`
	LegacyModeSunset          string `json:"legacy_mode_sunset,omitempty"`
	LegacyModeMaxDays         int    `json:"legacy_mode_max_days,omitempty"`
	SkewSoftSeconds           int    `json:"skew_soft_seconds,omitempty"`
	SkewHardSeconds           int    `json:"skew_hard_seconds,omitempty"`
	ReplayWindowSeconds       int    `json:"replay_window_seconds,omitempty"`
	ReplayCacheSize           int    `json:"replay_cache_size,omitempty"`
	TransportReplay           bool   `json:"transport_replay,omitempty"`
	TransportReplayLimit      uint64 `json:"transport_replay_limit,omitempty"`
	RateLimitPPS              int    `json:"rate_limit_pps,omitempty"`
	RateLimitBurst            int    `json:"rate_limit_burst,omitempty"`
}

type jsonPadding struct {
	Min       *int     `json:"pad_min,omitempty"`
	Max       *int     `json:"pad_max,omitempty"`
	BurstMin  *int     `json:"pad_burst_min,omitempty"`
	BurstMax  *int     `json:"pad_burst_max,omitempty"`
	BurstProb *float64 `json:"pad_burst_prob,omitempty"`
}

func profileToJSON(p profile.Profile) jsonProfile {
	out := jsonProfile{
		Name:              p.Name,
		ProxyAddr:         p.ProxyAddr,
		HandshakeAttempts: p.HandshakeAttempts,
		PreambleDelayMs:   p.PreambleDelayMs,
		PreambleJitterMs:  p.PreambleJitterMs,
	}
	if p.HandshakeTimeout.Duration > 0 {
		out.HandshakeTimeout = p.HandshakeTimeout.Duration.String()
	}
	if quic := quicToJSON(p.Quic); quic != nil {
		out.Quic = quic
	}
	if obf := obfToJSON(p.Obfuscation); obf != nil {
		out.Obfuscation = obf
	}
	if pad := paddingToJSON(p.TransportPadding); pad != nil {
		out.TransportPadding = pad
	}
	return out
}

func quicToJSON(q profile.QuicConfig) *jsonQuicConfig {
	out := jsonQuicConfig{
		MaxPacketSize: q.MaxPacketSize,
		MaxPayload:    q.MaxPayload,
		MaxStreams:    q.MaxStreams,
	}
	if q.KeepAlive.Duration > 0 {
		out.KeepAlive = q.KeepAlive.Duration.String()
	}
	if q.IdleTimeout.Duration > 0 {
		out.IdleTimeout = q.IdleTimeout.Duration.String()
	}
	if out.MaxPacketSize == 0 && out.MaxPayload == 0 && out.MaxStreams == 0 && out.KeepAlive == "" && out.IdleTimeout == "" {
		return nil
	}
	return &out
}

func obfToJSON(o profile.ObfConfig) *jsonObfConfig {
	out := jsonObfConfig{
		Jc:                        o.Jc,
		Jmin:                      o.Jmin,
		Jmax:                      o.Jmax,
		S1:                        o.S1,
		S2:                        o.S2,
		S3:                        o.S3,
		S4:                        o.S4,
		H1:                        o.H1,
		H2:                        o.H2,
		H3:                        o.H3,
		H4:                        o.H4,
		I1:                        o.I1,
		I2:                        o.I2,
		I3:                        o.I3,
		I4:                        o.I4,
		I5:                        o.I5,
		ServerPrivateKey:          o.ServerPrivateKey,
		ServerPublicKey:           o.ServerPublicKey,
		SignatureValidate:         o.SignatureValidate,
		RequireTimestamp:          o.RequireTimestamp,
		EncryptedTimestamp:        o.EncryptedTimestamp,
		RequireEncryptedTimestamp: o.RequireEncryptedTimestamp,
		LegacyModeEnabled:         o.LegacyModeEnabled,
		LegacyModeSunset:          o.LegacyModeSunset,
		LegacyModeMaxDays:         o.LegacyModeMaxDays,
		SkewSoftSeconds:           o.SkewSoftSeconds,
		SkewHardSeconds:           o.SkewHardSeconds,
		ReplayWindowSeconds:       o.ReplayWindowSeconds,
		ReplayCacheSize:           o.ReplayCacheSize,
		TransportReplay:           o.TransportReplay,
		TransportReplayLimit:      o.TransportReplayLimit,
		RateLimitPPS:              o.RateLimitPPS,
		RateLimitBurst:            o.RateLimitBurst,
	}
	if out == (jsonObfConfig{}) {
		return nil
	}
	return &out
}

func paddingToJSON(p profile.TransportPadding) *jsonPadding {
	out := jsonPadding{
		Min:       p.Min,
		Max:       p.Max,
		BurstMin:  p.BurstMin,
		BurstMax:  p.BurstMax,
		BurstProb: p.BurstProb,
	}
	if out.Min == nil && out.Max == nil && out.BurstMin == nil && out.BurstMax == nil && out.BurstProb == nil {
		return nil
	}
	return &out
}

func encodeQuic(q profile.QuicConfig) map[uint64]any {
	out := make(map[uint64]any)
	if shouldIncludeInt(q.MaxPacketSize, defaultQuicMaxPacketSize) {
		out[keyQuicMaxPacketSize] = uint64(q.MaxPacketSize)
	}
	if q.MaxPayload > 0 {
		out[keyQuicMaxPayload] = uint64(q.MaxPayload)
	}
	if shouldIncludeDuration(q.KeepAlive.Duration, defaultQuicKeepAlive) {
		out[keyQuicKeepAlive] = uint64(q.KeepAlive.Duration / time.Millisecond)
	}
	if shouldIncludeDuration(q.IdleTimeout.Duration, defaultQuicIdleTimeout) {
		out[keyQuicIdleTimeout] = uint64(q.IdleTimeout.Duration / time.Millisecond)
	}
	if shouldIncludeInt(q.MaxStreams, defaultQuicMaxStreams) {
		out[keyQuicMaxStreams] = uint64(q.MaxStreams)
	}
	return out
}

func encodeObfuscation(o profile.ObfConfig) (map[uint64]any, error) {
	out := make(map[uint64]any)
	if o.Jc != 0 {
		out[keyObfJc] = uint64(o.Jc)
	}
	if o.Jmin != 0 {
		out[keyObfJmin] = uint64(o.Jmin)
	}
	if o.Jmax != 0 {
		out[keyObfJmax] = uint64(o.Jmax)
	}
	if o.S1 != 0 {
		out[keyObfS1] = uint64(o.S1)
	}
	if o.S2 != 0 {
		out[keyObfS2] = uint64(o.S2)
	}
	if o.S3 != 0 {
		out[keyObfS3] = uint64(o.S3)
	}
	if o.S4 != 0 {
		out[keyObfS4] = uint64(o.S4)
	}
	if o.H1 != "" {
		out[keyObfH1] = o.H1
	}
	if o.H2 != "" {
		out[keyObfH2] = o.H2
	}
	if o.H3 != "" {
		out[keyObfH3] = o.H3
	}
	if o.H4 != "" {
		out[keyObfH4] = o.H4
	}
	if o.I1 != "" {
		out[keyObfI1] = o.I1
	}
	if o.I2 != "" {
		out[keyObfI2] = o.I2
	}
	if o.I3 != "" {
		out[keyObfI3] = o.I3
	}
	if o.I4 != "" {
		out[keyObfI4] = o.I4
	}
	if o.I5 != "" {
		out[keyObfI5] = o.I5
	}
	if o.ServerPrivateKey != "" {
		raw, err := base64.StdEncoding.DecodeString(o.ServerPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("server_private_key: %w", err)
		}
		out[keyObfServerPrivateKey] = raw
	}
	if o.ServerPublicKey != "" {
		raw, err := base64.StdEncoding.DecodeString(o.ServerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("server_public_key: %w", err)
		}
		out[keyObfServerPublicKey] = raw
	}
	if o.SignatureValidate != nil {
		out[keyObfSignatureValidate] = *o.SignatureValidate
	}
	if o.RequireTimestamp != nil {
		out[keyObfRequireTimestamp] = *o.RequireTimestamp
	}
	if o.EncryptedTimestamp != nil {
		out[keyObfEncryptedTimestamp] = *o.EncryptedTimestamp
	}
	if o.RequireEncryptedTimestamp != nil {
		out[keyObfRequireEncryptedTimestamp] = *o.RequireEncryptedTimestamp
	}
	if o.LegacyModeEnabled != nil {
		out[keyObfLegacyModeEnabled] = *o.LegacyModeEnabled
	}
	if o.LegacyModeSunset != "" {
		out[keyObfLegacyModeSunset] = o.LegacyModeSunset
	}
	if o.LegacyModeMaxDays != 0 {
		out[keyObfLegacyModeMaxDays] = uint64(o.LegacyModeMaxDays)
	}
	if o.SkewSoftSeconds != 0 {
		out[keyObfSkewSoftSeconds] = uint64(o.SkewSoftSeconds)
	}
	if o.SkewHardSeconds != 0 {
		out[keyObfSkewHardSeconds] = uint64(o.SkewHardSeconds)
	}
	if o.ReplayWindowSeconds != 0 {
		out[keyObfReplayWindowSeconds] = uint64(o.ReplayWindowSeconds)
	}
	if o.ReplayCacheSize != 0 {
		out[keyObfReplayCacheSize] = uint64(o.ReplayCacheSize)
	}
	if o.TransportReplay {
		out[keyObfTransportReplay] = true
	}
	if o.TransportReplayLimit != 0 {
		out[keyObfTransportReplayLimit] = o.TransportReplayLimit
	}
	if o.RateLimitPPS != 0 {
		out[keyObfRateLimitPPS] = uint64(o.RateLimitPPS)
	}
	if o.RateLimitBurst != 0 {
		out[keyObfRateLimitBurst] = uint64(o.RateLimitBurst)
	}
	return out, nil
}

func encodePadding(p profile.TransportPadding) map[uint64]any {
	out := make(map[uint64]any)
	if p.Min != nil && *p.Min != defaultPadding.Min {
		out[keyPadMin] = uint64(*p.Min)
	}
	if p.Max != nil && *p.Max != defaultPadding.Max {
		out[keyPadMax] = uint64(*p.Max)
	}
	if p.BurstMin != nil && *p.BurstMin != defaultPadding.BurstMin {
		out[keyPadBurstMin] = uint64(*p.BurstMin)
	}
	if p.BurstMax != nil && *p.BurstMax != defaultPadding.BurstMax {
		out[keyPadBurstMax] = uint64(*p.BurstMax)
	}
	if p.BurstProb != nil && *p.BurstProb != defaultPadding.BurstProb {
		out[keyPadBurstProb] = *p.BurstProb
	}
	return out
}

func decodeQuic(value any) (profile.QuicConfig, error) {
	raw, err := asMapUint(value)
	if err != nil {
		return profile.QuicConfig{}, fmt.Errorf("expected map: %w", err)
	}
	var out profile.QuicConfig
	if v, ok := raw[keyQuicMaxPacketSize]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.QuicConfig{}, err
		}
		out.MaxPacketSize = int(val)
	}
	if v, ok := raw[keyQuicMaxPayload]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.QuicConfig{}, err
		}
		out.MaxPayload = int(val)
	}
	if v, ok := raw[keyQuicKeepAlive]; ok {
		ms, err := asUint(v)
		if err != nil {
			return profile.QuicConfig{}, err
		}
		out.KeepAlive = config.Duration{Duration: time.Duration(ms) * time.Millisecond}
	}
	if v, ok := raw[keyQuicIdleTimeout]; ok {
		ms, err := asUint(v)
		if err != nil {
			return profile.QuicConfig{}, err
		}
		out.IdleTimeout = config.Duration{Duration: time.Duration(ms) * time.Millisecond}
	}
	if v, ok := raw[keyQuicMaxStreams]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.QuicConfig{}, err
		}
		out.MaxStreams = int(val)
	}
	return out, nil
}

func decodeObfuscation(value any) (profile.ObfConfig, error) {
	raw, err := asMapUint(value)
	if err != nil {
		return profile.ObfConfig{}, fmt.Errorf("expected map: %w", err)
	}
	var out profile.ObfConfig
	if v, ok := raw[keyObfJc]; ok {
		out.Jc, err = asInt(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfJmin]; ok {
		out.Jmin, err = asInt(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfJmax]; ok {
		out.Jmax, err = asInt(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfS1]; ok {
		out.S1, err = asInt(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfS2]; ok {
		out.S2, err = asInt(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfS3]; ok {
		out.S3, err = asInt(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfS4]; ok {
		out.S4, err = asInt(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfH1]; ok {
		out.H1, err = asString(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfH2]; ok {
		out.H2, err = asString(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfH3]; ok {
		out.H3, err = asString(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfH4]; ok {
		out.H4, err = asString(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfI1]; ok {
		out.I1, err = asString(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfI2]; ok {
		out.I2, err = asString(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfI3]; ok {
		out.I3, err = asString(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfI4]; ok {
		out.I4, err = asString(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfI5]; ok {
		out.I5, err = asString(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfServerPrivateKey]; ok {
		rawBytes, ok := v.([]byte)
		if !ok {
			return profile.ObfConfig{}, fmt.Errorf("server_private_key: expected bytes")
		}
		out.ServerPrivateKey = base64.StdEncoding.EncodeToString(rawBytes)
	}
	if v, ok := raw[keyObfServerPublicKey]; ok {
		rawBytes, ok := v.([]byte)
		if !ok {
			return profile.ObfConfig{}, fmt.Errorf("server_public_key: expected bytes")
		}
		out.ServerPublicKey = base64.StdEncoding.EncodeToString(rawBytes)
	}
	if v, ok := raw[keyObfSignatureValidate]; ok {
		val, err := asBool(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.SignatureValidate = &val
	}
	if v, ok := raw[keyObfRequireTimestamp]; ok {
		val, err := asBool(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.RequireTimestamp = &val
	}
	if v, ok := raw[keyObfEncryptedTimestamp]; ok {
		val, err := asBool(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.EncryptedTimestamp = &val
	}
	if v, ok := raw[keyObfRequireEncryptedTimestamp]; ok {
		val, err := asBool(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.RequireEncryptedTimestamp = &val
	}
	if v, ok := raw[keyObfLegacyModeEnabled]; ok {
		val, err := asBool(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.LegacyModeEnabled = &val
	}
	if v, ok := raw[keyObfLegacyModeSunset]; ok {
		out.LegacyModeSunset, err = asString(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
	}
	if v, ok := raw[keyObfLegacyModeMaxDays]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.LegacyModeMaxDays = int(val)
	}
	if v, ok := raw[keyObfSkewSoftSeconds]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.SkewSoftSeconds = int(val)
	}
	if v, ok := raw[keyObfSkewHardSeconds]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.SkewHardSeconds = int(val)
	}
	if v, ok := raw[keyObfReplayWindowSeconds]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.ReplayWindowSeconds = int(val)
	}
	if v, ok := raw[keyObfReplayCacheSize]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.ReplayCacheSize = int(val)
	}
	if v, ok := raw[keyObfTransportReplay]; ok {
		val, err := asBool(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.TransportReplay = val
	}
	if v, ok := raw[keyObfTransportReplayLimit]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.TransportReplayLimit = val
	}
	if v, ok := raw[keyObfRateLimitPPS]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.RateLimitPPS = int(val)
	}
	if v, ok := raw[keyObfRateLimitBurst]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.ObfConfig{}, err
		}
		out.RateLimitBurst = int(val)
	}
	return out, nil
}

func decodePadding(value any) (profile.TransportPadding, error) {
	raw, err := asMapUint(value)
	if err != nil {
		return profile.TransportPadding{}, fmt.Errorf("expected map: %w", err)
	}
	var out profile.TransportPadding
	if v, ok := raw[keyPadMin]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.TransportPadding{}, err
		}
		valInt := int(val)
		out.Min = &valInt
	}
	if v, ok := raw[keyPadMax]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.TransportPadding{}, err
		}
		valInt := int(val)
		out.Max = &valInt
	}
	if v, ok := raw[keyPadBurstMin]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.TransportPadding{}, err
		}
		valInt := int(val)
		out.BurstMin = &valInt
	}
	if v, ok := raw[keyPadBurstMax]; ok {
		val, err := asUint(v)
		if err != nil {
			return profile.TransportPadding{}, err
		}
		valInt := int(val)
		out.BurstMax = &valInt
	}
	if v, ok := raw[keyPadBurstProb]; ok {
		val, err := asFloat(v)
		if err != nil {
			return profile.TransportPadding{}, err
		}
		out.BurstProb = &val
	}
	return out, nil
}

func shouldIncludeDuration(value time.Duration, def time.Duration) bool {
	if value <= 0 {
		return false
	}
	return value != def
}

func shouldIncludeInt(value int, def int) bool {
	if value <= 0 {
		return false
	}
	return value != def
}

func asUint(value any) (uint64, error) {
	switch v := value.(type) {
	case uint64:
		return v, nil
	case uint32:
		return uint64(v), nil
	case uint16:
		return uint64(v), nil
	case uint8:
		return uint64(v), nil
	case uint:
		return uint64(v), nil
	case int64:
		if v < 0 {
			return 0, fmt.Errorf("negative value")
		}
		return uint64(v), nil
	case int:
		if v < 0 {
			return 0, fmt.Errorf("negative value")
		}
		return uint64(v), nil
	default:
		return 0, fmt.Errorf("unexpected type %T", value)
	}
}

func asInt(value any) (int, error) {
	switch v := value.(type) {
	case uint64:
		if v > uint64(^uint(0)>>1) {
			return 0, fmt.Errorf("overflow")
		}
		return int(v), nil
	case uint:
		return int(v), nil
	case int64:
		return int(v), nil
	case int:
		return v, nil
	default:
		return 0, fmt.Errorf("unexpected type %T", value)
	}
}

func asString(value any) (string, error) {
	if value == nil {
		return "", nil
	}
	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("expected string got %T", value)
	}
	return str, nil
}

func asBool(value any) (bool, error) {
	val, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("expected bool got %T", value)
	}
	return val, nil
}

func asFloat(value any) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	default:
		return 0, fmt.Errorf("expected float got %T", value)
	}
}

func asMapUint(value any) (map[uint64]any, error) {
	switch m := value.(type) {
	case map[uint64]any:
		return m, nil
	case map[any]any:
		out := make(map[uint64]any, len(m))
		for key, val := range m {
			k, err := asUint(key)
			if err != nil {
				return nil, err
			}
			out[k] = val
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unexpected type %T", value)
	}
}
