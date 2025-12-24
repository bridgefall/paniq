package cborprofile

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/bridgefall/transport/commons/config"
	"github.com/bridgefall/transport/profile"
	"github.com/fxamacker/cbor/v2"
)

func TestJSONCBORJSONRoundTrip(t *testing.T) {
	input := []byte(`{
  "name": "test",
  "proxy_addr": "127.0.0.1:9000",
  "handshake_timeout": "5s",
  "handshake_attempts": 3,
  "preamble_delay_ms": 5,
  "preamble_jitter_ms": 3,
  "quic": {
    "max_packet_size": 1350,
    "max_payload": 1200,
    "keepalive": "20s",
    "idle_timeout": "2m",
    "max_streams": 256
  },
  "transport_padding": {
    "pad_min": 0,
    "pad_max": 64,
    "pad_burst_min": 128,
    "pad_burst_max": 256,
    "pad_burst_prob": 0.02
  },
  "obfuscation": {
    "jc": 4,
    "jmin": 200,
    "jmax": 1202,
    "s1": 339,
    "s2": 432,
    "s3": 213,
    "s4": 126,
    "h1": "1662442204",
    "h2": "793654571",
    "h3": "468452595",
    "h4": "1578142977",
    "i1": "<t>",
    "i2": "",
    "i3": "",
    "i4": "",
    "i5": "",
    "server_public_key": "N2q78AwSzvTwmB9IAEdPTrHIzlyPBvwUQvWQu7eARzk=",
    "encrypted_timestamp": true,
    "transport_replay": true,
    "transport_replay_limit": 10
  }
}`)

	cborData, err := EncodeJSONProfile(input)
	if err != nil {
		t.Fatalf("encode json to cbor: %v", err)
	}
	outJSON, err := DecodeCBORToJSON(cborData)
	if err != nil {
		t.Fatalf("decode cbor to json: %v", err)
	}
	var inProfile profile.Profile
	if err := json.Unmarshal(input, &inProfile); err != nil {
		t.Fatalf("unmarshal input: %v", err)
	}
	var outProfile profile.Profile
	if err := json.Unmarshal(outJSON, &outProfile); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if !semanticEqualProfile(inProfile, outProfile) {
		t.Fatalf("profile semantics mismatch after round-trip")
	}
}

func TestDeterministicEncoding(t *testing.T) {
	p := profile.Profile{
		Name:              "test",
		ProxyAddr:         "127.0.0.1:9000",
		HandshakeTimeout:  config.Duration{Duration: 5 * time.Second},
		HandshakeAttempts: 3,
	}
	a, err := EncodeProfile(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	b, err := EncodeProfile(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("encoding not deterministic")
	}
}

func TestVersionHandling(t *testing.T) {
	payload := map[uint64]any{
		keyVersion:   uint64(Version + 1),
		keyProxyAddr: "127.0.0.1:9000",
	}
	mode, err := cborEncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	data, err := mode.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := DecodeProfile(data); err == nil {
		t.Fatalf("expected version error")
	}
}

func semanticEqualProfile(a, b profile.Profile) bool {
	normalize := func(p profile.Profile) profile.Profile {
		if p.HandshakeTimeout.Duration == 0 {
			p.HandshakeTimeout = config.Duration{Duration: defaultHandshakeTimeout}
		}
		if p.HandshakeAttempts == 0 {
			p.HandshakeAttempts = defaultHandshakeAttempts
		}
		if p.Quic.MaxPacketSize == 0 {
			p.Quic.MaxPacketSize = defaultQuicMaxPacketSize
		}
		if p.Quic.KeepAlive.Duration == 0 {
			p.Quic.KeepAlive = config.Duration{Duration: defaultQuicKeepAlive}
		}
		if p.Quic.IdleTimeout.Duration == 0 {
			p.Quic.IdleTimeout = config.Duration{Duration: defaultQuicIdleTimeout}
		}
		if p.Quic.MaxStreams == 0 {
			p.Quic.MaxStreams = defaultQuicMaxStreams
		}
		return p
	}
	na := normalize(a)
	nb := normalize(b)
	if na.Name != nb.Name ||
		na.ProxyAddr != nb.ProxyAddr ||
		na.HandshakeTimeout.Duration != nb.HandshakeTimeout.Duration ||
		na.HandshakeAttempts != nb.HandshakeAttempts ||
		na.PreambleDelayMs != nb.PreambleDelayMs ||
		na.PreambleJitterMs != nb.PreambleJitterMs ||
		na.Quic.MaxPacketSize != nb.Quic.MaxPacketSize ||
		na.Quic.MaxPayload != nb.Quic.MaxPayload ||
		na.Quic.KeepAlive.Duration != nb.Quic.KeepAlive.Duration ||
		na.Quic.IdleTimeout.Duration != nb.Quic.IdleTimeout.Duration ||
		na.Quic.MaxStreams != nb.Quic.MaxStreams ||
		!reflect.DeepEqual(na.Obfuscation, nb.Obfuscation) {
		return false
	}
	ap, _ := na.TransportPadding.Resolve()
	bp, _ := nb.TransportPadding.Resolve()
	return ap == bp
}

func cborEncMode() (cbor.EncMode, error) {
	return cbor.CanonicalEncOptions().EncMode()
}
