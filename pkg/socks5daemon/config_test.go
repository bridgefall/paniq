package socks5daemon

import (
	"testing"

	"github.com/bridgefall/paniq/pkg/commons/config"
	"github.com/bridgefall/paniq/pkg/profile"
)

func TestFileConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     FileConfig
		profile profile.Profile
		wantErr bool
	}{
		{
			name: "missing listen",
			cfg: FileConfig{
				Username: "user",
				Password: "pass",
			},
			profile: profile.Profile{},
			wantErr: true,
		},
		{
			name: "missing credentials",
			cfg: FileConfig{
				ListenAddr: "127.0.0.1:1080",
			},
			profile: profile.Profile{
				ProxyAddr: "127.0.0.1:9000",
				Obfuscation: ObfConfig{
					S1: 0, S2: 0, S3: 0, S4: 0,
					H1: "100", H2: "200", H3: "300", H4: "400",
				},
			},
			wantErr: false,
		},
		{
			name: "valid",
			cfg: FileConfig{
				ListenAddr: "127.0.0.1:1080",
				Username:   "user",
				Password:   "pass",
			},
			profile: profile.Profile{
				ProxyAddr:        "127.0.0.1:9000",
				HandshakeTimeout: config.Duration{},
				Obfuscation: ObfConfig{
					S1: 0, S2: 0, S3: 0, S4: 0,
					H1: "100", H2: "200", H3: "300", H4: "400",
				},
			},
			wantErr: false,
		},
		{
			name: "missing proxy",
			cfg: FileConfig{
				ListenAddr: "127.0.0.1:1080",
				Username:   "user",
				Password:   "pass",
			},
			profile: profile.Profile{
				Obfuscation: ObfConfig{
					S1: 0, S2: 0, S3: 0, S4: 0,
					H1: "100", H2: "200", H3: "300", H4: "400",
				},
			},
			wantErr: true,
		},
		{
			name: "missing obfuscation",
			cfg: FileConfig{
				ListenAddr: "127.0.0.1:1080",
			},
			profile: profile.Profile{
				ProxyAddr: "127.0.0.1:9000",
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.cfg.ToServerConfig(tc.profile)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
