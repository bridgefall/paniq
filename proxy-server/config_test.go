package proxyserver

import (
	"testing"

	"github.com/bridgefall/paniq/commons/config"
	"github.com/bridgefall/paniq/profile"
)

func TestFileConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     FileConfig
		profile profile.Profile
		wantErr bool
	}{
		{
			name:    "missing listen",
			cfg:     FileConfig{},
			profile: profile.Profile{},
			wantErr: true,
		},
		{
			name: "valid",
			cfg: FileConfig{
				ListenAddr: "127.0.0.1:9000",
			},
			profile: profile.Profile{
				HandshakeTimeout: config.Duration{},
				Obfuscation: ObfConfig{
					S1: 0, S2: 0, S3: 0, S4: 0,
					H1: "100", H2: "200", H3: "300", H4: "400",
					I1: "<t>",
				},
			},
			wantErr: false,
		},
		{
			name: "missing obfuscation",
			cfg: FileConfig{
				ListenAddr: "127.0.0.1:9000",
			},
			profile: profile.Profile{},
			wantErr: true,
		},
		{
			name: "invalid obfuscation",
			cfg: FileConfig{
				ListenAddr: "127.0.0.1:9000",
			},
			profile: profile.Profile{
				Obfuscation: ObfConfig{Jmin: 10, Jmax: 5},
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
