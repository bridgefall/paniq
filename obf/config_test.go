package obf

import "testing"

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid defaults",
			cfg:  Config{},
		},
		{
			name: "bad jmin jmax",
			cfg: Config{
				Jmin: 10,
				Jmax: 5,
			},
			wantErr: true,
		},
		{
			name: "negative padding",
			cfg: Config{
				S1: -1,
			},
			wantErr: true,
		},
		{
			name: "negative jc",
			cfg: Config{
				Jc: -1,
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
