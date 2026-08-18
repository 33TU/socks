package shadowsocks_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	psk16 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	psk32 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	psk15 := base64.StdEncoding.EncodeToString(make([]byte, 15))
	psk31 := base64.StdEncoding.EncodeToString(make([]byte, 31))

	tests := []struct {
		name    string
		cfg     *shadowsocks.Config
		wantErr string
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: "nil config",
		},
		{
			name: "valid aes128",
			cfg: &shadowsocks.Config{
				Method: shadowsocks.Method2022Blake3AES128GCM,
				PSK:    psk16,
			},
		},
		{
			name: "valid aes256",
			cfg: &shadowsocks.Config{
				Method: shadowsocks.Method2022Blake3AES256GCM,
				PSK:    psk32,
			},
		},
		{
			name: "valid chacha20",
			cfg: &shadowsocks.Config{
				Method: shadowsocks.Method2022Blake3ChaCha20Poly1305,
				PSK:    psk32,
			},
		},
		{
			name: "invalid method",
			cfg: &shadowsocks.Config{
				Method: "invalid-method",
				PSK:    psk32,
			},
			wantErr: "invalid method",
		},
		{
			name: "missing psk",
			cfg: &shadowsocks.Config{
				Method: shadowsocks.Method2022Blake3AES128GCM,
			},
			wantErr: "missing PSK",
		},
		{
			name: "invalid base64",
			cfg: &shadowsocks.Config{
				Method: shadowsocks.Method2022Blake3AES128GCM,
				PSK:    "!!!not-base64!!!",
			},
			wantErr: "invalid PSK: must be standard base64",
		},
		{
			name: "invalid aes128 key length",
			cfg: &shadowsocks.Config{
				Method: shadowsocks.Method2022Blake3AES128GCM,
				PSK:    psk15,
			},
			wantErr: "invalid PSK length",
		},
		{
			name: "invalid aes256 key length",
			cfg: &shadowsocks.Config{
				Method: shadowsocks.Method2022Blake3AES256GCM,
				PSK:    psk31,
			},
			wantErr: "invalid PSK length",
		},
		{
			name: "invalid chacha20 key length",
			cfg: &shadowsocks.Config{
				Method: shadowsocks.Method2022Blake3ChaCha20Poly1305,
				PSK:    psk31,
			},
			wantErr: "invalid PSK length",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}
