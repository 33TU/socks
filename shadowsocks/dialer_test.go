package shadowsocks_test

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	socksnet "github.com/33TU/socks/net"
	"github.com/33TU/socks/shadowsocks"
)

func mustBase64Key(n int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, n))
}

func TestNewDialerFromURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		rawURL     string
		wantAddr   string
		wantMethod string
		wantPSK    string
		wantPlugin string
		wantTag    string
		wantErr    string
	}{
		{
			name:       "valid aes-256-gcm",
			rawURL:     "ss://2022-blake3-aes-256-gcm:" + url.QueryEscape(mustBase64Key(32)) + "@127.0.0.1:8388",
			wantAddr:   "127.0.0.1:8388",
			wantMethod: shadowsocks.Method2022Blake3AES256GCM,
			wantPSK:    mustBase64Key(32),
		},
		{
			name:       "valid aes-128-gcm with plugin and tag",
			rawURL:     "ss://2022-blake3-aes-128-gcm:" + url.QueryEscape(mustBase64Key(16)) + "@proxy.example.com:443/?plugin=" + url.QueryEscape("v2ray-plugin;server;host=example.com") + "#edge",
			wantAddr:   "proxy.example.com:443",
			wantMethod: shadowsocks.Method2022Blake3AES128GCM,
			wantPSK:    mustBase64Key(16),
			wantPlugin: "v2ray-plugin;server;host=example.com",
			wantTag:    "edge",
		},
		{
			name:       "valid chacha20-poly1305",
			rawURL:     "ss://2022-blake3-chacha20-poly1305:" + url.QueryEscape(mustBase64Key(32)) + "@example.com:8443#demo",
			wantAddr:   "example.com:8443",
			wantMethod: shadowsocks.Method2022Blake3ChaCha20Poly1305,
			wantPSK:    mustBase64Key(32),
			wantTag:    "demo",
		},
		{
			name:    "nil url",
			wantErr: "nil proxy URL",
		},
		{
			name:    "invalid scheme",
			rawURL:  "http://127.0.0.1:8388",
			wantErr: "invalid scheme",
		},
		{
			name:    "missing host",
			rawURL:  "ss://2022-blake3-aes-256-gcm:" + url.QueryEscape(mustBase64Key(32)) + "@:8388",
			wantErr: "missing host",
		},
		{
			name:    "missing port",
			rawURL:  "ss://2022-blake3-aes-256-gcm:" + url.QueryEscape(mustBase64Key(32)) + "@127.0.0.1",
			wantErr: "missing port",
		},
		{
			name:    "missing userinfo",
			rawURL:  "ss://127.0.0.1:8388",
			wantErr: "missing method/psk",
		},
		{
			name:    "missing method",
			rawURL:  "ss://:" + url.QueryEscape(mustBase64Key(32)) + "@127.0.0.1:8388",
			wantErr: "missing method",
		},
		{
			name:    "missing psk",
			rawURL:  "ss://2022-blake3-aes-256-gcm@127.0.0.1:8388",
			wantErr: "missing PSK",
		},
		{
			name:    "invalid method",
			rawURL:  "ss://aes-256-gcm:" + url.QueryEscape(mustBase64Key(32)) + "@127.0.0.1:8388",
			wantErr: "invalid proxy URL",
		},
		{
			name:    "invalid psk length for aes-128",
			rawURL:  "ss://2022-blake3-aes-128-gcm:" + url.QueryEscape(mustBase64Key(32)) + "@127.0.0.1:8388",
			wantErr: "invalid proxy URL",
		},
		{
			name:    "invalid psk base64",
			rawURL:  "ss://2022-blake3-aes-256-gcm:not-base64!!!@127.0.0.1:8388",
			wantErr: "invalid proxy URL",
		},
		{
			name:       "ipv6 host",
			rawURL:     "ss://2022-blake3-aes-256-gcm:" + url.QueryEscape(mustBase64Key(32)) + "@[2001:db8::1]:8388",
			wantAddr:   "[2001:db8::1]:8388",
			wantMethod: shadowsocks.Method2022Blake3AES256GCM,
			wantPSK:    mustBase64Key(32),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.wantErr == "nil proxy URL" {
				d, err := shadowsocks.NewDialerFromURL(nil, nil)
				if d != nil {
					t.Fatal("expected nil dialer")
				}
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}

			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}

			d, err := shadowsocks.NewDialerFromURL(u, nil)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("NewDialerFromURL() error = %v", err)
			}
			if d == nil {
				t.Fatal("NewDialerFromURL() returned nil dialer")
			}
			if d.ProxyAddr != tt.wantAddr {
				t.Fatalf("ProxyAddr = %q, want %q", d.ProxyAddr, tt.wantAddr)
			}
			if d.Config == nil {
				t.Fatal("Config is nil")
			}
			if d.Config.Method != tt.wantMethod {
				t.Fatalf("Config.Method = %q, want %q", d.Config.Method, tt.wantMethod)
			}
			if d.Config.PSK != tt.wantPSK {
				t.Fatalf("Config.PSK = %q, want %q", d.Config.PSK, tt.wantPSK)
			}
			if d.Config.Plugin != tt.wantPlugin {
				t.Fatalf("Config.Plugin = %q, want %q", d.Config.Plugin, tt.wantPlugin)
			}
			if d.Config.Tag != tt.wantTag {
				t.Fatalf("Config.Tag = %q, want %q", d.Config.Tag, tt.wantTag)
			}
			if d.Dialer == nil {
				t.Fatal("Dialer is nil, want default dialer")
			}
		})
	}
}

func TestNewDialerFromURLString(t *testing.T) {
	t.Parallel()

	rawURL := "ss://2022-blake3-aes-256-gcm:" + url.QueryEscape(mustBase64Key(32)) + "@127.0.0.1:8388/?plugin=" + url.QueryEscape("simple-obfs") + "#local"

	d, err := shadowsocks.NewDialerFromURLString(rawURL, socksnet.DefaultDialer)
	if err != nil {
		t.Fatalf("NewDialerFromURLString() error = %v", err)
	}
	if d == nil {
		t.Fatal("NewDialerFromURLString() returned nil dialer")
	}
	if d.ProxyAddr != "127.0.0.1:8388" {
		t.Fatalf("ProxyAddr = %q, want %q", d.ProxyAddr, "127.0.0.1:8388")
	}
	if d.Config == nil {
		t.Fatal("Config is nil")
	}
	if d.Config.Method != shadowsocks.Method2022Blake3AES256GCM {
		t.Fatalf("Config.Method = %q, want %q", d.Config.Method, shadowsocks.Method2022Blake3AES256GCM)
	}
	if d.Config.Plugin != "simple-obfs" {
		t.Fatalf("Config.Plugin = %q, want %q", d.Config.Plugin, "simple-obfs")
	}
	if d.Config.Tag != "local" {
		t.Fatalf("Config.Tag = %q, want %q", d.Config.Tag, "local")
	}
}
