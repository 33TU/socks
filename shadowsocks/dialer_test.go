package shadowsocks_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	socksnet "github.com/33TU/socks/net"
	"github.com/33TU/socks/shadowsocks"
)

func mustBase64Key(n int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, n))
}

func startMockShadowsocksServer(t *testing.T, handle func(net.Conn)) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()

	return ln.Addr().String(), func() { _ = ln.Close() }
}

func decodePSKForMethod(t *testing.T, method shadowsocks.Method, psk string) []byte {
	t.Helper()

	raw, err := shadowsocks.DecodePSKTo(nil, method, psk)
	if err != nil {
		t.Fatalf("DecodePSKTo() error = %v", err)
	}
	return raw
}

func TestNewDialer(t *testing.T) {
	t.Parallel()

	cfg := &shadowsocks.Config{
		Method: shadowsocks.Method2022Blake3AES256GCM,
		PSK:    mustBase64Key(32),
	}

	d := shadowsocks.NewDialer("127.0.0.1:8388", cfg, nil)
	if d == nil {
		t.Fatal("NewDialer() returned nil")
	}
	if d.ProxyAddr != "127.0.0.1:8388" {
		t.Fatalf("ProxyAddr = %q, want %q", d.ProxyAddr, "127.0.0.1:8388")
	}
	if d.Config != cfg {
		t.Fatal("Config pointer mismatch")
	}
	if d.Dialer == nil {
		t.Fatal("Dialer is nil, want default dialer")
	}
}

func TestDialer_ProxyAddress(t *testing.T) {
	t.Parallel()

	d := &shadowsocks.Dialer{ProxyAddr: "127.0.0.1:8388"}
	if got := d.ProxyAddress(); got != "127.0.0.1:8388" {
		t.Fatalf("ProxyAddress() = %q, want %q", got, "127.0.0.1:8388")
	}
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

func TestNewDialerFromURLString_Invalid(t *testing.T) {
	t.Parallel()

	_, err := shadowsocks.NewDialerFromURLString("://bad url", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid proxy URL") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDialer_DialConnContext_Errors(t *testing.T) {
	t.Parallel()

	t.Run("nil dialer", func(t *testing.T) {
		t.Parallel()

		c1, c2 := net.Pipe()
		defer c2.Close()

		var d *shadowsocks.Dialer
		_, err := d.DialConnContext(context.Background(), c1, "tcp", "example.com:443")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nil shadowsocks dialer") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing config", func(t *testing.T) {
		t.Parallel()

		c1, c2 := net.Pipe()
		defer c2.Close()

		d := &shadowsocks.Dialer{}
		_, err := d.DialConnContext(context.Background(), c1, "tcp", "example.com:443")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing shadowsocks config") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		t.Parallel()

		c1, c2 := net.Pipe()
		defer c2.Close()

		d := &shadowsocks.Dialer{
			Config: &shadowsocks.Config{
				Method: shadowsocks.Method2022Blake3AES128GCM,
				PSK:    mustBase64Key(32),
			},
		}
		_, err := d.DialConnContext(context.Background(), c1, "tcp", "example.com:443")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("invalid target address", func(t *testing.T) {
		t.Parallel()

		c1, c2 := net.Pipe()
		defer c2.Close()

		d := &shadowsocks.Dialer{
			Config: &shadowsocks.Config{
				Method: shadowsocks.Method2022Blake3AES128GCM,
				PSK:    mustBase64Key(16),
			},
		}
		_, err := d.DialConnContext(context.Background(), c1, "tcp", "not-a-hostport")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestDialer_DialContext_Success(t *testing.T) {
	t.Parallel()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	pskB64 := mustBase64Key(16)

	method, err := shadowsocks.ParseMethod(methodName)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}
	psk := decodePSKForMethod(t, method, pskB64)

	proxyAddr, stop := startMockShadowsocksServer(t, func(c net.Conn) {
		defer c.Close()

		var reqStart shadowsocks.TCPServerRequestStart
		_, err := reqStart.ReadRequestStart(c, method, psk)
		if err != nil {
			t.Errorf("server: ReadRequestStart() error = %v", err)
			return
		}

		if reqStart.Header.Target.AddrType != shadowsocks.AddrTypeDomain {
			t.Errorf("server: target type = %v, want domain", reqStart.Header.Target.AddrType)
			return
		}
		if reqStart.Header.Target.Domain != "example.com" {
			t.Errorf("server: target domain = %q, want %q", reqStart.Header.Target.Domain, "example.com")
			return
		}
		if reqStart.Header.Target.Port != 443 {
			t.Errorf("server: target port = %d, want %d", reqStart.Header.Target.Port, 443)
			return
		}

		responseSalt := bytes.Repeat([]byte{0x33}, method.SaltSize)

		var respStart shadowsocks.TCPServerResponseStart
		if err := respStart.Init(method, psk, responseSalt); err != nil {
			t.Errorf("server: response Init() error = %v", err)
			return
		}

		if _, err := respStart.WriteResponseStart(c, time.Now(), reqStart.RequestSalt); err != nil {
			t.Errorf("server: WriteResponseStart() error = %v", err)
			return
		}

		var reader shadowsocks.TCPChunkReader
		if err := reader.Init(reqStart.RequestCipher); err != nil {
			t.Errorf("server: reader Init() error = %v", err)
			return
		}

		var writer shadowsocks.TCPChunkWriter
		if err := writer.Init(respStart.ResponseCipher); err != nil {
			t.Errorf("server: writer Init() error = %v", err)
			return
		}

		payload, _, err := reader.ReadChunkTo(nil, c)
		if err != nil {
			t.Errorf("server: ReadChunk() error = %v", err)
			return
		}
		if string(payload) != "ping" {
			t.Errorf("server: payload = %q, want %q", payload, "ping")
			return
		}

		if _, err := writer.WriteChunk(c, []byte("pong")); err != nil {
			t.Errorf("server: WriteChunk() error = %v", err)
			return
		}
	})
	defer stop()

	d := shadowsocks.NewDialer(proxyAddr, &shadowsocks.Config{
		Method: methodName,
		PSK:    pskB64,
	}, nil)

	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("conn.Write() error = %v", err)
	}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("conn.Read() error = %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("response = %q, want %q", buf, "pong")
	}
}

func TestDialer_DialContext_Deadline(t *testing.T) {
	t.Parallel()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	pskB64 := mustBase64Key(16)

	method, err := shadowsocks.ParseMethod(methodName)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}
	psk := decodePSKForMethod(t, method, pskB64)

	proxyAddr, stop := startMockShadowsocksServer(t, func(c net.Conn) {
		defer c.Close()

		var reqStart shadowsocks.TCPServerRequestStart
		if _, err := reqStart.ReadRequestStart(c, method, psk); err != nil {
			return
		}

		responseSalt := bytes.Repeat([]byte{0x33}, method.SaltSize)

		var respStart shadowsocks.TCPServerResponseStart
		if err := respStart.Init(method, psk, responseSalt); err != nil {
			return
		}
		if _, err := respStart.WriteResponseStart(c, time.Now(), reqStart.RequestSalt); err != nil {
			return
		}

		time.Sleep(200 * time.Millisecond)
	})
	defer stop()

	d := shadowsocks.NewDialer(proxyAddr, &shadowsocks.Config{
		Method: methodName,
		PSK:    pskB64,
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()

	time.Sleep(150 * time.Millisecond)

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected read error after deadline")
	}
}
