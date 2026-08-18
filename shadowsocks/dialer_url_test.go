package shadowsocks_test

import (
	"encoding/base64"
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

const (
	urlTestMethod = shadowsocks.Method2022Blake3AES128GCM
	urlTestPSK    = "iDN+jVYAcTkUxwNICMTQRA=="
	urlTestHost   = "127.0.0.1:8388"
)

// TestNewDialerFromURL_UserInfoForms covers the spellings of ss:// userinfo in
// circulation: AEAD-2022 links usually carry method:psk directly, while SIP002
// wraps it in base64, and emitters disagree on which alphabet and padding.
func TestNewDialerFromURL_UserInfoForms(t *testing.T) {
	plain := urlTestMethod + ":" + urlTestPSK

	tests := []struct {
		name     string
		userinfo string
	}{
		{"plain method:psk", plain},
		{"base64url no padding", base64.RawURLEncoding.EncodeToString([]byte(plain))},
		{"base64url padded", base64.URLEncoding.EncodeToString([]byte(plain))},
		{"base64 std no padding", base64.RawStdEncoding.EncodeToString([]byte(plain))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := shadowsocks.NewDialerFromURLString("ss://"+tt.userinfo+"@"+urlTestHost, nil)
			if err != nil {
				t.Fatalf("NewDialerFromURLString() error = %v", err)
			}
			if d.ProxyAddress() != urlTestHost {
				t.Errorf("proxy address = %s, want %s", d.ProxyAddress(), urlTestHost)
			}
			if d.Config.Method != urlTestMethod {
				t.Errorf("method = %s, want %s", d.Config.Method, urlTestMethod)
			}
			if d.Config.PSK != urlTestPSK {
				t.Errorf("PSK = %s, want %s", d.Config.PSK, urlTestPSK)
			}
		})
	}
}

// TestNewDialerFromURL_Base64PreservesPluginAndTag checks that the rest of the
// URL is still read when the userinfo is base64.
func TestNewDialerFromURL_Base64PreservesPluginAndTag(t *testing.T) {
	ui := base64.RawURLEncoding.EncodeToString([]byte(urlTestMethod + ":" + urlTestPSK))

	d, err := shadowsocks.NewDialerFromURLString(
		"ss://"+ui+"@"+urlTestHost+"/?plugin=obfs-local#my%20server", nil,
	)
	if err != nil {
		t.Fatalf("NewDialerFromURLString() error = %v", err)
	}
	if d.Config.Plugin != "obfs-local" {
		t.Errorf("plugin = %q, want %q", d.Config.Plugin, "obfs-local")
	}
	if d.Config.Tag != "my server" {
		t.Errorf("tag = %q, want %q", d.Config.Tag, "my server")
	}
}

func TestNewDialerFromURL_RejectsBadUserInfo(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"no userinfo", "ss://" + urlTestHost},
		{"method only, no psk", "ss://" + urlTestMethod + "@" + urlTestHost},
		{"base64 without a colon", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("nocolon")) + "@" + urlTestHost},
		{"base64 with empty psk", "ss://" + base64.RawURLEncoding.EncodeToString([]byte(urlTestMethod+":")) + "@" + urlTestHost},
		{"unknown method in base64", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("rc4-md5:secret")) + "@" + urlTestHost},
		{"wrong PSK size in base64", "ss://" + base64.RawURLEncoding.EncodeToString([]byte(urlTestMethod+":c2hvcnQ=")) + "@" + urlTestHost},
		{"empty psk in plain form", "ss://" + urlTestMethod + ":@" + urlTestHost},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := shadowsocks.NewDialerFromURLString(tt.url, nil); err == nil {
				t.Fatalf("NewDialerFromURLString(%q) = nil error, want rejection", tt.url)
			}
		})
	}
}
