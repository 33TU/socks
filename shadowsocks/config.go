package shadowsocks

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Config holds the configuration for a Shadowsocks proxy.
type Config struct {
	Method string
	PSK    string
	Plugin string
	Tag    string
}

// Validate checks if the Config is valid and returns an error if not.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("nil config")
	}

	switch c.Method {
	case Method2022Blake3AES128GCM,
		Method2022Blake3AES256GCM,
		Method2022Blake3ChaCha20Poly1305:
	default:
		return fmt.Errorf("invalid method: %s", c.Method)
	}

	if c.PSK == "" {
		return fmt.Errorf("missing PSK")
	}

	want := 32
	if c.Method == Method2022Blake3AES128GCM {
		want = 16
	}

	// A chain of keys names a user through identity headers: any identity PSKs
	// first, then the user PSK the session itself uses.
	list := c.PSKList()

	for i, psk := range list {
		// The position only helps when there is more than one key.
		label := "invalid PSK"
		if len(list) > 1 {
			label = fmt.Sprintf("invalid PSK %d", i)
		}

		rawKey, err := base64.StdEncoding.DecodeString(psk)
		if err != nil {
			return fmt.Errorf("%s: must be standard base64: %w", label, err)
		}
		if len(rawKey) != want {
			return fmt.Errorf("%s length for %s: got %d, want %d", label, c.Method, len(rawKey), want)
		}
	}

	return nil
}

// PSKList returns the configured keys: any identity PSKs in order, followed by
// the user PSK. A single key is just the user PSK.
func (c *Config) PSKList() []string {
	if c == nil || c.PSK == "" {
		return nil
	}
	return strings.Split(c.PSK, ":")
}
