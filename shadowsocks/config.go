package shadowsocks

import (
	"encoding/base64"
	"fmt"
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

	rawKey, err := base64.StdEncoding.DecodeString(c.PSK)
	if err != nil {
		return fmt.Errorf("invalid PSK: must be standard base64: %w", err)
	}

	switch c.Method {
	case Method2022Blake3AES128GCM:
		if len(rawKey) != 16 {
			return fmt.Errorf("invalid PSK length for %s: got %d, want 16", c.Method, len(rawKey))
		}
	case Method2022Blake3AES256GCM, Method2022Blake3ChaCha20Poly1305:
		if len(rawKey) != 32 {
			return fmt.Errorf("invalid PSK length for %s: got %d, want 32", c.Method, len(rawKey))
		}
	}

	return nil
}
