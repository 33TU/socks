package shadowsocks

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/zeebo/blake3"
)

// blake3SessionSubkeyContext is the context string used for deriving session subkeys with Blake3 in Shadowsocks 2022 methods.
const blake3SessionSubkeyContext = "shadowsocks 2022 session subkey"

// DecodePSKTo decodes and validates a base64 PSK for the given method into dst.
// The returned slice may reuse dst's backing array.
func DecodePSKTo(dst []byte, method Method, s string) ([]byte, error) {
	if err := method.Validate(); err != nil {
		return nil, err
	}
	if s == "" {
		return nil, fmt.Errorf("missing PSK")
	}

	key, err := base64.StdEncoding.AppendDecode(dst[:0], []byte(s))
	if err != nil {
		return nil, fmt.Errorf("invalid PSK: %w", err)
	}
	if len(key) != method.KeySize {
		return nil, fmt.Errorf("invalid PSK length: got %d, want %d", len(key), method.KeySize)
	}

	return key, nil
}

// FillSaltTo fills dst with a random salt for the given method.
func FillSaltTo(dst []byte, method Method) error {
	if err := method.Validate(); err != nil {
		return err
	}
	if len(dst) != method.SaltSize {
		return fmt.Errorf("invalid salt length: got %d, want %d", len(dst), method.SaltSize)
	}

	if _, err := rand.Read(dst); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	return nil
}

// DeriveSubkeyTo derives a session subkey into dst.
func DeriveSubkeyTo(dst []byte, method Method, key, salt []byte) error {
	if err := method.Validate(); err != nil {
		return err
	}
	if len(key) != method.KeySize {
		return fmt.Errorf("invalid key length: got %d, want %d", len(key), method.KeySize)
	}
	if len(salt) != method.SaltSize {
		return fmt.Errorf("invalid salt length: got %d, want %d", len(salt), method.SaltSize)
	}
	if len(dst) != method.KeySize {
		return fmt.Errorf("invalid subkey length: got %d, want %d", len(dst), method.KeySize)
	}

	h := blake3.NewDeriveKey(blake3SessionSubkeyContext)
	if _, err := h.Write(key); err != nil {
		return fmt.Errorf("derive subkey: %w", err)
	}
	if _, err := h.Write(salt); err != nil {
		return fmt.Errorf("derive subkey: %w", err)
	}

	sum := h.Sum(nil)
	copy(dst, sum[:method.KeySize])

	return nil
}
