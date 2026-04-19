package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// MethodKind identifies the AEAD cipher family used by a Shadowsocks method.
type MethodKind uint8

const (
	MethodKindUnknown MethodKind = iota
	MethodKindAESGCM
	MethodKindChaCha20Poly1305
)

// Method describes a supported Shadowsocks method and its cryptographic parameters.
type Method struct {
	Kind      MethodKind
	KeySize   int
	SaltSize  int
	NonceSize int
	TagSize   int
}

var (
	method2022Blake3AES128GCM = Method{
		Kind:      MethodKindAESGCM,
		KeySize:   16,
		SaltSize:  16,
		NonceSize: AeadNonceSize,
		TagSize:   AeadTagSize,
	}

	method2022Blake3AES256GCM = Method{
		Kind:      MethodKindAESGCM,
		KeySize:   32,
		SaltSize:  32,
		NonceSize: AeadNonceSize,
		TagSize:   AeadTagSize,
	}

	method2022Blake3ChaCha20Poly1305 = Method{
		Kind:      MethodKindChaCha20Poly1305,
		KeySize:   32,
		SaltSize:  32,
		NonceSize: AeadNonceSize,
		TagSize:   AeadTagSize,
	}
)

// ParseMethod parses a Shadowsocks method name into its method definition.
func ParseMethod(name string) (Method, error) {
	switch name {
	case Method2022Blake3AES128GCM:
		return method2022Blake3AES128GCM, nil
	case Method2022Blake3AES256GCM:
		return method2022Blake3AES256GCM, nil
	case Method2022Blake3ChaCha20Poly1305:
		return method2022Blake3ChaCha20Poly1305, nil
	default:
		return Method{}, fmt.Errorf("invalid method: %s", name)
	}
}

// IsSupportedMethod reports whether name is a supported Shadowsocks method.
func IsSupportedMethod(name string) bool {
	_, err := ParseMethod(name)
	return err == nil
}

// Validate checks whether the method definition is internally valid.
func (m Method) Validate() error {
	switch m.Kind {
	case MethodKindAESGCM, MethodKindChaCha20Poly1305:
	default:
		return fmt.Errorf("invalid method kind: %d", m.Kind)
	}

	if m.KeySize <= 0 {
		return fmt.Errorf("invalid key size: %d", m.KeySize)
	}
	if m.SaltSize <= 0 {
		return fmt.Errorf("invalid salt size: %d", m.SaltSize)
	}
	if m.NonceSize <= 0 {
		return fmt.Errorf("invalid nonce size: %d", m.NonceSize)
	}
	if m.TagSize <= 0 {
		return fmt.Errorf("invalid tag size: %d", m.TagSize)
	}

	return nil
}

// NewAEAD constructs a new AEAD instance for the method using key.
func (m Method) NewAEAD(key []byte) (cipher.AEAD, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if len(key) != m.KeySize {
		return nil, fmt.Errorf("invalid key length: got %d, want %d", len(key), m.KeySize)
	}

	var aead cipher.AEAD

	switch m.Kind {
	case MethodKindAESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("create AES cipher: %w", err)
		}

		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("create AES-GCM: %w", err)
		}

	case MethodKindChaCha20Poly1305:
		var err error
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("create ChaCha20-Poly1305: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported method kind: %d", m.Kind)
	}

	if aead.NonceSize() != m.NonceSize {
		return nil, fmt.Errorf("unexpected nonce size: got %d, want %d", aead.NonceSize(), m.NonceSize)
	}
	if aead.Overhead() != m.TagSize {
		return nil, fmt.Errorf("unexpected tag size: got %d, want %d", aead.Overhead(), m.TagSize)
	}

	return aead, nil
}
