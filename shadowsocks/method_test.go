package shadowsocks_test

import (
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func TestParseMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		methodName string
		wantKind   shadowsocks.MethodKind
		wantKeyLen int
		wantErr    bool
	}{
		{
			name:       "aes128",
			methodName: shadowsocks.Method2022Blake3AES128GCM,
			wantKind:   shadowsocks.MethodKindAESGCM,
			wantKeyLen: 16,
		},
		{
			name:       "aes256",
			methodName: shadowsocks.Method2022Blake3AES256GCM,
			wantKind:   shadowsocks.MethodKindAESGCM,
			wantKeyLen: 32,
		},
		{
			name:       "chacha20",
			methodName: shadowsocks.Method2022Blake3ChaCha20Poly1305,
			wantKind:   shadowsocks.MethodKindChaCha20Poly1305,
			wantKeyLen: 32,
		},
		{
			name:       "invalid",
			methodName: "invalid-method",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := shadowsocks.ParseMethod(tt.methodName)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMethod() error = %v", err)
			}

			if m.Kind != tt.wantKind {
				t.Fatalf("Kind = %v, want %v", m.Kind, tt.wantKind)
			}
			if m.KeySize != tt.wantKeyLen {
				t.Fatalf("KeySize = %d, want %d", m.KeySize, tt.wantKeyLen)
			}
		})
	}
}

func TestIsSupportedMethod(t *testing.T) {
	t.Parallel()

	if !shadowsocks.IsSupportedMethod(shadowsocks.Method2022Blake3AES128GCM) {
		t.Fatal("expected aes128 method to be supported")
	}
	if shadowsocks.IsSupportedMethod("invalid-method") {
		t.Fatal("expected invalid method to be unsupported")
	}
}

func TestMethodValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  shadowsocks.Method
		wantErr bool
	}{
		{
			name: "valid",
			method: shadowsocks.Method{
				Kind:      shadowsocks.MethodKindAESGCM,
				KeySize:   16,
				SaltSize:  16,
				NonceSize: 12,
				TagSize:   16,
			},
		},
		{
			name: "invalid kind",
			method: shadowsocks.Method{
				Kind:      shadowsocks.MethodKindUnknown,
				KeySize:   16,
				SaltSize:  16,
				NonceSize: 12,
				TagSize:   16,
			},
			wantErr: true,
		},
		{
			name: "invalid key size",
			method: shadowsocks.Method{
				Kind:      shadowsocks.MethodKindAESGCM,
				KeySize:   0,
				SaltSize:  16,
				NonceSize: 12,
				TagSize:   16,
			},
			wantErr: true,
		},
		{
			name: "invalid salt size",
			method: shadowsocks.Method{
				Kind:      shadowsocks.MethodKindAESGCM,
				KeySize:   16,
				SaltSize:  0,
				NonceSize: 12,
				TagSize:   16,
			},
			wantErr: true,
		},
		{
			name: "invalid nonce size",
			method: shadowsocks.Method{
				Kind:      shadowsocks.MethodKindAESGCM,
				KeySize:   16,
				SaltSize:  16,
				NonceSize: 0,
				TagSize:   16,
			},
			wantErr: true,
		},
		{
			name: "invalid tag size",
			method: shadowsocks.Method{
				Kind:      shadowsocks.MethodKindAESGCM,
				KeySize:   16,
				SaltSize:  16,
				NonceSize: 12,
				TagSize:   0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.method.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestMethodNewAEAD(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		methodName string
		keyLen     int
		wantErr    bool
	}{
		{
			name:       "aes128",
			methodName: shadowsocks.Method2022Blake3AES128GCM,
			keyLen:     16,
		},
		{
			name:       "aes256",
			methodName: shadowsocks.Method2022Blake3AES256GCM,
			keyLen:     32,
		},
		{
			name:       "chacha20",
			methodName: shadowsocks.Method2022Blake3ChaCha20Poly1305,
			keyLen:     32,
		},
		{
			name:       "invalid key length",
			methodName: shadowsocks.Method2022Blake3AES128GCM,
			keyLen:     15,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := shadowsocks.ParseMethod(tt.methodName)
			if err != nil {
				t.Fatalf("ParseMethod() error = %v", err)
			}

			aead, err := m.NewAEAD(make([]byte, tt.keyLen))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewAEAD() error = %v", err)
			}

			if aead.NonceSize() != m.NonceSize {
				t.Fatalf("NonceSize = %d, want %d", aead.NonceSize(), m.NonceSize)
			}
			if aead.Overhead() != m.TagSize {
				t.Fatalf("Overhead = %d, want %d", aead.Overhead(), m.TagSize)
			}
		})
	}
}
