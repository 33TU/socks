package shadowsocks_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func TestDecodePSKTo(t *testing.T) {
	t.Parallel()

	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	validRaw := make([]byte, method.KeySize)
	for i := range validRaw {
		validRaw[i] = byte(i + 1)
	}

	validPSK := base64.StdEncoding.EncodeToString(validRaw)
	shortPSK := base64.StdEncoding.EncodeToString(make([]byte, method.KeySize-1))

	tests := []struct {
		name    string
		method  shadowsocks.Method
		psk     string
		want    []byte
		wantErr string
	}{
		{
			name:   "valid",
			method: method,
			psk:    validPSK,
			want:   validRaw,
		},
		{
			name:    "missing psk",
			method:  method,
			psk:     "",
			wantErr: "missing PSK",
		},
		{
			name:    "invalid base64",
			method:  method,
			psk:     "!!!",
			wantErr: "invalid PSK",
		},
		{
			name:    "invalid key length",
			method:  method,
			psk:     shortPSK,
			wantErr: "invalid PSK length",
		},
		{
			name: "invalid method",
			method: shadowsocks.Method{
				Kind: shadowsocks.MethodKindUnknown,
			},
			psk:     validPSK,
			wantErr: "invalid method kind",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := shadowsocks.DecodePSKTo(nil, tt.method, tt.psk)
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
				t.Fatalf("DecodePSKTo() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("DecodePSKTo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodePSKTo_ReuseDst(t *testing.T) {
	t.Parallel()

	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	raw := make([]byte, method.KeySize)
	for i := range raw {
		raw[i] = byte(i + 1)
	}

	psk := base64.StdEncoding.EncodeToString(raw)
	dst := make([]byte, 0, 64)

	got, err := shadowsocks.DecodePSKTo(dst, method, psk)
	if err != nil {
		t.Fatalf("DecodePSKTo() error = %v", err)
	}

	if !bytes.Equal(got, raw) {
		t.Fatalf("DecodePSKTo() = %v, want %v", got, raw)
	}
}

func TestFillSalt(t *testing.T) {
	t.Parallel()

	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES256GCM)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		salt := make([]byte, method.SaltSize)
		if err := shadowsocks.FillSalt(salt, method); err != nil {
			t.Fatalf("FillSalt() error = %v", err)
		}

		if len(salt) != method.SaltSize {
			t.Fatalf("len(salt) = %d, want %d", len(salt), method.SaltSize)
		}

		if bytes.Equal(salt, make([]byte, method.SaltSize)) {
			t.Fatal("salt is all zeros, expected random data")
		}
	})

	t.Run("invalid salt length", func(t *testing.T) {
		t.Parallel()

		salt := make([]byte, method.SaltSize-1)
		err := shadowsocks.FillSalt(salt, method)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid salt length") {
			t.Fatalf("expected invalid salt length error, got %q", err.Error())
		}
	})

	t.Run("invalid method", func(t *testing.T) {
		t.Parallel()

		err := shadowsocks.FillSalt(make([]byte, 16), shadowsocks.Method{})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid method kind") {
			t.Fatalf("expected invalid method kind error, got %q", err.Error())
		}
	})
}

func TestDeriveSubkeyTo(t *testing.T) {
	t.Parallel()

	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES256GCM)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	key := make([]byte, method.KeySize)
	salt := make([]byte, method.SaltSize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range salt {
		salt[i] = byte(i + 101)
	}

	t.Run("valid deterministic", func(t *testing.T) {
		t.Parallel()

		dst1 := make([]byte, method.KeySize)
		dst2 := make([]byte, method.KeySize)

		if err := shadowsocks.DeriveSubkeyTo(dst1, method, key, salt); err != nil {
			t.Fatalf("DeriveSubkeyTo() error = %v", err)
		}
		if err := shadowsocks.DeriveSubkeyTo(dst2, method, key, salt); err != nil {
			t.Fatalf("DeriveSubkeyTo() error = %v", err)
		}

		if !bytes.Equal(dst1, dst2) {
			t.Fatal("derived subkeys differ for same key and salt")
		}
		if bytes.Equal(dst1, make([]byte, method.KeySize)) {
			t.Fatal("derived subkey is all zeros")
		}
	})

	t.Run("invalid key length", func(t *testing.T) {
		t.Parallel()

		dst := make([]byte, method.KeySize)
		err := shadowsocks.DeriveSubkeyTo(dst, method, key[:len(key)-1], salt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid key length") {
			t.Fatalf("expected invalid key length error, got %q", err.Error())
		}
	})

	t.Run("invalid salt length", func(t *testing.T) {
		t.Parallel()

		dst := make([]byte, method.KeySize)
		err := shadowsocks.DeriveSubkeyTo(dst, method, key, salt[:len(salt)-1])
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid salt length") {
			t.Fatalf("expected invalid salt length error, got %q", err.Error())
		}
	})

	t.Run("invalid subkey length", func(t *testing.T) {
		t.Parallel()

		dst := make([]byte, method.KeySize-1)
		err := shadowsocks.DeriveSubkeyTo(dst, method, key, salt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid subkey length") {
			t.Fatalf("expected invalid subkey length error, got %q", err.Error())
		}
	})

	t.Run("invalid method", func(t *testing.T) {
		t.Parallel()

		err := shadowsocks.DeriveSubkeyTo(make([]byte, 16), shadowsocks.Method{}, make([]byte, 16), make([]byte, 16))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid method kind") {
			t.Fatalf("expected invalid method kind error, got %q", err.Error())
		}
	})
}
