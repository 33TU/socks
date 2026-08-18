package shadowsocks_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func newTestMethod(t *testing.T) shadowsocks.Method {
	t.Helper()

	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	return method
}

func newTestPSKAndSalt(method shadowsocks.Method) ([]byte, []byte) {
	psk := make([]byte, method.KeySize)
	salt := make([]byte, method.SaltSize)

	for i := range psk {
		psk[i] = byte(i + 1)
	}
	for i := range salt {
		salt[i] = byte(i + 101)
	}

	return psk, salt
}

func newTestCipherPair(t *testing.T) (*shadowsocks.TCPStreamCipher, *shadowsocks.TCPStreamCipher, shadowsocks.Method) {
	t.Helper()

	method := newTestMethod(t)
	psk, salt := newTestPSKAndSalt(method)

	enc, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, salt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK(enc) error = %v", err)
	}

	dec, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, salt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK(dec) error = %v", err)
	}

	return enc, dec, method
}

func TestNewTCPStreamCipher(t *testing.T) {
	t.Parallel()

	method := newTestMethod(t)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		subkey := make([]byte, method.KeySize)
		for i := range subkey {
			subkey[i] = byte(i + 1)
		}

		s, err := shadowsocks.NewTCPStreamCipher(method, subkey)
		if err != nil {
			t.Fatalf("NewTCPStreamCipher() error = %v", err)
		}
		if s == nil {
			t.Fatal("NewTCPStreamCipher() returned nil cipher")
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("invalid method", func(t *testing.T) {
		t.Parallel()

		_, err := shadowsocks.NewTCPStreamCipher(shadowsocks.Method{}, make([]byte, 16))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("invalid subkey length", func(t *testing.T) {
		t.Parallel()

		_, err := shadowsocks.NewTCPStreamCipher(method, make([]byte, method.KeySize-1))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid subkey length") {
			t.Fatalf("expected invalid subkey length error, got %q", err.Error())
		}
	})
}

func TestNewTCPStreamCipherFromPSK(t *testing.T) {
	t.Parallel()

	method := newTestMethod(t)
	psk, salt := newTestPSKAndSalt(method)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		s, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, salt)
		if err != nil {
			t.Fatalf("NewTCPStreamCipherFromPSK() error = %v", err)
		}
		if s == nil {
			t.Fatal("NewTCPStreamCipherFromPSK() returned nil cipher")
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("invalid psk length", func(t *testing.T) {
		t.Parallel()

		_, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk[:len(psk)-1], salt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid PSK length") {
			t.Fatalf("expected invalid PSK length error, got %q", err.Error())
		}
	})

	t.Run("invalid salt length", func(t *testing.T) {
		t.Parallel()

		_, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, salt[:len(salt)-1])
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid salt length") {
			t.Fatalf("expected invalid salt length error, got %q", err.Error())
		}
	})
}

func TestTCPStreamCipher_Reset(t *testing.T) {
	t.Parallel()

	s, _, _ := newTestCipherPair(t)

	for i := range s.Nonce {
		s.Nonce[i] = 0xff
	}

	s.Reset()

	var zero [shadowsocks.AeadNonceSize]byte
	if s.Nonce != zero {
		t.Fatalf("Nonce = %v, want zero", s.Nonce)
	}
}

func TestTCPStreamCipher_Validate(t *testing.T) {
	t.Parallel()

	method := newTestMethod(t)
	psk, salt := newTestPSKAndSalt(method)

	valid, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, salt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK() error = %v", err)
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		if err := valid.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("nil cipher", func(t *testing.T) {
		t.Parallel()

		var s *shadowsocks.TCPStreamCipher
		err := s.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nil TCP stream cipher") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing aead", func(t *testing.T) {
		t.Parallel()

		s := &shadowsocks.TCPStreamCipher{
			Method: method,
			AEAD:   nil,
		}

		err := s.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing AEAD") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestTCPStreamCipher_SealTo_OpenTo(t *testing.T) {
	t.Parallel()

	enc, dec, _ := newTestCipherPair(t)
	plaintext := []byte("hello shadowsocks")

	ciphertext, err := enc.SealTo(nil, plaintext)
	if err != nil {
		t.Fatalf("SealTo() error = %v", err)
	}

	got, err := dec.OpenTo(nil, ciphertext)
	if err != nil {
		t.Fatalf("OpenTo() error = %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("OpenTo() = %q, want %q", got, plaintext)
	}
}

func TestTCPStreamCipher_SealTo_OpenTo_NilCipher(t *testing.T) {
	t.Parallel()

	var s *shadowsocks.TCPStreamCipher

	if _, err := s.SealTo(nil, []byte("x")); err == nil {
		t.Fatal("expected error from nil SealTo receiver")
	}
	if _, err := s.OpenTo(nil, []byte("x")); err == nil {
		t.Fatal("expected error from nil OpenTo receiver")
	}
}

func TestTCPStreamCipher_OpenTo_WrongCipherFails(t *testing.T) {
	t.Parallel()

	enc, _, method := newTestCipherPair(t)

	psk := make([]byte, method.KeySize)
	salt := make([]byte, method.SaltSize)
	for i := range psk {
		psk[i] = byte(i + 9)
	}
	for i := range salt {
		salt[i] = byte(i + 19)
	}

	wrongDec, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, salt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK() error = %v", err)
	}

	ciphertext, err := enc.SealTo(nil, []byte("hello"))
	if err != nil {
		t.Fatalf("SealTo() error = %v", err)
	}

	if _, err := wrongDec.OpenTo(nil, ciphertext); err == nil {
		t.Fatal("expected decrypt error, got nil")
	}
}

func TestTCPStreamCipher_EncryptedLengths(t *testing.T) {
	t.Parallel()

	s, _, method := newTestCipherPair(t)

	if got, want := s.EncryptedChunkLength(), shadowsocks.TCPChunkLengthLen+method.TagSize; got != want {
		t.Fatalf("EncryptedChunkLength() = %d, want %d", got, want)
	}

	if got, want := s.EncryptedPayloadLength(123), 123+method.TagSize; got != want {
		t.Fatalf("EncryptedPayloadLength() = %d, want %d", got, want)
	}
}

func TestTCPStreamCipher_ChunkLength_RoundTrip(t *testing.T) {
	t.Parallel()

	enc, dec, method := newTestCipherPair(t)

	ciphertext, err := enc.EncodeChunkLengthTo(nil, 1234)
	if err != nil {
		t.Fatalf("EncodeChunkLengthTo() error = %v", err)
	}

	if got, want := len(ciphertext), shadowsocks.TCPChunkLengthLen+method.TagSize; got != want {
		t.Fatalf("len(ciphertext) = %d, want %d", got, want)
	}

	n, err := dec.DecodeChunkLength(ciphertext, nil)
	if err != nil {
		t.Fatalf("DecodeChunkLength() error = %v", err)
	}
	if n != 1234 {
		t.Fatalf("DecodeChunkLength() = %d, want %d", n, 1234)
	}
}

func TestTCPStreamCipher_ChunkPayload_RoundTrip(t *testing.T) {
	t.Parallel()

	enc, dec, method := newTestCipherPair(t)
	payload := []byte("payload-data")

	ciphertext, err := enc.EncodeChunkPayloadTo(nil, payload)
	if err != nil {
		t.Fatalf("EncodeChunkPayloadTo() error = %v", err)
	}

	if got, want := len(ciphertext), len(payload)+method.TagSize; got != want {
		t.Fatalf("len(ciphertext) = %d, want %d", got, want)
	}

	plain, err := dec.DecodeChunkPayloadTo(nil, ciphertext)
	if err != nil {
		t.Fatalf("DecodeChunkPayloadTo() error = %v", err)
	}
	if !bytes.Equal(plain, payload) {
		t.Fatalf("DecodeChunkPayloadTo() = %q, want %q", plain, payload)
	}
}

func TestTCPStreamCipher_EncodeChunkPayloadTo_TooLarge(t *testing.T) {
	t.Parallel()

	enc, _, _ := newTestCipherPair(t)
	payload := make([]byte, 0x10000)

	_, err := enc.EncodeChunkPayloadTo(nil, payload)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "payload too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTCPStreamCipher_RequestFixedHeader_RoundTrip(t *testing.T) {
	t.Parallel()

	enc, dec, _ := newTestCipherPair(t)

	var want shadowsocks.TCPRequestFixedHeader
	want.Init(shadowsocks.TCPHeaderTypeClientStream, 123456789, 321)

	ciphertext, err := enc.EncodeRequestFixedHeaderTo(nil, &want, nil)
	if err != nil {
		t.Fatalf("EncodeRequestFixedHeaderTo() error = %v", err)
	}

	got, err := dec.DecodeRequestFixedHeader(ciphertext, nil)
	if err != nil {
		t.Fatalf("DecodeRequestFixedHeader() error = %v", err)
	}

	if got.Type != want.Type || got.Timestamp != want.Timestamp || got.Length != want.Length {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestTCPStreamCipher_RequestFixedHeader_Nil(t *testing.T) {
	t.Parallel()

	enc, _, _ := newTestCipherPair(t)

	_, err := enc.EncodeRequestFixedHeaderTo(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "nil TCP request fixed header") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTCPStreamCipher_RequestVariableHeader_RoundTrip(t *testing.T) {
	t.Parallel()

	enc, dec, _ := newTestCipherPair(t)

	var want shadowsocks.TCPRequestVariableHeader
	want.Init(
		shadowsocks.Addr{
			AddrType: shadowsocks.AddrTypeDomain,
			Domain:   "example.com",
			Port:     443,
		},
		[]byte{1, 2, 3},
		[]byte("hello"),
	)

	ciphertext, err := enc.EncodeRequestVariableHeaderTo(nil, &want, nil)
	if err != nil {
		t.Fatalf("EncodeRequestVariableHeaderTo() error = %v", err)
	}

	got, err := dec.DecodeRequestVariableHeader(ciphertext, nil)
	if err != nil {
		t.Fatalf("DecodeRequestVariableHeader() error = %v", err)
	}

	if got.Target.AddrType != want.Target.AddrType {
		t.Fatalf("Target.AddrType = %v, want %v", got.Target.AddrType, want.Target.AddrType)
	}
	if got.Target.Domain != want.Target.Domain {
		t.Fatalf("Target.Domain = %q, want %q", got.Target.Domain, want.Target.Domain)
	}
	if got.Target.Port != want.Target.Port {
		t.Fatalf("Target.Port = %d, want %d", got.Target.Port, want.Target.Port)
	}
	if got.PaddingLen != want.PaddingLen {
		t.Fatalf("PaddingLen = %d, want %d", got.PaddingLen, want.PaddingLen)
	}
	if !bytes.Equal(got.Padding, want.Padding) {
		t.Fatalf("Padding = %v, want %v", got.Padding, want.Padding)
	}
	if !bytes.Equal(got.InitialData, want.InitialData) {
		t.Fatalf("InitialData = %v, want %v", got.InitialData, want.InitialData)
	}
}

func TestTCPStreamCipher_RequestVariableHeader_Nil(t *testing.T) {
	t.Parallel()

	enc, _, _ := newTestCipherPair(t)

	_, err := enc.EncodeRequestVariableHeaderTo(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "nil TCP request variable header") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTCPStreamCipher_ResponseHeader_RoundTrip(t *testing.T) {
	t.Parallel()

	enc, dec, method := newTestCipherPair(t)

	requestSalt := bytes.Repeat([]byte{0xaa}, method.SaltSize)

	var want shadowsocks.TCPResponseHeader
	want.Init(shadowsocks.TCPHeaderTypeServerStream, 123456789, requestSalt, 4)

	ciphertext, err := enc.EncodeResponseHeaderTo(nil, &want, nil)
	if err != nil {
		t.Fatalf("EncodeResponseHeaderTo() error = %v", err)
	}

	got, err := dec.DecodeResponseHeader(ciphertext, nil)
	if err != nil {
		t.Fatalf("DecodeResponseHeader() error = %v", err)
	}

	if got.Type != want.Type || got.Timestamp != want.Timestamp || got.Length != want.Length {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if !bytes.Equal(got.RequestSalt, want.RequestSalt) {
		t.Fatalf("RequestSalt = %v, want %v", got.RequestSalt, want.RequestSalt)
	}
}

func TestTCPStreamCipher_ResponseHeader_Nil(t *testing.T) {
	t.Parallel()

	enc, _, _ := newTestCipherPair(t)

	_, err := enc.EncodeResponseHeaderTo(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "nil TCP response header") {
		t.Fatalf("unexpected error: %v", err)
	}
}
