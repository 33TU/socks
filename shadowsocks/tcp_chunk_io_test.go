package shadowsocks_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func newTCPChunkTestMethod(t *testing.T) shadowsocks.Method {
	t.Helper()

	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	return method
}

func newTCPChunkTestPSKAndSalt(method shadowsocks.Method) ([]byte, []byte) {
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

func newTCPChunkCipherPair(t *testing.T) (*shadowsocks.TCPStreamCipher, *shadowsocks.TCPStreamCipher) {
	t.Helper()

	method := newTCPChunkTestMethod(t)
	psk, salt := newTCPChunkTestPSKAndSalt(method)

	enc, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, salt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK(enc) error = %v", err)
	}

	dec, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, salt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK(dec) error = %v", err)
	}

	return enc, dec
}

func TestTCPChunkReader_Init_Validate(t *testing.T) {
	t.Parallel()

	_, dec := newTCPChunkCipherPair(t)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		var r shadowsocks.TCPChunkReader
		if err := r.Init(dec, bytes.NewReader(nil)); err != nil {
			t.Fatalf("Init() error = %v", err)
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("nil cipher", func(t *testing.T) {
		t.Parallel()

		var r shadowsocks.TCPChunkReader
		err := r.Init(nil, bytes.NewReader(nil))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nil TCP stream cipher") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("nil source", func(t *testing.T) {
		t.Parallel()

		var r shadowsocks.TCPChunkReader
		err := r.Init(dec, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nil TCP chunk source") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("nil reader validate", func(t *testing.T) {
		t.Parallel()

		var r *shadowsocks.TCPChunkReader
		err := r.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nil TCP chunk reader") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing cipher", func(t *testing.T) {
		t.Parallel()

		r := &shadowsocks.TCPChunkReader{Src: bytes.NewReader(nil)}
		err := r.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing TCP stream cipher") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing source", func(t *testing.T) {
		t.Parallel()

		r := &shadowsocks.TCPChunkReader{Cipher: dec}
		err := r.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing TCP chunk source") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestTCPChunkWriter_Init_Validate(t *testing.T) {
	t.Parallel()

	enc, _ := newTCPChunkCipherPair(t)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		var w shadowsocks.TCPChunkWriter
		if err := w.Init(enc, io.Discard); err != nil {
			t.Fatalf("Init() error = %v", err)
		}
		if err := w.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("nil cipher", func(t *testing.T) {
		t.Parallel()

		var w shadowsocks.TCPChunkWriter
		err := w.Init(nil, io.Discard)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nil TCP stream cipher") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("nil destination", func(t *testing.T) {
		t.Parallel()

		var w shadowsocks.TCPChunkWriter
		err := w.Init(enc, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nil TCP chunk destination") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("nil writer validate", func(t *testing.T) {
		t.Parallel()

		var w *shadowsocks.TCPChunkWriter
		err := w.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nil TCP chunk writer") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing cipher", func(t *testing.T) {
		t.Parallel()

		w := &shadowsocks.TCPChunkWriter{Dst: io.Discard}
		err := w.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing TCP stream cipher") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing destination", func(t *testing.T) {
		t.Parallel()

		w := &shadowsocks.TCPChunkWriter{Cipher: enc}
		err := w.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing TCP chunk destination") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestTCPChunkWriterReader_RoundTrip(t *testing.T) {
	t.Parallel()

	enc, dec := newTCPChunkCipherPair(t)

	var buf bytes.Buffer

	var w shadowsocks.TCPChunkWriter
	if err := w.Init(enc, &buf); err != nil {
		t.Fatalf("writer Init() error = %v", err)
	}

	var r shadowsocks.TCPChunkReader
	if err := r.Init(dec, &buf); err != nil {
		t.Fatalf("reader Init() error = %v", err)
	}

	payload := []byte("hello chunk")

	nw, err := w.WriteChunk(payload)
	if err != nil {
		t.Fatalf("WriteChunk() error = %v", err)
	}
	if nw != int64(buf.Len()) {
		t.Fatalf("WriteChunk() wrote %d bytes, buffer has %d", nw, buf.Len())
	}

	got, nr, err := r.ReadChunkTo(nil)
	if err != nil {
		t.Fatalf("ReadChunkTo() error = %v", err)
	}
	if nr != nw {
		t.Fatalf("ReadChunkTo() read %d bytes, want %d", nr, nw)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadChunkTo() = %q, want %q", got, payload)
	}
}

func TestTCPChunkReader_ReadChunkTo_AppendsToDst(t *testing.T) {
	t.Parallel()

	enc, dec := newTCPChunkCipherPair(t)

	var buf bytes.Buffer

	var w shadowsocks.TCPChunkWriter
	if err := w.Init(enc, &buf); err != nil {
		t.Fatalf("writer Init() error = %v", err)
	}

	var r shadowsocks.TCPChunkReader
	if err := r.Init(dec, &buf); err != nil {
		t.Fatalf("reader Init() error = %v", err)
	}

	payload := []byte("payload")
	prefix := []byte("prefix:")

	if _, err := w.WriteChunk(payload); err != nil {
		t.Fatalf("WriteChunk() error = %v", err)
	}

	got, _, err := r.ReadChunkTo(append([]byte(nil), prefix...))
	if err != nil {
		t.Fatalf("ReadChunkTo() error = %v", err)
	}

	want := append(append([]byte(nil), prefix...), payload...)
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadChunkTo() = %q, want %q", got, want)
	}
}

func TestTCPChunkWriter_WriteChunk_TooLarge(t *testing.T) {
	t.Parallel()

	enc, _ := newTCPChunkCipherPair(t)

	var w shadowsocks.TCPChunkWriter
	if err := w.Init(enc, io.Discard); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	payload := make([]byte, 0x10000)
	_, err := w.WriteChunk(payload)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "payload too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTCPChunkReader_ReadChunk_ShortLengthRead(t *testing.T) {
	t.Parallel()

	_, dec := newTCPChunkCipherPair(t)

	short := bytes.NewReader([]byte{1, 2, 3})

	var r shadowsocks.TCPChunkReader
	if err := r.Init(dec, short); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	_, n, err := r.ReadChunkTo(nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if n != 3 {
		t.Fatalf("ReadChunkTo() read %d bytes, want 3", n)
	}
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTCPChunkReader_ReadChunk_ShortPayloadRead(t *testing.T) {
	t.Parallel()

	enc, dec := newTCPChunkCipherPair(t)

	var buf bytes.Buffer

	var w shadowsocks.TCPChunkWriter
	if err := w.Init(enc, &buf); err != nil {
		t.Fatalf("writer Init() error = %v", err)
	}

	payload := []byte("hello payload")
	nw, err := w.WriteChunk(payload)
	if err != nil {
		t.Fatalf("WriteChunk() error = %v", err)
	}

	wire := buf.Bytes()
	shortWire := wire[:len(wire)-2]

	var r shadowsocks.TCPChunkReader
	if err := r.Init(dec, bytes.NewReader(shortWire)); err != nil {
		t.Fatalf("reader Init() error = %v", err)
	}

	_, nr, err := r.ReadChunkTo(nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if nr != nw-2 {
		t.Fatalf("ReadChunkTo() read %d bytes, want %d", nr, nw-2)
	}
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTCPChunkReader_ReadChunk_WrongCipherFails(t *testing.T) {
	t.Parallel()

	enc, _ := newTCPChunkCipherPair(t)

	method := newTCPChunkTestMethod(t)
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

	var buf bytes.Buffer

	var w shadowsocks.TCPChunkWriter
	if err := w.Init(enc, &buf); err != nil {
		t.Fatalf("writer Init() error = %v", err)
	}

	var r shadowsocks.TCPChunkReader
	if err := r.Init(wrongDec, &buf); err != nil {
		t.Fatalf("reader Init() error = %v", err)
	}

	if _, err := w.WriteChunk([]byte("hello")); err != nil {
		t.Fatalf("WriteChunk() error = %v", err)
	}

	_, _, err = r.ReadChunkTo(nil)
	if err == nil {
		t.Fatal("expected decrypt error, got nil")
	}
}
