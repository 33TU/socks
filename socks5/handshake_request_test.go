package socks5_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/33TU/socks/socks5"
)

func Test_HandshakeRequest_Init_And_Validate(t *testing.T) {
	r := &socks5.HandshakeRequest{}
	r.Init(socks5.SocksVersion, socks5.MethodNoAuth, socks5.MethodUserPass)

	if err := r.Validate(); err != nil {
		t.Fatalf("expected valid request, got %v", err)
	}

	r.Version = 4
	if err := r.Validate(); !errors.Is(err, socks5.ErrInvalidHandshakeVersion) {
		t.Errorf("expected ErrInvalidHandshakeVersion, got %v", err)
	}

	r.Version = socks5.SocksVersion
	r.NMethods = 0
	if err := r.Validate(); !errors.Is(err, socks5.ErrNoMethodsProvided) {
		t.Errorf("expected ErrNoMethodsProvided, got %v", err)
	}
}

func Test_HandshakeRequest_WriteTo_ReadFrom_RoundTrip(t *testing.T) {
	orig := &socks5.HandshakeRequest{}
	orig.Init(socks5.SocksVersion, socks5.MethodNoAuth, socks5.MethodUserPass)

	var buf bytes.Buffer
	n1, err := orig.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	var parsed socks5.HandshakeRequest
	n2, err := parsed.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if n1 != n2 {
		t.Errorf("expected %d bytes read, got %d", n1, n2)
	}
	if parsed.Version != socks5.SocksVersion {
		t.Errorf("expected version %d, got %d", socks5.SocksVersion, parsed.Version)
	}
	if len(parsed.Methods) != len(orig.Methods) {
		t.Fatalf("expected %d methods, got %d", len(orig.Methods), len(parsed.Methods))
	}
	for i, m := range parsed.Methods {
		if m != orig.Methods[i] {
			t.Errorf("method[%d]: expected 0x%02x, got 0x%02x", i, orig.Methods[i], m)
		}
	}
}

func Test_HandshakeRequest_ReadFrom_Truncated(t *testing.T) {
	data := []byte{5, 2, 0x00} // NMETHODS=2 but only 1 method byte present
	r := &socks5.HandshakeRequest{}
	if _, err := r.ReadFrom(bytes.NewReader(data)); err == nil {
		t.Errorf("expected error for truncated handshake")
	}
}

func Test_HandshakeRequest_WriteTo_ErrorPropagation(t *testing.T) {
	r := &socks5.HandshakeRequest{}
	r.Init(socks5.SocksVersion, socks5.MethodNoAuth)

	failWriter := writerFunc(func(p []byte) (int, error) {
		return 0, io.ErrClosedPipe
	})

	if _, err := r.WriteTo(failWriter); err == nil {
		t.Errorf("expected write error")
	}
}

func Test_HandshakeRequest_String(t *testing.T) {
	r := &socks5.HandshakeRequest{}
	r.Init(socks5.SocksVersion, socks5.MethodNoAuth, socks5.MethodUserPass)

	if s := r.String(); s == "" {
		t.Errorf("expected non-empty String() output")
	}
}

// helper type to simulate write errors.

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
