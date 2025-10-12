package socks4_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/33TU/socks/socks4"
)

// helper to build an IP array easily
func ip4(a, b, c, d byte) [4]byte { return [4]byte{a, b, c, d} }

func Test_Request_Init_And_Validate(t *testing.T) {
	r := &socks4.Request{}
	r.Init(socks4.SocksVersion, socks4.CmdConnect, 1080, net.IPv4(127, 0, 0, 1), "user", "")

	if err := r.Validate(); err != nil {
		t.Fatalf("expected valid request, got %v", err)
	}

	r.Version = 5
	if err := r.Validate(); !errors.Is(err, socks4.ErrInvalidVersion) {
		t.Errorf("expected ErrInvalidVersion, got %v", err)
	}
}

func Test_Request_WriteTo_ReadFrom_RoundTrip(t *testing.T) {
	orig := socks4.Request{}
	orig.Init(socks4.SocksVersion, socks4.CmdConnect, 8080, net.IPv4(192, 168, 0, 1), "user123", "")

	var buf bytes.Buffer
	n1, err := orig.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	var parsed socks4.Request
	n2, err := parsed.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if n1 != n2 {
		t.Errorf("expected %d bytes read, got %d", n1, n2)
	}
	if parsed.UserID != orig.UserID || parsed.Port != orig.Port || parsed.IP != orig.IP {
		t.Errorf("mismatch:\n got  %+v\n want %+v", parsed, orig)
	}
}

func Test_Request_WriteTo_ReadFrom_SOCKS4a(t *testing.T) {
	orig := socks4.Request{}
	orig.Init(socks4.SocksVersion, socks4.CmdConnect, 443, net.IPv4(0, 0, 0, 1), "alice", "example.org")

	var buf bytes.Buffer
	if _, err := orig.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	var parsed socks4.Request
	if _, err := parsed.ReadFrom(&buf); err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if !parsed.IsSOCKS4a() {
		t.Fatalf("expected SOCKS4a request")
	}
	if parsed.Domain != "example.org" {
		t.Errorf("expected domain %q, got %q", "example.org", parsed.Domain)
	}
	if parsed.UserID != "alice" {
		t.Errorf("expected userid %q, got %q", "alice", parsed.UserID)
	}
}

func Test_Request_GetHost(t *testing.T) {
	r := socks4.Request{IP: ip4(127, 0, 0, 1)}
	if got := r.GetHost(); got != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", got)
	}

	r = socks4.Request{IP: ip4(0, 0, 0, 1), Domain: "example.com"}
	if got := r.GetHost(); got != "example.com" {
		t.Errorf("expected example.com, got %s", got)
	}
}

func Test_Request_ValidateDomain(t *testing.T) {
	r := socks4.Request{IP: ip4(0, 0, 0, 1), Domain: ""}
	if err := r.ValidateDomain(); !errors.Is(err, socks4.ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain for missing domain, got %v", err)
	}

	r = socks4.Request{IP: ip4(0, 0, 0, 1), Domain: "ok.com"}
	if err := r.ValidateDomain(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	r = socks4.Request{IP: ip4(127, 0, 0, 1), Domain: "should-not-have"}
	if err := r.ValidateDomain(); !errors.Is(err, socks4.ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain, got %v", err)
	}
}

func Test_Request_ReadHeaderFrom_Invalid(t *testing.T) {
	bad := bytes.NewBuffer(make([]byte, 4)) // too short
	var r socks4.Request
	if _, err := r.ReadHeaderFrom(bad); err == nil {
		t.Errorf("expected error for short header")
	}
}

func Test_Request_WriteTo_ErrorPropagation(t *testing.T) {
	r := socks4.Request{}
	r.Init(4, socks4.CmdConnect, 80, net.IPv4(1, 2, 3, 4), "test", "")

	failWriter := writerFunc(func(p []byte) (int, error) {
		return 0, io.ErrClosedPipe
	})

	if _, err := r.WriteTo(failWriter); err == nil {
		t.Errorf("expected write error")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func Test_Request_ReadUserIDAndDomain_Truncated(t *testing.T) {
	data := []byte{4, 1, 0x1F, 0x90, 127, 0, 0, 1, 'u'} // no null terminator
	r := socks4.Request{}
	_, err := r.ReadFrom(bytes.NewReader(data))
	if err == nil {
		t.Errorf("expected EOF for truncated userid")
	}
}

func Test_Request_ValidateHeader_InvalidIP(t *testing.T) {
	var r socks4.Request
	r.Init(socks4.SocksVersion, socks4.CmdConnect, 0, net.ParseIP("0.0.0.0"), "", "")
	if err := r.ValidateHeader(); err == nil {
		t.Errorf("expected ErrInvalidIP for IPv6")
	}
}
