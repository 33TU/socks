package socks5_test

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/33TU/socks/socks5"
)

func Test_Request_Init_And_Validate(t *testing.T) {
	r := &socks5.Request{}
	r.Init(socks5.SocksVersion, socks5.CmdConnect, 0x00, socks5.AddrTypeIPv4, net.IPv4(127, 0, 0, 1), "", 8080)

	if err := r.Validate(); err != nil {
		t.Fatalf("expected valid request, got %v", err)
	}

	r.Version = 4
	if err := r.Validate(); !errors.Is(err, socks5.ErrInvalidVersion) {
		t.Errorf("expected ErrInvalidVersion, got %v", err)
	}
}

func Test_Request_WriteTo_ReadFrom_RoundTrip_IPv4(t *testing.T) {
	orig := &socks5.Request{}
	orig.Init(socks5.SocksVersion, socks5.CmdConnect, 0x00, socks5.AddrTypeIPv4, net.IPv4(192, 168, 0, 10), "", 1080)

	var buf bytes.Buffer
	n1, err := orig.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	var parsed socks5.Request
	n2, err := parsed.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if n1 != n2 {
		t.Errorf("expected %d bytes read, got %d", n1, n2)
	}
	if !parsed.IP.Equal(orig.IP) {
		t.Errorf("expected IP %v, got %v", orig.IP, parsed.IP)
	}
	if parsed.Port != orig.Port {
		t.Errorf("expected port %d, got %d", orig.Port, parsed.Port)
	}
}

func Test_Request_WriteTo_ReadFrom_RoundTrip_Domain(t *testing.T) {
	orig := &socks5.Request{}
	orig.Init(socks5.SocksVersion, socks5.CmdConnect, 0x00, socks5.AddrTypeDomain, nil, "example.com", 443)

	var buf bytes.Buffer
	_, err := orig.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	var parsed socks5.Request
	_, err = parsed.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if parsed.Domain != orig.Domain {
		t.Errorf("expected domain %q, got %q", orig.Domain, parsed.Domain)
	}
	if parsed.Port != orig.Port {
		t.Errorf("expected port %d, got %d", orig.Port, parsed.Port)
	}
}

func Test_Request_WriteTo_ReadFrom_RoundTrip_IPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	orig := &socks5.Request{}
	orig.Init(socks5.SocksVersion, socks5.CmdUDPAssociate, 0x00, socks5.AddrTypeIPv6, ip, "", 9050)

	var buf bytes.Buffer
	_, err := orig.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	var parsed socks5.Request
	_, err = parsed.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if !parsed.IP.Equal(ip) {
		t.Errorf("expected IP %v, got %v", ip, parsed.IP)
	}
	if parsed.Port != 9050 {
		t.Errorf("expected port 9050, got %d", parsed.Port)
	}
}

func Test_Request_Validate_Invalid(t *testing.T) {
	r := &socks5.Request{}
	r.Init(5, 0x99, 0x00, socks5.AddrTypeIPv4, net.IPv4(1, 1, 1, 1), "", 80)
	if err := r.Validate(); !errors.Is(err, socks5.ErrInvalidCommand) {
		t.Errorf("expected ErrInvalidCommand, got %v", err)
	}

	r.Init(5, socks5.CmdConnect, 0x01, socks5.AddrTypeIPv4, net.IPv4(1, 1, 1, 1), "", 80)
	if err := r.Validate(); !errors.Is(err, socks5.ErrInvalidRSV) {
		t.Errorf("expected ErrInvalidRSV, got %v", err)
	}

	r.Init(5, socks5.CmdConnect, 0x00, socks5.AddrTypeDomain, nil, "", 80)
	if err := r.Validate(); !errors.Is(err, socks5.ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain, got %v", err)
	}
}

func Test_Request_ResolveCommands(t *testing.T) {
	r := &socks5.Request{}
	r.Init(5, socks5.CmdResolve, 0x00, socks5.AddrTypeDomain, nil, "example.com", 0)
	if err := r.Validate(); err != nil {
		t.Fatalf("expected valid RESOLVE request, got %v", err)
	}

	r.Init(5, socks5.CmdResolvePTR, 0x00, socks5.AddrTypeIPv4, net.IPv4(8, 8, 8, 8), "", 0)
	if err := r.Validate(); err != nil {
		t.Fatalf("expected valid RESOLVE_PTR request, got %v", err)
	}
}

func Test_Request_String(t *testing.T) {
	r := &socks5.Request{}
	r.Init(socks5.SocksVersion, socks5.CmdConnect, 0x00, socks5.AddrTypeDomain, nil, "user.example.com", 8080)

	if s := r.String(); s == "" {
		t.Errorf("expected non-empty String() output")
	}
}
