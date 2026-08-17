package shadowsocks_test

import (
	"net"
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func testPaddingAddr(port uint16) shadowsocks.Addr {
	var a shadowsocks.Addr
	a.Init(shadowsocks.AddrTypeIPv4, net.IPv4(1, 2, 3, 4).To4(), "", port)
	return a
}

func TestPadWhenEmpty(t *testing.T) {
	policy := shadowsocks.PadWhenEmpty(shadowsocks.MaxPaddingLength)
	target := testPaddingAddr(443)

	// A header with no payload must be padded, or it would be rejected.
	for range 64 {
		n, err := policy(target, 0)
		if err != nil {
			t.Fatalf("policy() error = %v", err)
		}
		if n < 1 || n > shadowsocks.MaxPaddingLength {
			t.Fatalf("padding = %d, want between 1 and %d", n, shadowsocks.MaxPaddingLength)
		}
	}

	n, err := policy(target, 100)
	if err != nil {
		t.Fatalf("policy() error = %v", err)
	}
	if n != 0 {
		t.Fatalf("padding with payload = %d, want 0", n)
	}
}

func TestPadPlainDNS(t *testing.T) {
	policy := shadowsocks.PadPlainDNS(shadowsocks.MaxPaddingLength)

	n, err := policy(testPaddingAddr(53), 40)
	if err != nil {
		t.Fatalf("policy() error = %v", err)
	}
	if n < 1 {
		t.Fatalf("padding for port 53 = %d, want at least 1", n)
	}

	n, err = policy(testPaddingAddr(443), 40)
	if err != nil {
		t.Fatalf("policy() error = %v", err)
	}
	if n != 0 {
		t.Fatalf("padding for port 443 = %d, want 0", n)
	}
}

func TestPadAlwaysAndNever(t *testing.T) {
	target := testPaddingAddr(443)

	n, err := shadowsocks.PadAlways(64)(target, 100)
	if err != nil {
		t.Fatalf("PadAlways() error = %v", err)
	}
	if n < 1 || n > 64 {
		t.Fatalf("padding = %d, want between 1 and 64", n)
	}

	n, err = shadowsocks.PadNever(target, 0)
	if err != nil {
		t.Fatalf("PadNever() error = %v", err)
	}
	if n != 0 {
		t.Fatalf("padding = %d, want 0", n)
	}
}

func TestPaddingPolicy_RejectsOversizedMax(t *testing.T) {
	target := testPaddingAddr(53)

	if _, err := shadowsocks.PadAlways(shadowsocks.MaxPaddingLength+1)(target, 0); err == nil {
		t.Fatal("policy with max above MaxPaddingLength = nil error, want error")
	}
}

func TestPaddingPolicy_ZeroMax(t *testing.T) {
	target := testPaddingAddr(53)

	n, err := shadowsocks.PadAlways(0)(target, 0)
	if err != nil {
		t.Fatalf("PadAlways(0) error = %v", err)
	}
	if n != 0 {
		t.Fatalf("padding = %d, want 0", n)
	}
}
