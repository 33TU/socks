package shadowsocks_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func TestUDPClientHeader_RoundTrip(t *testing.T) {
	var target shadowsocks.Addr
	target.Init(shadowsocks.AddrTypeDomain, nil, "example.com", 53)

	padding := bytes.Repeat([]byte{0xab}, 17)

	var h shadowsocks.UDPClientHeader
	h.Init(shadowsocks.UDPHeaderTypeClientPacket, 1700000000, padding, target)

	encoded, err := h.EncodeTo(nil)
	if err != nil {
		t.Fatalf("EncodeTo() error = %v", err)
	}
	if len(encoded) != h.EncodedLen() {
		t.Errorf("encoded length = %d, want %d", len(encoded), h.EncodedLen())
	}

	payload := []byte("dns query")
	packet := append(append([]byte(nil), encoded...), payload...)

	var got shadowsocks.UDPClientHeader
	n, err := got.Decode(packet)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if n != len(encoded) {
		t.Errorf("consumed = %d, want %d", n, len(encoded))
	}
	if got.Type != h.Type || got.Timestamp != h.Timestamp {
		t.Errorf("header = %+v, want type %d timestamp %d", got, h.Type, h.Timestamp)
	}
	if !bytes.Equal(got.Padding, padding) {
		t.Errorf("padding = %x, want %x", got.Padding, padding)
	}
	if got.Target.Domain != "example.com" || got.Target.Port != 53 {
		t.Errorf("target = %s, want example.com:53", got.Target.Addr())
	}
	if !bytes.Equal(packet[n:], payload) {
		t.Errorf("payload = %q, want %q", packet[n:], payload)
	}
}

func TestUDPClientHeader_RejectsBadType(t *testing.T) {
	var target shadowsocks.Addr
	target.Init(shadowsocks.AddrTypeIPv4, net.IPv4(1, 2, 3, 4).To4(), "", 80)

	var h shadowsocks.UDPClientHeader
	h.Init(shadowsocks.UDPHeaderTypeServerPacket, 1700000000, nil, target)

	if _, err := h.EncodeTo(nil); err == nil {
		t.Error("EncodeTo() with server type succeeded, want failure")
	}

	h.Type = shadowsocks.UDPHeaderTypeClientPacket
	encoded, err := h.EncodeTo(nil)
	if err != nil {
		t.Fatalf("EncodeTo() error = %v", err)
	}

	encoded[0] = shadowsocks.UDPHeaderTypeServerPacket
	var got shadowsocks.UDPClientHeader
	if _, err := got.Decode(encoded); err == nil {
		t.Error("Decode() of server-typed header succeeded, want failure")
	}
}

func TestUDPClientHeader_RejectsPaddingBeyondPacket(t *testing.T) {
	var target shadowsocks.Addr
	target.Init(shadowsocks.AddrTypeIPv4, net.IPv4(1, 2, 3, 4).To4(), "", 80)

	var h shadowsocks.UDPClientHeader
	h.Init(shadowsocks.UDPHeaderTypeClientPacket, 1700000000, []byte{1, 2, 3, 4}, target)

	encoded, err := h.EncodeTo(nil)
	if err != nil {
		t.Fatalf("EncodeTo() error = %v", err)
	}

	// Advertise more padding than the packet holds.
	encoded[9], encoded[10] = 0xff, 0xff
	var got shadowsocks.UDPClientHeader
	if _, err := got.Decode(encoded); err == nil {
		t.Error("Decode() with overlong padding succeeded, want failure")
	}
}

func TestUDPServerHeader_RoundTrip(t *testing.T) {
	var source shadowsocks.Addr
	source.Init(shadowsocks.AddrTypeIPv6, net.ParseIP("2001:db8::1").To16(), "", 443)

	padding := bytes.Repeat([]byte{0x5c}, 5)

	var h shadowsocks.UDPServerHeader
	h.Init(shadowsocks.UDPHeaderTypeServerPacket, 1700000000, 0xfeedfacecafebeef, padding, source)

	encoded, err := h.EncodeTo(nil)
	if err != nil {
		t.Fatalf("EncodeTo() error = %v", err)
	}
	if len(encoded) != h.EncodedLen() {
		t.Errorf("encoded length = %d, want %d", len(encoded), h.EncodedLen())
	}

	payload := []byte("response")
	packet := append(append([]byte(nil), encoded...), payload...)

	var got shadowsocks.UDPServerHeader
	n, err := got.Decode(packet)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.ClientSessionID != h.ClientSessionID {
		t.Errorf("client session ID = %#x, want %#x", got.ClientSessionID, h.ClientSessionID)
	}
	if !got.Source.IP.Equal(source.IP) || got.Source.Port != 443 {
		t.Errorf("source = %s, want %s", got.Source.Addr(), source.Addr())
	}
	if !bytes.Equal(packet[n:], payload) {
		t.Errorf("payload = %q, want %q", packet[n:], payload)
	}
}

func TestUDPHeaders_RejectShortBuffers(t *testing.T) {
	var client shadowsocks.UDPClientHeader
	for size := range shadowsocks.UDPClientHeaderFixedLen {
		if _, err := client.Decode(make([]byte, size)); err == nil {
			t.Errorf("UDPClientHeader.Decode(%d bytes) succeeded, want failure", size)
		}
	}

	var server shadowsocks.UDPServerHeader
	for size := range shadowsocks.UDPServerHeaderFixedLen {
		if _, err := server.Decode(make([]byte, size)); err == nil {
			t.Errorf("UDPServerHeader.Decode(%d bytes) succeeded, want failure", size)
		}
	}
}
