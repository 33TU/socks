package socks5_test

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/33TU/socks/socks5"
)

func Test_UDPPacket_Init_Validate(t *testing.T) {
	tests := []struct {
		name    string
		packet  socks5.UDPPacket
		wantErr bool
	}{
		{
			name: "valid IPv4 packet",
			packet: func() socks5.UDPPacket {
				var p socks5.UDPPacket
				p.Init([2]byte{0, 0}, 0x00, socks5.AddrTypeIPv4, net.IPv4(127, 0, 0, 1), "", 9000, []byte("data"))
				return p
			}(),
			wantErr: false,
		},
		{
			name: "invalid reserved bytes",
			packet: func() socks5.UDPPacket {
				var p socks5.UDPPacket
				p.Init([2]byte{1, 0}, 0x00, socks5.AddrTypeIPv4, net.IPv4(127, 0, 0, 1), "", 9000, []byte("data"))
				return p
			}(),
			wantErr: true,
		},
		{
			name: "invalid frag byte",
			packet: func() socks5.UDPPacket {
				var p socks5.UDPPacket
				p.Init([2]byte{0, 0}, 0x01, socks5.AddrTypeIPv4, net.IPv4(127, 0, 0, 1), "", 9000, []byte("data"))
				return p
			}(),
			wantErr: true,
		},
		{
			name: "invalid address type",
			packet: func() socks5.UDPPacket {
				var p socks5.UDPPacket
				p.Init([2]byte{0, 0}, 0x00, 0x99, net.IPv4(127, 0, 0, 1), "", 9000, []byte("data"))
				return p
			}(),
			wantErr: true,
		},
		{
			name: "missing data",
			packet: func() socks5.UDPPacket {
				var p socks5.UDPPacket
				p.Init([2]byte{0, 0}, 0x00, socks5.AddrTypeIPv4, net.IPv4(127, 0, 0, 1), "", 9000, nil)
				return p
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.packet.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func Test_UDPPacket_WriteTo_ReadFrom_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		init func() socks5.UDPPacket
	}{
		{
			name: "IPv4",
			init: func() socks5.UDPPacket {
				var p socks5.UDPPacket
				p.Init([2]byte{0, 0}, 0, socks5.AddrTypeIPv4, net.IPv4(192, 168, 1, 100), "", 8080, []byte("hello"))
				return p
			},
		},
		{
			name: "IPv6",
			init: func() socks5.UDPPacket {
				var p socks5.UDPPacket
				ip := net.ParseIP("2001:db8::1")
				p.Init([2]byte{0, 0}, 0, socks5.AddrTypeIPv6, ip, "", 9000, []byte("payload"))
				return p
			},
		},
		{
			name: "Domain",
			init: func() socks5.UDPPacket {
				var p socks5.UDPPacket
				p.Init([2]byte{0, 0}, 0, socks5.AddrTypeDomain, nil, "example.org", 53, []byte{0xaa, 0xbb})
				return p
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := tt.init()
			var buf bytes.Buffer

			nw, err := orig.WriteTo(&buf)
			if err != nil {
				t.Fatalf("WriteTo() failed: %v", err)
			}

			var got socks5.UDPPacket
			nr, err := got.ReadFrom(&buf)
			if err != nil {
				t.Fatalf("ReadFrom() failed: %v", err)
			}

			if nw != nr {
				t.Errorf("expected %d bytes written == %d bytes read", nw, nr)
			}
			if got.Port != orig.Port {
				t.Errorf("port mismatch: got %d, want %d", got.Port, orig.Port)
			}
			if got.AddrType == socks5.AddrTypeDomain {
				if got.Domain != orig.Domain {
					t.Errorf("domain mismatch: got %q, want %q", got.Domain, orig.Domain)
				}
			} else if !got.IP.Equal(orig.IP) {
				t.Errorf("IP mismatch: got %v, want %v", got.IP, orig.IP)
			}
			if !bytes.Equal(got.Data, orig.Data) {
				t.Errorf("data mismatch: got %x, want %x", got.Data, orig.Data)
			}
		})
	}
}

func Test_UDPPacket_ReadFrom_InvalidRSV(t *testing.T) {
	b := []byte{
		0x01, 0x00, // RSV (invalid)
		0x00, // FRAG
		socks5.AddrTypeIPv4,
		127, 0, 0, 1,
		0x1F, 0x90, // port 8080
		'h', 'i',
	}

	var p socks5.UDPPacket
	if _, err := p.ReadFrom(bytes.NewReader(b)); !errors.Is(err, socks5.ErrInvalidUDPReserved) {
		t.Errorf("expected ErrInvalidUDPReserved, got %v", err)
	}
}

func Test_UDPPacket_ReadFrom_InvalidFrag(t *testing.T) {
	b := []byte{
		0x00, 0x00, // RSV
		0x01, // FRAG (invalid)
		socks5.AddrTypeIPv4,
		127, 0, 0, 1,
		0x1F, 0x90,
		'd', 'a', 't', 'a',
	}

	var p socks5.UDPPacket
	if _, err := p.ReadFrom(bytes.NewReader(b)); !errors.Is(err, socks5.ErrUnsupportedFrag) {
		t.Errorf("expected ErrUnsupportedFrag, got %v", err)
	}
}

func Test_UDPPacket_ReadFrom_InvalidAddrType(t *testing.T) {
	b := []byte{
		0x00, 0x00,
		0x00,
		0x99, // invalid ATYP
		0x1F, 0x90,
	}

	var p socks5.UDPPacket
	if _, err := p.ReadFrom(bytes.NewReader(b)); !errors.Is(err, socks5.ErrInvalidUDPAddrType) {
		t.Errorf("expected ErrInvalidUDPAddrType, got %v", err)
	}
}

func Test_UDPPacket_String(t *testing.T) {
	var p socks5.UDPPacket
	p.Init([2]byte{0, 0}, 0, socks5.AddrTypeIPv4, net.IPv4(8, 8, 8, 8), "", 53, []byte{0xaa, 0xbb})

	if s := p.String(); s == "" {
		t.Errorf("expected non-empty String() output")
	}
}
