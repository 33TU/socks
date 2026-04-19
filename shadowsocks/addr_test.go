package shadowsocks_test

import (
	"errors"
	"net"
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func TestAddr_Init_Validate(t *testing.T) {
	tests := []struct {
		name    string
		addr    shadowsocks.Addr
		wantErr error
	}{
		{
			name: "valid ipv4",
			addr: func() shadowsocks.Addr {
				var a shadowsocks.Addr
				a.Init(shadowsocks.AddrTypeIPv4, net.IPv4(127, 0, 0, 1), "", 1080)
				return a
			}(),
		},
		{
			name: "valid domain",
			addr: func() shadowsocks.Addr {
				var a shadowsocks.Addr
				a.Init(shadowsocks.AddrTypeDomain, nil, "example.com", 443)
				return a
			}(),
		},
		{
			name: "valid ipv6",
			addr: func() shadowsocks.Addr {
				var a shadowsocks.Addr
				a.Init(shadowsocks.AddrTypeIPv6, net.ParseIP("::1"), "", 5353)
				return a
			}(),
		},
		{
			name: "invalid addr type",
			addr: func() shadowsocks.Addr {
				var a shadowsocks.Addr
				a.Init(0x99, net.IPv4(127, 0, 0, 1), "", 1080)
				return a
			}(),
			wantErr: shadowsocks.ErrInvalidAddrType,
		},
		{
			name: "invalid ipv4 ip",
			addr: func() shadowsocks.Addr {
				var a shadowsocks.Addr
				a.Init(shadowsocks.AddrTypeIPv4, nil, "", 1080)
				return a
			}(),
			wantErr: shadowsocks.ErrInvalidAddr,
		},
		{
			name: "invalid ipv6 ip",
			addr: func() shadowsocks.Addr {
				var a shadowsocks.Addr
				a.Init(shadowsocks.AddrTypeIPv6, net.IPv4(127, 0, 0, 1), "", 1080)
				return a
			}(),
			wantErr: shadowsocks.ErrInvalidAddr,
		},
		{
			name: "missing domain",
			addr: func() shadowsocks.Addr {
				var a shadowsocks.Addr
				a.Init(shadowsocks.AddrTypeDomain, nil, "", 1080)
				return a
			}(),
			wantErr: shadowsocks.ErrInvalidDomain,
		},
		{
			name: "domain too long",
			addr: func() shadowsocks.Addr {
				var a shadowsocks.Addr
				a.Init(shadowsocks.AddrTypeDomain, nil, string(make([]byte, 256)), 1080)
				return a
			}(),
			wantErr: shadowsocks.ErrInvalidDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.addr.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestAddr_GetHost(t *testing.T) {
	tests := []struct {
		name string
		addr shadowsocks.Addr
		want string
	}{
		{
			name: "domain",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeDomain,
				Domain:   "example.com",
				Port:     443,
			},
			want: "example.com",
		},
		{
			name: "ipv4",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeIPv4,
				IP:       net.IPv4(127, 0, 0, 1),
				Port:     1080,
			},
			want: "127.0.0.1",
		},
		{
			name: "nil ip",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeIPv4,
				IP:       nil,
				Port:     1080,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.addr.GetHost()
			if got != tt.want {
				t.Fatalf("GetHost() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAddr_Addr(t *testing.T) {
	tests := []struct {
		name string
		addr shadowsocks.Addr
		want string
	}{
		{
			name: "domain",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeDomain,
				Domain:   "example.com",
				Port:     443,
			},
			want: "example.com:443",
		},
		{
			name: "ipv4",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeIPv4,
				IP:       net.IPv4(127, 0, 0, 1),
				Port:     1080,
			},
			want: "127.0.0.1:1080",
		},
		{
			name: "ipv6",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeIPv6,
				IP:       net.ParseIP("::1"),
				Port:     53,
			},
			want: "[::1]:53",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.addr.Addr()
			if got != tt.want {
				t.Fatalf("Addr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAddr_EncodedLen(t *testing.T) {
	tests := []struct {
		name string
		addr shadowsocks.Addr
		want int
	}{
		{
			name: "ipv4",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeIPv4,
				IP:       net.IPv4(127, 0, 0, 1),
				Port:     1080,
			},
			want: 7,
		},
		{
			name: "domain",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeDomain,
				Domain:   "example.com",
				Port:     443,
			},
			want: 1 + 1 + len("example.com") + 2,
		},
		{
			name: "ipv6",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeIPv6,
				IP:       net.ParseIP("::1"),
				Port:     53,
			},
			want: 19,
		},
		{
			name: "invalid",
			addr: shadowsocks.Addr{
				AddrType: 0x99,
				Port:     1,
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.addr.EncodedLen()
			if got != tt.want {
				t.Errorf("EncodedLen() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAddr_EncodeTo_Decode_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		addr shadowsocks.Addr
	}{
		{
			name: "ipv4",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeIPv4,
				IP:       net.IPv4(127, 0, 0, 1),
				Port:     1080,
			},
		},
		{
			name: "domain",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeDomain,
				Domain:   "example.com",
				Port:     443,
			},
		},
		{
			name: "ipv6",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeIPv6,
				IP:       net.ParseIP("2001:db8::1"),
				Port:     5353,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.addr.EncodedLen())

			bw, err := tt.addr.EncodeTo(buf[:0])
			if err != nil {
				t.Fatalf("EncodeTo() failed: %v", err)
			}
			if len(bw) != len(buf) {
				t.Fatalf("EncodeTo() wrote %d bytes, want %d", len(bw), len(buf))
			}

			var got shadowsocks.Addr
			nr, err := got.Decode(buf)
			if err != nil {
				t.Fatalf("Decode() failed: %v", err)
			}
			if nr != len(buf) {
				t.Fatalf("Decode() read %d bytes, want %d", nr, len(buf))
			}

			if got.AddrType != tt.addr.AddrType {
				t.Fatalf("AddrType = %v, want %v", got.AddrType, tt.addr.AddrType)
			}
			if got.Port != tt.addr.Port {
				t.Fatalf("Port = %d, want %d", got.Port, tt.addr.Port)
			}
			if got.Domain != tt.addr.Domain {
				t.Fatalf("Domain = %q, want %q", got.Domain, tt.addr.Domain)
			}

			switch tt.addr.AddrType {
			case shadowsocks.AddrTypeIPv4:
				if !got.IP.Equal(tt.addr.IP.To4()) {
					t.Fatalf("IP = %v, want %v", got.IP, tt.addr.IP.To4())
				}
			case shadowsocks.AddrTypeIPv6:
				if !got.IP.Equal(tt.addr.IP.To16()) {
					t.Fatalf("IP = %v, want %v", got.IP, tt.addr.IP.To16())
				}
			}
		})
	}
}

func TestAddr_EncodeTo_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		addr    shadowsocks.Addr
		bufLen  int
		wantErr error
	}{
		{
			name: "invalid addr type",
			addr: shadowsocks.Addr{
				AddrType: 0x99,
				IP:       net.IPv4(127, 0, 0, 1),
				Port:     1080,
			},
			bufLen:  32,
			wantErr: shadowsocks.ErrInvalidAddrType,
		},
		{
			name: "invalid domain",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeDomain,
				Domain:   "",
				Port:     80,
			},
			bufLen:  32,
			wantErr: shadowsocks.ErrInvalidDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.bufLen)
			_, err := tt.addr.EncodeTo(buf[:0])
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("EncodeTo() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestAddr_Decode_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		src     []byte
		wantErr error
	}{
		{
			name:    "empty",
			src:     nil,
			wantErr: shadowsocks.ErrShortAddr,
		},
		{
			name:    "invalid addr type",
			src:     []byte{0x99},
			wantErr: shadowsocks.ErrInvalidAddrType,
		},
		{
			name:    "short ipv4",
			src:     []byte{shadowsocks.AddrTypeIPv4, 127, 0, 0},
			wantErr: shadowsocks.ErrShortAddr,
		},
		{
			name:    "short domain length byte missing payload",
			src:     []byte{shadowsocks.AddrTypeDomain, 5, 'a', 'b'},
			wantErr: shadowsocks.ErrShortAddr,
		},
		{
			name:    "short ipv6",
			src:     []byte{shadowsocks.AddrTypeIPv6, 0, 1, 2},
			wantErr: shadowsocks.ErrShortAddr,
		},
		{
			name: "empty domain",
			src: []byte{
				shadowsocks.AddrTypeDomain,
				0,
				0, 80,
			},
			wantErr: shadowsocks.ErrInvalidDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a shadowsocks.Addr
			_, err := a.Decode(tt.src)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Decode() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestAddr_String(t *testing.T) {
	tests := []struct {
		name string
		addr shadowsocks.Addr
		want string
	}{
		{
			name: "ipv4",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeIPv4,
				IP:       net.IPv4(127, 0, 0, 1),
				Port:     1080,
			},
			want: "Addr{AddrType=IPv4, Host=127.0.0.1, Port=1080}",
		},
		{
			name: "domain",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeDomain,
				Domain:   "example.com",
				Port:     443,
			},
			want: "Addr{AddrType=DOMAIN, Host=example.com, Port=443}",
		},
		{
			name: "ipv6",
			addr: shadowsocks.Addr{
				AddrType: shadowsocks.AddrTypeIPv6,
				IP:       net.ParseIP("::1"),
				Port:     53,
			},
			want: "Addr{AddrType=IPv6, Host=::1, Port=53}",
		},
		{
			name: "unknown",
			addr: shadowsocks.Addr{
				AddrType: 0x99,
				Domain:   "x",
				Port:     1,
			},
			want: "Addr{AddrType=0x99, Host=, Port=1}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.addr.String()
			if got != tt.want {
				t.Fatalf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
