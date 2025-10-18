package socks5_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/33TU/socks/socks5"
)

func Test_Reply_Init_Validate(t *testing.T) {
	tests := []struct {
		name    string
		reply   socks5.Reply
		wantErr bool
	}{
		{
			name: "valid success IPv4",
			reply: func() socks5.Reply {
				var r socks5.Reply
				r.Init(socks5.SocksVersion, socks5.RepSuccess, 0x00, socks5.AddrTypeIPv4, net.IPv4(127, 0, 0, 1), "", 1080)
				return r
			}(),
			wantErr: false,
		},
		{
			name: "invalid version",
			reply: func() socks5.Reply {
				var r socks5.Reply
				r.Init(4, socks5.RepSuccess, 0x00, socks5.AddrTypeIPv4, net.IPv4(127, 0, 0, 1), "", 1080)
				return r
			}(),
			wantErr: true,
		},
		{
			name: "invalid RSV",
			reply: func() socks5.Reply {
				var r socks5.Reply
				r.Init(5, socks5.RepSuccess, 0x01, socks5.AddrTypeIPv4, net.IPv4(127, 0, 0, 1), "", 1080)
				return r
			}(),
			wantErr: true,
		},
		{
			name: "invalid ATYP",
			reply: func() socks5.Reply {
				var r socks5.Reply
				r.Init(5, socks5.RepSuccess, 0x00, 0x99, net.IPv4(127, 0, 0, 1), "", 1080)
				return r
			}(),
			wantErr: true,
		},
		{
			name: "invalid domain length",
			reply: func() socks5.Reply {
				var r socks5.Reply
				r.Init(5, socks5.RepSuccess, 0x00, socks5.AddrTypeDomain, nil, "", 1080)
				return r
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.reply.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func Test_Reply_WriteTo_ReadFrom_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		init func() socks5.Reply
	}{
		{
			name: "IPv4",
			init: func() socks5.Reply {
				var r socks5.Reply
				r.Init(socks5.SocksVersion, socks5.RepSuccess, 0x00, socks5.AddrTypeIPv4, net.IPv4(192, 168, 1, 10), "", 1080)
				return r
			},
		},
		{
			name: "Domain",
			init: func() socks5.Reply {
				var r socks5.Reply
				r.Init(socks5.SocksVersion, socks5.RepSuccess, 0x00, socks5.AddrTypeDomain, nil, "example.org", 443)
				return r
			},
		},
		{
			name: "IPv6",
			init: func() socks5.Reply {
				var r socks5.Reply
				ip := net.ParseIP("2001:db8::1")
				r.Init(socks5.SocksVersion, socks5.RepSuccess, 0x00, socks5.AddrTypeIPv6, ip, "", 9050)
				return r
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

			var got socks5.Reply
			nr, err := got.ReadFrom(&buf)
			if err != nil {
				t.Fatalf("ReadFrom() failed: %v", err)
			}

			if nw != nr {
				t.Errorf("expected %d bytes written == %d bytes read", nw, nr)
			}
			if got.Reply != orig.Reply {
				t.Errorf("reply mismatch: got %d, want %d", got.Reply, orig.Reply)
			}
			if got.Port != orig.Port {
				t.Errorf("port mismatch: got %d, want %d", got.Port, orig.Port)
			}
			if got.AddrType == socks5.AddrTypeDomain && got.Domain != orig.Domain {
				t.Errorf("domain mismatch: got %q, want %q", got.Domain, orig.Domain)
			}
			if (got.AddrType == socks5.AddrTypeIPv4 || got.AddrType == socks5.AddrTypeIPv6) && !got.IP.Equal(orig.IP) {
				t.Errorf("IP mismatch: got %v, want %v", got.IP, orig.IP)
			}
		})
	}
}

func Test_Reply_ReadFrom_InvalidData(t *testing.T) {
	// incomplete 4-byte header
	data := []byte{5, socks5.RepSuccess, 0x00}
	var r socks5.Reply
	if _, err := r.ReadFrom(bytes.NewReader(data)); err == nil {
		t.Errorf("expected error for truncated header")
	}
}

func Test_Reply_WriteTo_InvalidDomain(t *testing.T) {
	var r socks5.Reply
	longDomain := make([]byte, 300)
	for i := range longDomain {
		longDomain[i] = 'a'
	}
	r.Init(5, socks5.RepSuccess, 0x00, socks5.AddrTypeDomain, nil, string(longDomain), 1080)

	var buf bytes.Buffer
	if _, err := r.WriteTo(&buf); err == nil {
		t.Errorf("expected ErrInvalidReplyDomain, got nil")
	}
}

func Test_Reply_String(t *testing.T) {
	r := &socks5.Reply{}
	r.Init(5, socks5.RepHostUnreachable, 0x00, socks5.AddrTypeIPv4, net.IPv4(10, 0, 0, 2), "", 9999)

	if s := r.String(); s == "" {
		t.Errorf("expected non-empty String() output")
	}
}
