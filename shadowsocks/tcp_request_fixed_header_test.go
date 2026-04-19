package shadowsocks_test

import (
	"errors"
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func TestTCPRequestFixedHeader_Init_Validate(t *testing.T) {
	tests := []struct {
		name    string
		hdr     shadowsocks.TCPRequestFixedHeader
		wantErr error
	}{
		{
			name: "valid",
			hdr: func() shadowsocks.TCPRequestFixedHeader {
				var h shadowsocks.TCPRequestFixedHeader
				h.Init(shadowsocks.TCPHeaderTypeClientStream, 123456789, 42)
				return h
			}(),
		},
		{
			name: "invalid type",
			hdr: func() shadowsocks.TCPRequestFixedHeader {
				var h shadowsocks.TCPRequestFixedHeader
				h.Init(0x99, 123456789, 42)
				return h
			}(),
			wantErr: shadowsocks.ErrInvalidTCPHeaderType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.hdr.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestTCPRequestFixedHeader_EncodedLen(t *testing.T) {
	var h shadowsocks.TCPRequestFixedHeader
	h.Init(shadowsocks.TCPHeaderTypeClientStream, 1, 2)

	if got := h.EncodedLen(); got != shadowsocks.TcpRequestFixedHeaderLen {
		t.Fatalf("EncodedLen() = %d, want %d", got, shadowsocks.TcpRequestFixedHeaderLen)
	}
}

func TestTCPRequestFixedHeader_EncodeTo_Decode_RoundTrip(t *testing.T) {
	var want shadowsocks.TCPRequestFixedHeader
	want.Init(shadowsocks.TCPHeaderTypeClientStream, 123456789, 321)

	buf := make([]byte, want.EncodedLen())

	bw, err := want.EncodeTo(buf[:0])
	if err != nil {
		t.Fatalf("EncodeTo() failed: %v", err)
	}
	if len(bw) != len(buf) {
		t.Fatalf("EncodeTo() wrote %d bytes, want %d", len(bw), len(buf))
	}

	var got shadowsocks.TCPRequestFixedHeader
	nr, err := got.Decode(buf)
	if err != nil {
		t.Fatalf("Decode() failed: %v", err)
	}
	if nr != len(buf) {
		t.Fatalf("Decode() read %d bytes, want %d", nr, len(buf))
	}

	if got.Type != want.Type || got.Timestamp != want.Timestamp || got.Length != want.Length {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestTCPRequestFixedHeader_EncodeTo_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		hdr     shadowsocks.TCPRequestFixedHeader
		bufLen  int
		wantErr error
	}{
		{
			name: "invalid type",
			hdr: shadowsocks.TCPRequestFixedHeader{
				Type:      0x99,
				Timestamp: 1,
				Length:    2,
			},
			bufLen:  32,
			wantErr: shadowsocks.ErrInvalidTCPHeaderType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.bufLen)
			_, err := tt.hdr.EncodeTo(buf)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("EncodeTo() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestTCPRequestFixedHeader_Decode_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		src     []byte
		wantErr error
	}{
		{
			name:    "short header",
			src:     make([]byte, shadowsocks.TcpRequestFixedHeaderLen-1),
			wantErr: shadowsocks.ErrShortTCPHeader,
		},
		{
			name: "invalid type",
			src: []byte{
				0x99,
				0, 0, 0, 0, 0, 0, 0, 1,
				0, 2,
			},
			wantErr: shadowsocks.ErrInvalidTCPHeaderType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h shadowsocks.TCPRequestFixedHeader
			_, err := h.Decode(tt.src)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Decode() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestTCPRequestFixedHeader_String(t *testing.T) {
	var h shadowsocks.TCPRequestFixedHeader
	h.Init(shadowsocks.TCPHeaderTypeClientStream, 123, 45)

	want := "TCPRequestFixedHeader{Type:0 Timestamp:123 Length:45}"
	if got := h.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
