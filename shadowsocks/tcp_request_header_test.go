package shadowsocks_test

import (
	"bytes"
	"errors"
	"net"
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

	if got := h.EncodedLen(); got != shadowsocks.TCPRequestFixedHeaderLen {
		t.Fatalf("EncodedLen() = %d, want %d", got, shadowsocks.TCPRequestFixedHeaderLen)
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
			src:     make([]byte, shadowsocks.TCPRequestFixedHeaderLen-1),
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

///////

func TestTCPRequestVariableHeader_Init_Validate(t *testing.T) {
	validTarget := shadowsocks.Addr{
		AddrType: shadowsocks.AddrTypeDomain,
		Domain:   "example.com",
		Port:     443,
	}

	tests := []struct {
		name    string
		hdr     shadowsocks.TCPRequestVariableHeader
		wantErr error
	}{
		{
			name: "valid with padding",
			hdr: func() shadowsocks.TCPRequestVariableHeader {
				var h shadowsocks.TCPRequestVariableHeader
				h.Init(validTarget, []byte{1, 2, 3}, nil)
				return h
			}(),
		},
		{
			name: "valid with initial data",
			hdr: func() shadowsocks.TCPRequestVariableHeader {
				var h shadowsocks.TCPRequestVariableHeader
				h.Init(validTarget, nil, []byte("hello"))
				return h
			}(),
		},
		{
			name: "invalid target",
			hdr: shadowsocks.TCPRequestVariableHeader{
				Target: shadowsocks.Addr{
					AddrType: 0x99,
					Port:     80,
				},
				PaddingLen: 1,
				Padding:    []byte{1},
			},
			wantErr: shadowsocks.ErrInvalidAddrType,
		},
		{
			name: "invalid padding length",
			hdr: shadowsocks.TCPRequestVariableHeader{
				Target:     validTarget,
				PaddingLen: 5,
				Padding:    []byte{1, 2},
			},
			wantErr: shadowsocks.ErrInvalidTCPPaddingLength,
		},
		{
			name: "missing header data",
			hdr: shadowsocks.TCPRequestVariableHeader{
				Target:      validTarget,
				PaddingLen:  0,
				Padding:     nil,
				InitialData: nil,
			},
			wantErr: shadowsocks.ErrMissingTCPHeaderData,
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

func TestTCPRequestVariableHeader_EncodedLen(t *testing.T) {
	h := shadowsocks.TCPRequestVariableHeader{
		Target: shadowsocks.Addr{
			AddrType: shadowsocks.AddrTypeDomain,
			Domain:   "example.com",
			Port:     443,
		},
		PaddingLen:  3,
		Padding:     []byte{1, 2, 3},
		InitialData: []byte("abc"),
	}

	want := h.Target.EncodedLen() + 2 + 3 + 3
	if got := h.EncodedLen(); got != want {
		t.Fatalf("EncodedLen() = %d, want %d", got, want)
	}
}

func TestTCPRequestVariableHeader_EncodeTo_Decode_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		hdr  shadowsocks.TCPRequestVariableHeader
	}{
		{
			name: "domain target",
			hdr: shadowsocks.TCPRequestVariableHeader{
				Target: shadowsocks.Addr{
					AddrType: shadowsocks.AddrTypeDomain,
					Domain:   "example.com",
					Port:     443,
				},
				PaddingLen:  2,
				Padding:     []byte{0xaa, 0xbb},
				InitialData: []byte("hello"),
			},
		},
		{
			name: "ipv4 target",
			hdr: shadowsocks.TCPRequestVariableHeader{
				Target: shadowsocks.Addr{
					AddrType: shadowsocks.AddrTypeIPv4,
					IP:       net.IPv4(127, 0, 0, 1),
					Port:     1080,
				},
				PaddingLen:  1,
				Padding:     []byte{0x01},
				InitialData: []byte("x"),
			},
		},
		{
			name: "ipv6 target",
			hdr: shadowsocks.TCPRequestVariableHeader{
				Target: shadowsocks.Addr{
					AddrType: shadowsocks.AddrTypeIPv6,
					IP:       net.ParseIP("2001:db8::1"),
					Port:     53,
				},
				PaddingLen:  3,
				Padding:     []byte{1, 2, 3},
				InitialData: []byte("payload"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.hdr.EncodedLen())

			bw, err := tt.hdr.EncodeTo(buf[:0])
			if err != nil {
				t.Fatalf("EncodeTo() failed: %v", err)
			}
			if len(bw) != len(buf) {
				t.Fatalf("EncodeTo() wrote %d bytes, want %d", len(bw), len(buf))
			}

			var got shadowsocks.TCPRequestVariableHeader
			nr, err := got.Decode(buf)
			if err != nil {
				t.Fatalf("Decode() failed: %v", err)
			}
			if nr != len(buf) {
				t.Fatalf("Decode() read %d bytes, want %d", nr, len(buf))
			}

			if got.Target.AddrType != tt.hdr.Target.AddrType {
				t.Fatalf("Target.AddrType = %v, want %v", got.Target.AddrType, tt.hdr.Target.AddrType)
			}
			if got.Target.Port != tt.hdr.Target.Port {
				t.Fatalf("Target.Port = %d, want %d", got.Target.Port, tt.hdr.Target.Port)
			}
			if got.Target.Domain != tt.hdr.Target.Domain {
				t.Fatalf("Target.Domain = %q, want %q", got.Target.Domain, tt.hdr.Target.Domain)
			}
			if tt.hdr.Target.IP != nil && !got.Target.IP.Equal(tt.hdr.Target.IP) {
				t.Fatalf("Target.IP = %v, want %v", got.Target.IP, tt.hdr.Target.IP)
			}
			if got.PaddingLen != tt.hdr.PaddingLen {
				t.Fatalf("PaddingLen = %d, want %d", got.PaddingLen, tt.hdr.PaddingLen)
			}
			if !bytes.Equal(got.Padding, tt.hdr.Padding) {
				t.Fatalf("Padding = %v, want %v", got.Padding, tt.hdr.Padding)
			}
			if !bytes.Equal(got.InitialData, tt.hdr.InitialData) {
				t.Fatalf("InitialData = %v, want %v", got.InitialData, tt.hdr.InitialData)
			}
		})
	}
}

func TestTCPRequestVariableHeader_EncodeTo_Invalid(t *testing.T) {
	validTarget := shadowsocks.Addr{
		AddrType: shadowsocks.AddrTypeDomain,
		Domain:   "example.com",
		Port:     443,
	}

	tests := []struct {
		name    string
		hdr     shadowsocks.TCPRequestVariableHeader
		bufLen  int
		wantErr error
	}{
		{
			name: "invalid target",
			hdr: shadowsocks.TCPRequestVariableHeader{
				Target: shadowsocks.Addr{
					AddrType: 0x99,
				},
				PaddingLen: 1,
				Padding:    []byte{1},
			},
			bufLen:  64,
			wantErr: shadowsocks.ErrInvalidAddrType,
		},
		{
			name: "invalid padding length",
			hdr: shadowsocks.TCPRequestVariableHeader{
				Target:     validTarget,
				PaddingLen: 10,
				Padding:    []byte{1},
			},
			bufLen:  64,
			wantErr: shadowsocks.ErrInvalidTCPPaddingLength,
		},
		{
			name: "missing header data",
			hdr: shadowsocks.TCPRequestVariableHeader{
				Target: validTarget,
			},
			bufLen:  64,
			wantErr: shadowsocks.ErrMissingTCPHeaderData,
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

func TestTCPRequestVariableHeader_Decode_Invalid(t *testing.T) {
	validTarget := shadowsocks.Addr{
		AddrType: shadowsocks.AddrTypeDomain,
		Domain:   "example.com",
		Port:     443,
	}
	validTargetBuf, err := validTarget.EncodeTo(nil)
	if err != nil {
		t.Fatalf("target EncodeTo() failed: %v", err)
	}

	tests := []struct {
		name    string
		src     []byte
		wantErr error
	}{
		{
			name:    "invalid target",
			src:     []byte{0x99},
			wantErr: shadowsocks.ErrInvalidAddrType,
		},
		{
			name:    "short after target before padding length",
			src:     validTargetBuf[:len(validTargetBuf)-1],
			wantErr: shadowsocks.ErrShortAddr,
		},
		{
			name:    "missing padding length bytes",
			src:     append(append([]byte{}, validTargetBuf...), 0x00),
			wantErr: shadowsocks.ErrShortTCPHeader,
		},
		{
			name:    "short padding bytes",
			src:     append(append(append([]byte{}, validTargetBuf...), 0x00, 0x02), 0x01),
			wantErr: shadowsocks.ErrShortTCPHeader,
		},
		{
			name:    "missing header data",
			src:     append(append([]byte{}, validTargetBuf...), 0x00, 0x00),
			wantErr: shadowsocks.ErrMissingTCPHeaderData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h shadowsocks.TCPRequestVariableHeader
			_, err := h.Decode(tt.src)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Decode() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestTCPRequestVariableHeader_String(t *testing.T) {
	h := shadowsocks.TCPRequestVariableHeader{
		Target: shadowsocks.Addr{
			AddrType: shadowsocks.AddrTypeDomain,
			Domain:   "example.com",
			Port:     443,
		},
		PaddingLen:  2,
		Padding:     []byte{1, 2},
		InitialData: []byte("abc"),
	}

	want := `TCPRequestVariableHeader{Target:Addr{AddrType=DOMAIN, Host=example.com, Port=443} PaddingLen:2 InitialDataLen:3}`
	if got := h.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
