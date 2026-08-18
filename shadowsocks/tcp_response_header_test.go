package shadowsocks_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func TestTCPResponseHeader_Init_Validate(t *testing.T) {
	tests := []struct {
		name    string
		hdr     shadowsocks.TCPResponseHeader
		wantErr error
	}{
		{
			name: "valid",
			hdr: func() shadowsocks.TCPResponseHeader {
				var h shadowsocks.TCPResponseHeader
				h.Init(shadowsocks.TCPHeaderTypeServerStream, 123456789, []byte{1, 2, 3, 4}, 4)
				return h
			}(),
		},
		{
			name: "invalid type",
			hdr: func() shadowsocks.TCPResponseHeader {
				var h shadowsocks.TCPResponseHeader
				h.Init(0x99, 123456789, []byte{1, 2, 3, 4}, 4)
				return h
			}(),
			wantErr: shadowsocks.ErrInvalidTCPHeaderType,
		},
		{
			name: "missing salt",
			hdr: func() shadowsocks.TCPResponseHeader {
				var h shadowsocks.TCPResponseHeader
				h.Init(shadowsocks.TCPHeaderTypeServerStream, 123456789, nil, 0)
				return h
			}(),
			wantErr: shadowsocks.ErrMissingTCPResponseSalt,
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

func TestTCPResponseHeader_EncodedLen(t *testing.T) {
	h := shadowsocks.TCPResponseHeader{
		Type:        shadowsocks.TCPHeaderTypeServerStream,
		Timestamp:   1,
		RequestSalt: []byte{1, 2, 3, 4},
		Length:      4,
	}

	want := shadowsocks.TCPResponseFixedBaseLen + 4
	if got := h.EncodedLen(); got != want {
		t.Fatalf("EncodedLen() = %d, want %d", got, want)
	}
}

func TestTCPResponseHeader_EncodeTo_Decode_RoundTrip(t *testing.T) {
	want := shadowsocks.TCPResponseHeader{
		Type:        shadowsocks.TCPHeaderTypeServerStream,
		Timestamp:   123456789,
		RequestSalt: []byte{0xaa, 0xbb, 0xcc, 0xdd},
		Length:      4, // first response payload length
	}

	buf, err := want.EncodeTo(nil)
	if err != nil {
		t.Fatalf("EncodeTo() failed: %v", err)
	}
	if len(buf) != want.EncodedLen() {
		t.Fatalf("EncodeTo() wrote %d bytes, want %d", len(buf), want.EncodedLen())
	}

	var got shadowsocks.TCPResponseHeader
	nr, err := got.Decode(buf, len(want.RequestSalt))
	if err != nil {
		t.Fatalf("Decode() failed: %v", err)
	}
	if nr != len(buf) {
		t.Fatalf("Decode() read %d bytes, want %d", nr, len(buf))
	}

	if got.Type != want.Type || got.Timestamp != want.Timestamp || got.Length != want.Length {
		t.Fatalf("header mismatch: got %+v, want %+v", got, want)
	}
	if !bytes.Equal(got.RequestSalt, want.RequestSalt) {
		t.Fatalf("RequestSalt = %v, want %v", got.RequestSalt, want.RequestSalt)
	}
}

func TestTCPResponseHeader_EncodeTo_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		hdr     shadowsocks.TCPResponseHeader
		bufLen  int
		wantErr error
	}{
		{
			name: "invalid type",
			hdr: shadowsocks.TCPResponseHeader{
				Type:        0x99,
				Timestamp:   1,
				RequestSalt: []byte{1, 2},
				Length:      2,
			},
			bufLen:  32,
			wantErr: shadowsocks.ErrInvalidTCPHeaderType,
		},
		{
			name: "missing salt",
			hdr: shadowsocks.TCPResponseHeader{
				Type:      shadowsocks.TCPHeaderTypeServerStream,
				Timestamp: 1,
				Length:    0,
			},
			bufLen:  32,
			wantErr: shadowsocks.ErrMissingTCPResponseSalt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.bufLen)
			_, err := tt.hdr.EncodeTo(buf[:0])
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("EncodeTo() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestTCPResponseHeader_Decode_Invalid(t *testing.T) {
	tests := []struct {
		name           string
		src            []byte
		requestSaltLen int
		wantErr        error
	}{
		{
			name:           "invalid request salt length",
			src:            []byte{},
			requestSaltLen: 0,
			wantErr:        shadowsocks.ErrInvalidTCPResponseSaltLen,
		},
		{
			name:           "short fixed header",
			src:            make([]byte, 1+8+2+2-1), // type + timestamp + 2-byte salt + length - 1
			requestSaltLen: 2,
			wantErr:        shadowsocks.ErrShortTCPHeader,
		},
		{
			name: "invalid type",
			src: []byte{
				0x99,
				0, 0, 0, 0, 0, 0, 0, 1,
				0xaa, 0xbb,
				0, 2,
			},
			requestSaltLen: 2,
			wantErr:        shadowsocks.ErrInvalidTCPHeaderType,
		},
		{
			name: "missing salt bytes",
			src: []byte{
				shadowsocks.TCPHeaderTypeServerStream,
				0, 0, 0, 0, 0, 0, 0, 1,
				0xaa,
				0, 2,
			},
			requestSaltLen: 2,
			wantErr:        shadowsocks.ErrShortTCPHeader,
		},
		{
			name: "missing length bytes after salt",
			src: []byte{
				shadowsocks.TCPHeaderTypeServerStream,
				0, 0, 0, 0, 0, 0, 0, 1,
				0xaa, 0xbb,
				0,
			},
			requestSaltLen: 2,
			wantErr:        shadowsocks.ErrShortTCPHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h shadowsocks.TCPResponseHeader
			_, err := h.Decode(tt.src, tt.requestSaltLen)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Decode() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestTCPResponseHeader_String(t *testing.T) {
	h := shadowsocks.TCPResponseHeader{
		Type:        shadowsocks.TCPHeaderTypeServerStream,
		Timestamp:   123,
		RequestSalt: []byte{1, 2, 3, 4},
		Length:      4,
	}

	want := "TCPResponseHeader{Type:1 Timestamp:123 RequestSaltLen:4 Length:4}"
	if got := h.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
