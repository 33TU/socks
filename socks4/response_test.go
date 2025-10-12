package socks4_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/33TU/socks/socks4"
)

func Test_Response_Init_Validate(t *testing.T) {
	tests := []struct {
		name    string
		resp    socks4.Response
		wantErr bool
	}{
		{
			name: "valid granted",
			resp: func() socks4.Response {
				var r socks4.Response
				r.Init(0x00, socks4.ReqGranted, 1080, net.IPv4(127, 0, 0, 1))
				return r
			}(),
			wantErr: false,
		},
		{
			name: "invalid version",
			resp: func() socks4.Response {
				var r socks4.Response
				r.Init(0x04, socks4.ReqGranted, 1080, net.IPv4(127, 0, 0, 1))
				return r
			}(),
			wantErr: true,
		},
		{
			name: "invalid code",
			resp: func() socks4.Response {
				var r socks4.Response
				r.Init(0x00, 0x99, 1080, net.IPv4(127, 0, 0, 1))
				return r
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.resp.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func Test_Response_IsGranted(t *testing.T) {
	var r socks4.Response
	r.Init(0x00, socks4.ReqGranted, 1080, net.IPv4(127, 0, 0, 1))
	if !r.IsGranted() {
		t.Errorf("expected IsGranted() to be true")
	}

	r.Code = socks4.ReqRejected
	if r.IsGranted() {
		t.Errorf("expected IsGranted() to be false")
	}
}

func Test_Response_WriteTo_ReadFrom_RoundTrip(t *testing.T) {
	want := socks4.Response{}
	want.Init(0x00, socks4.ReqGranted, 4321, net.IPv4(192, 168, 1, 10))

	var buf bytes.Buffer
	nw, err := want.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo() failed: %v", err)
	}
	if nw != 8 {
		t.Errorf("expected 8 bytes written, got %d", nw)
	}

	var got socks4.Response
	nr, err := got.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrom() failed: %v", err)
	}
	if nr != 8 {
		t.Errorf("expected 8 bytes read, got %d", nr)
	}

	if got.Code != want.Code || got.Port != want.Port || !got.GetIP().Equal(want.GetIP()) {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, want)
	}
}

func Test_Response_ReadFrom_InvalidVersion(t *testing.T) {
	b := []byte{
		0x04,       // invalid version (should be 0x00)
		0x5A,       // granted
		0x04, 0x38, // port 1080
		127, 0, 0, 1,
	}

	var r socks4.Response
	_, err := r.ReadFrom(bytes.NewReader(b))
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
}

func Test_Response_ReadFrom_InvalidCode(t *testing.T) {
	b := []byte{
		0x00,
		0x99,       // invalid code
		0x04, 0x38, // port
		127, 0, 0, 1,
	}

	var r socks4.Response
	_, err := r.ReadFrom(bytes.NewReader(b))
	if err == nil {
		t.Fatal("expected error for invalid code")
	}
}
