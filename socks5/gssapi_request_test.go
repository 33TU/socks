package socks5_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/33TU/socks/socks5"
)

func Test_GSSAPIRequest_Init_And_Validate(t *testing.T) {
	r := &socks5.GSSAPIRequest{}
	r.Init(socks5.GSSAPIVersion, socks5.GSSAPITypeInit, []byte{0xde, 0xad, 0xbe, 0xef})

	if err := r.Validate(); err != nil {
		t.Fatalf("expected valid request, got %v", err)
	}

	r.Version = 0x05
	if err := r.Validate(); !errors.Is(err, socks5.ErrInvalidGSSAPIVersion) {
		t.Errorf("expected ErrInvalidGSSAPIVersion, got %v", err)
	}

	r.Version = socks5.GSSAPIVersion
	r.MsgType = socks5.GSSAPITypeInit
	r.Token = nil
	if err := r.Validate(); !errors.Is(err, socks5.ErrEmptyGSSAPIToken) {
		t.Errorf("expected ErrEmptyGSSAPIToken, got %v", err)
	}

	// Abort messages skip token validation
	r.MsgType = socks5.GSSAPITypeAbort
	r.Token = nil
	if err := r.Validate(); err != nil {
		t.Errorf("abort message should be valid, got %v", err)
	}

	r.MsgType = socks5.GSSAPITypeInit
	r.Token = make([]byte, 70000)
	if err := r.Validate(); !errors.Is(err, socks5.ErrGSSAPITokenTooLong) {
		t.Errorf("expected ErrGSSAPITokenTooLong, got %v", err)
	}
}

func Test_GSSAPIRequest_WriteTo_ReadFrom_RoundTrip(t *testing.T) {
	orig := &socks5.GSSAPIRequest{}
	orig.Init(socks5.GSSAPIVersion, socks5.GSSAPITypeInit, []byte{0x11, 0x22, 0x33, 0x44})

	var buf bytes.Buffer
	n1, err := orig.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	var parsed socks5.GSSAPIRequest
	n2, err := parsed.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if n1 != n2 {
		t.Errorf("expected %d bytes read, got %d", n1, n2)
	}
	if parsed.Version != socks5.GSSAPIVersion {
		t.Errorf("expected version 1, got %d", parsed.Version)
	}
	if parsed.MsgType != socks5.GSSAPITypeInit {
		t.Errorf("expected msgType 0x01, got %#02x", parsed.MsgType)
	}
	if !bytes.Equal(parsed.Token, orig.Token) {
		t.Errorf("token mismatch: got %x, want %x", parsed.Token, orig.Token)
	}
}

func Test_GSSAPIRequest_ReadFrom_Abort(t *testing.T) {
	data := []byte{socks5.GSSAPIVersion, socks5.GSSAPITypeAbort}
	r := &socks5.GSSAPIRequest{}
	n, err := r.ReadFrom(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 bytes read, got %d", n)
	}
	if r.MsgType != socks5.GSSAPITypeAbort {
		t.Errorf("expected abort msgType 0xFF, got %#02x", r.MsgType)
	}
}

func Test_GSSAPIRequest_ReadFrom_Truncated(t *testing.T) {
	data := []byte{
		socks5.GSSAPIVersion, socks5.GSSAPITypeInit, 0x00, 0x04, // header
		0xde, 0xad, // only 2 of 4 bytes
	}
	r := &socks5.GSSAPIRequest{}
	if _, err := r.ReadFrom(bytes.NewReader(data)); err == nil {
		t.Errorf("expected error for truncated payload")
	}
}

func Test_GSSAPIRequest_ReadFrom_EmptyOrTooLong(t *testing.T) {
	// empty token (len=0)
	data := []byte{socks5.GSSAPIVersion, socks5.GSSAPITypeInit, 0x00, 0x00}
	r := &socks5.GSSAPIRequest{}
	if _, err := r.ReadFrom(bytes.NewReader(data)); !errors.Is(err, socks5.ErrEmptyGSSAPIToken) {
		t.Errorf("expected ErrEmptyGSSAPIToken, got %v", err)
	}

	// invalid version
	data = []byte{0x05, socks5.GSSAPITypeInit, 0x00, 0x01, 0xff}
	if _, err := r.ReadFrom(bytes.NewReader(data)); !errors.Is(err, socks5.ErrInvalidGSSAPIVersion) && err != nil {
		t.Errorf("expected ErrInvalidGSSAPIVersion, got %v", err)
	}
}

func Test_GSSAPIRequest_WriteTo_ErrorPropagation(t *testing.T) {
	r := &socks5.GSSAPIRequest{}
	r.Init(socks5.GSSAPIVersion, socks5.GSSAPITypeInit, []byte{0xaa, 0xbb})

	failWriter := writerFunc(func(p []byte) (int, error) {
		return 0, io.ErrClosedPipe
	})

	if _, err := r.WriteTo(failWriter); err == nil {
		t.Errorf("expected write error")
	}
}

func Test_GSSAPIRequest_String(t *testing.T) {
	r := &socks5.GSSAPIRequest{}
	r.Init(socks5.GSSAPIVersion, socks5.GSSAPITypeInit, []byte{0xde, 0xad})
	if s := r.String(); s == "" {
		t.Errorf("expected non-empty String() output")
	}
}
