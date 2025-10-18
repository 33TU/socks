package socks5_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/33TU/socks/socks5"
)

func Test_HandshakeReply_Init_And_Validate(t *testing.T) {
	h := &socks5.HandshakeReply{}
	h.Init(socks5.MethodUserPass)

	if err := h.Validate(); err != nil {
		t.Fatalf("expected valid reply, got %v", err)
	}

	h.Version = 4
	if err := h.Validate(); !errors.Is(err, socks5.ErrInvalidHandshakeReplyVersion) {
		t.Errorf("expected ErrInvalidHandshakeReplyVersion, got %v", err)
	}
}

func Test_HandshakeReply_WriteTo_ReadFrom_RoundTrip(t *testing.T) {
	orig := &socks5.HandshakeReply{}
	orig.Init(socks5.MethodNoAuth)

	var buf bytes.Buffer
	n1, err := orig.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	var parsed socks5.HandshakeReply
	n2, err := parsed.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if n1 != n2 {
		t.Errorf("expected %d bytes, got %d", n1, n2)
	}
	if parsed.Method != orig.Method {
		t.Errorf("expected method 0x%02x, got 0x%02x", orig.Method, parsed.Method)
	}
}

func Test_HandshakeReply_ReadFrom_Truncated(t *testing.T) {
	data := []byte{5} // incomplete
	var h socks5.HandshakeReply
	if _, err := h.ReadFrom(bytes.NewReader(data)); err == nil {
		t.Errorf("expected EOF for truncated reply")
	}
}

func Test_HandshakeReply_WriteTo_ErrorPropagation(t *testing.T) {
	h := &socks5.HandshakeReply{}
	h.Init(socks5.MethodUserPass)

	failWriter := writerFunc(func(p []byte) (int, error) {
		return 0, io.ErrClosedPipe
	})

	if _, err := h.WriteTo(failWriter); err == nil {
		t.Errorf("expected write error")
	}
}

func Test_HandshakeReply_String(t *testing.T) {
	h := &socks5.HandshakeReply{}
	h.Init(socks5.MethodNoAuth)

	if s := h.String(); s == "" {
		t.Errorf("expected non-empty String() output")
	}
}
