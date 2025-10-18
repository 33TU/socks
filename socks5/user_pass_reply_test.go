package socks5_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/33TU/socks/socks5"
)

func Test_UserPassReply_Init_And_Validate(t *testing.T) {
	r := &socks5.UserPassReply{}
	r.Init(socks5.AuthVersionUserPass, 0x00)

	if err := r.Validate(); err != nil {
		t.Fatalf("expected valid reply, got %v", err)
	}

	r.Version = 0x02
	if err := r.Validate(); !errors.Is(err, socks5.ErrInvalidUserPassReplyVersion) {
		t.Errorf("expected ErrInvalidUserPassReplyVersion, got %v", err)
	}
}

func Test_UserPassReply_WriteTo_ReadFrom_RoundTrip(t *testing.T) {
	orig := &socks5.UserPassReply{}
	orig.Init(socks5.AuthVersionUserPass, 0x00)

	var buf bytes.Buffer
	n1, err := orig.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	var parsed socks5.UserPassReply
	n2, err := parsed.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if n1 != n2 {
		t.Errorf("expected %d bytes read, got %d", n1, n2)
	}
	if parsed.Version != socks5.AuthVersionUserPass {
		t.Errorf("expected version %d, got %d", socks5.AuthVersionUserPass, parsed.Version)
	}
	if parsed.Status != 0x00 {
		t.Errorf("expected status 0x00, got 0x%02x", parsed.Status)
	}
	if !parsed.Success() {
		t.Errorf("expected Success() to be true")
	}
}

func Test_UserPassReply_FailureStatus(t *testing.T) {
	r := &socks5.UserPassReply{}
	r.Init(socks5.AuthVersionUserPass, 0xFF)

	if r.Success() {
		t.Errorf("expected Success() to be false for failure status")
	}

	str := r.String()
	if want := "failure(0xff)"; !bytes.Contains([]byte(str), []byte(want)) {
		t.Errorf("expected String() to contain %q, got %q", want, str)
	}
}

func Test_UserPassReply_ReadFrom_Truncated(t *testing.T) {
	data := []byte{1} // incomplete (missing STATUS)
	var r socks5.UserPassReply
	if _, err := r.ReadFrom(bytes.NewReader(data)); err == nil {
		t.Errorf("expected EOF for truncated reply")
	}
}

func Test_UserPassReply_WriteTo_ErrorPropagation(t *testing.T) {
	r := &socks5.UserPassReply{}
	r.Init(socks5.AuthVersionUserPass, 0x00)

	failWriter := writerFunc(func(p []byte) (int, error) {
		return 0, io.ErrClosedPipe
	})

	if _, err := r.WriteTo(failWriter); err == nil {
		t.Errorf("expected write error")
	}
}

func Test_UserPassReply_String(t *testing.T) {
	r := &socks5.UserPassReply{}
	r.Init(socks5.AuthVersionUserPass, 0x00)

	if s := r.String(); s == "" {
		t.Errorf("expected non-empty String() output")
	}
}
