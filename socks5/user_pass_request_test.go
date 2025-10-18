package socks5_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/33TU/socks/socks5"
)

func Test_UserPassRequest_Init_And_Validate(t *testing.T) {
	r := &socks5.UserPassRequest{}
	r.Init(socks5.AuthVersionUserPass, "alice", "secret")

	if err := r.Validate(); err != nil {
		t.Fatalf("expected valid request, got %v", err)
	}

	r.Version = 0x02
	if err := r.Validate(); !errors.Is(err, socks5.ErrInvalidUserPassVersion) {
		t.Errorf("expected ErrInvalidUserPassVersion, got %v", err)
	}

	r.Version = socks5.AuthVersionUserPass
	r.Username = ""
	if err := r.Validate(); !errors.Is(err, socks5.ErrEmptyUserPassUsername) {
		t.Errorf("expected ErrEmptyUserPassUsername, got %v", err)
	}

	r.Username = "bob"
	r.Password = ""
	if err := r.Validate(); !errors.Is(err, socks5.ErrEmptyUserPassPassword) {
		t.Errorf("expected ErrEmptyUserPassPassword, got %v", err)
	}
}

func Test_UserPassRequest_WriteTo_ReadFrom_RoundTrip(t *testing.T) {
	orig := &socks5.UserPassRequest{}
	orig.Init(socks5.AuthVersionUserPass, "admin", "hunter2")

	var buf bytes.Buffer
	n1, err := orig.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	var parsed socks5.UserPassRequest
	n2, err := parsed.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if n1 != n2 {
		t.Errorf("expected %d bytes read, got %d", n1, n2)
	}
	if parsed.Username != orig.Username {
		t.Errorf("expected username %q, got %q", orig.Username, parsed.Username)
	}
	if parsed.Password != orig.Password {
		t.Errorf("expected password %q, got %q", orig.Password, parsed.Password)
	}
	if parsed.Version != socks5.AuthVersionUserPass {
		t.Errorf("expected version %d, got %d", socks5.AuthVersionUserPass, parsed.Version)
	}
}

func Test_UserPassRequest_ReadFrom_Truncated(t *testing.T) {
	// missing password bytes
	data := []byte{
		socks5.AuthVersionUserPass,
		3, 'b', 'o', 'b',
		5, 'p', 'a', 's',
	}
	r := &socks5.UserPassRequest{}
	if _, err := r.ReadFrom(bytes.NewReader(data)); err == nil {
		t.Errorf("expected error for truncated payload")
	}
}

func Test_UserPassRequest_ReadFrom_EmptyUsernameOrPassword(t *testing.T) {
	// empty username (ULEN = 0)
	data := []byte{1, 0}
	r := &socks5.UserPassRequest{}
	if _, err := r.ReadFrom(bytes.NewReader(data)); !errors.Is(err, socks5.ErrEmptyUserPassUsername) {
		t.Errorf("expected ErrEmptyUserPassUsername, got %v", err)
	}

	// empty password (PLEN = 0)
	data = []byte{1, 3, 'b', 'o', 'b', 0}
	if _, err := r.ReadFrom(bytes.NewReader(data)); !errors.Is(err, socks5.ErrEmptyUserPassPassword) {
		t.Errorf("expected ErrEmptyUserPassPassword, got %v", err)
	}
}

func Test_UserPassRequest_WriteTo_ErrorPropagation(t *testing.T) {
	r := &socks5.UserPassRequest{}
	r.Init(socks5.AuthVersionUserPass, "foo", "bar")

	failWriter := writerFunc(func(p []byte) (int, error) {
		return 0, io.ErrClosedPipe
	})

	if _, err := r.WriteTo(failWriter); err == nil {
		t.Errorf("expected write error")
	}
}
func Test_UserPassRequest_String(t *testing.T) {
	r := &socks5.UserPassRequest{}
	r.Init(socks5.AuthVersionUserPass, "user", "pass")

	if s := r.String(); s == "" {
		t.Errorf("expected non-empty String() output")
	}
}
