package socks5

import (
	"errors"
	"fmt"
	"io"
)

// Errors for username/password authentication replies.
var (
	ErrInvalidUserPassReplyVersion = errors.New("invalid user/password reply version (must be 1)")
)

// UserPassReply represents a username/password authentication reply.
type UserPassReply struct {
	Version byte // VER (should be AuthVersionUserPass = 0x01)
	Status  byte // STATUS (0x00 = success, otherwise failure)
}

// Init initializes a user/password authentication reply with the given version and status.
func (r *UserPassReply) Init(version, status byte) {
	r.Version = version
	r.Status = status
}

// Validate ensures the reply is structurally valid.
func (r *UserPassReply) Validate() error {
	if r.Version != AuthVersionUserPass {
		return ErrInvalidUserPassReplyVersion
	}
	return nil
}

// ReadFrom reads a username/password authentication reply from an io.Reader.
// Implements io.ReaderFrom.
func (r *UserPassReply) ReadFrom(src io.Reader) (int64, error) {
	var buf [2]byte

	n, err := io.ReadFull(src, buf[:])
	if err != nil {
		return int64(n), err
	}

	r.Version = buf[0]
	r.Status = buf[1]

	return int64(n), r.Validate()
}

// WriteTo writes the authentication reply to an io.Writer.
// Implements io.WriterTo.
// Note: assumes the struct is already valid.
func (r *UserPassReply) WriteTo(dst io.Writer) (int64, error) {
	buf := [2]byte{r.Version, r.Status}
	n, err := dst.Write(buf[:])
	return int64(n), err
}

// Success returns true if STATUS == 0x00.
func (r *UserPassReply) Success() bool {
	return r.Status == 0x00
}

// String returns a human-readable representation.
func (r *UserPassReply) String() string {
	var status string
	if r.Status == 0x00 {
		status = "success"
	} else {
		status = fmt.Sprintf("failure(0x%02x)", r.Status)
	}

	return fmt.Sprintf(
		"UserPassReply{Version=%d, Status=%s}",
		r.Version, status,
	)
}
