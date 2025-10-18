package socks5

import (
	"errors"
	"fmt"
	"io"
)

// Errors for username/password authentication requests.
var (
	ErrInvalidUserPassVersion = errors.New("invalid user/password auth version (must be 1)")
	ErrEmptyUserPassUsername  = errors.New("username cannot be empty")
	ErrEmptyUserPassPassword  = errors.New("password cannot be empty")
	ErrUserPassTooLong        = errors.New("username or password too long (max 255)")
)

// UserPassRequest represents a username/password authentication request.
type UserPassRequest struct {
	Version  byte   // VER (should always be AuthVersionUserPass = 0x01)
	Username string // UNAME (1–255 bytes)
	Password string // PASSWD (1–255 bytes)
}

// Init initializes the authentication request with username and password.
func (r *UserPassRequest) Init(version byte, username, password string) {
	r.Version = version
	r.Username = username
	r.Password = password
}

// Validate checks for protocol correctness.
func (r *UserPassRequest) Validate() error {
	if r.Version != AuthVersionUserPass {
		return ErrInvalidUserPassVersion
	}
	if len(r.Username) == 0 {
		return ErrEmptyUserPassUsername
	}
	if len(r.Password) == 0 {
		return ErrEmptyUserPassPassword
	}
	if len(r.Username) > 255 || len(r.Password) > 255 {
		return ErrUserPassTooLong
	}
	return nil
}

// ReadFrom reads a username/password authentication request from a reader.
// Implements io.ReaderFrom.
func (r *UserPassRequest) ReadFrom(src io.Reader) (int64, error) {
	var hdr [2]byte

	// Read VER and ULEN
	n, err := io.ReadFull(src, hdr[:])
	if err != nil {
		return int64(n), err
	}

	r.Version = hdr[0]
	ulen := int(hdr[1])
	if ulen == 0 {
		return int64(n), ErrEmptyUserPassUsername
	}

	// Read username
	username := make([]byte, ulen)
	n2, err := io.ReadFull(src, username)
	total := int64(n + n2)
	if err != nil {
		return total, err
	}
	r.Username = string(username)

	// Read PLEN
	var plen [1]byte
	n3, err := io.ReadFull(src, plen[:])
	total += int64(n3)
	if err != nil {
		return total, err
	}

	// Read password
	pwlen := int(plen[0])
	if pwlen == 0 {
		return total, ErrEmptyUserPassPassword
	}

	password := make([]byte, pwlen)
	n4, err := io.ReadFull(src, password)
	total += int64(n4)
	if err != nil {
		return total, err
	}
	r.Password = string(password)

	return total, r.Validate()
}

// WriteTo writes the username/password request to a writer.
// Implements io.WriterTo.
// Note: returns error if user or pass is too long.
func (r *UserPassRequest) WriteTo(dst io.Writer) (int64, error) {
	if len(r.Username) > 255 || len(r.Password) > 255 {
		return 0, ErrUserPassTooLong
	}

	buf := []byte{
		r.Version,
		byte(len(r.Username)),
	}
	total := int64(0)

	// Write version + ULEN
	n, err := dst.Write(buf)
	total += int64(n)
	if err != nil {
		return total, err
	}

	// Write username
	n, err = io.WriteString(dst, r.Username)
	total += int64(n)
	if err != nil {
		return total, err
	}

	// Write password header and body
	pwHdr := [1]byte{byte(len(r.Password))}
	n, err = dst.Write(pwHdr[:])
	total += int64(n)
	if err != nil {
		return total, err
	}

	n, err = io.WriteString(dst, r.Password)
	total += int64(n)
	return total, err
}

// String returns a human-readable representation.
func (r *UserPassRequest) String() string {
	return fmt.Sprintf(
		"UserPassRequest{Version=%d, Username=%q, PasswordLen=%d}",
		r.Version, r.Username, len(r.Password),
	)
}
