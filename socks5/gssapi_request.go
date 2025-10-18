package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Errors for GSSAPI authentication requests.
var (
	ErrInvalidGSSAPIVersion = errors.New("invalid GSSAPI version (must be 1)")
	ErrEmptyGSSAPIToken     = errors.New("GSSAPI token cannot be empty")
	ErrGSSAPITokenTooLong   = errors.New("GSSAPI token too long (max 65535)")
)

// GSSAPIRequest represents a GSSAPI authentication request (RFC 1961 §3.4).
type GSSAPIRequest struct {
	Version byte   // VER (should always be 0x01)
	MsgType byte   // MTYP (0x01 = initial token)
	Token   []byte // TOKEN (opaque GSSAPI token)
}

// Init initializes a GSSAPI authentication request.
func (r *GSSAPIRequest) Init(version, msgType byte, token []byte) {
	r.Version = version
	r.MsgType = msgType
	r.Token = token
}

// Validate checks for protocol correctness.
func (r *GSSAPIRequest) Validate() error {
	if r.Version != 0x01 {
		return ErrInvalidGSSAPIVersion
	}
	if r.MsgType == GSSAPITypeAbort {
		return nil // Abort messages have no token
	}
	if len(r.Token) == 0 {
		return ErrEmptyGSSAPIToken
	}
	if len(r.Token) > 65535 {
		return ErrGSSAPITokenTooLong
	}
	return nil
}

// ReadFrom reads a GSSAPI authentication request from a reader.
func (r *GSSAPIRequest) ReadFrom(src io.Reader) (int64, error) {
	var hdr [4]byte
	n, err := io.ReadFull(src, hdr[:2])
	if err != nil {
		return int64(n), err
	}

	r.Version = hdr[0]
	r.MsgType = hdr[1]
	if r.MsgType == GSSAPITypeAbort {
		return int64(n), nil
	}

	// Read length
	n2, err := io.ReadFull(src, hdr[2:4])
	n += n2
	if err != nil {
		return int64(n), err
	}
	length := binary.BigEndian.Uint16(hdr[2:4])
	if length == 0 {
		return int64(n), ErrEmptyGSSAPIToken
	}

	token := make([]byte, length)
	n3, err := io.ReadFull(src, token)
	total := int64(n + n3)
	if err != nil {
		return total, err
	}
	r.Token = token
	return total, r.Validate()
}

// WriteTo writes the GSSAPI authentication request to a writer.
func (r *GSSAPIRequest) WriteTo(dst io.Writer) (int64, error) {
	if err := r.Validate(); err != nil {
		return 0, err
	}

	if r.MsgType == GSSAPITypeAbort {
		// Only version + abort message type
		buf := [2]byte{r.Version, r.MsgType}
		n, err := dst.Write(buf[:])
		return int64(n), err
	}

	var hdr [4]byte
	hdr[0] = r.Version
	hdr[1] = r.MsgType
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(r.Token)))

	n, err := dst.Write(hdr[:])
	total := int64(n)
	if err != nil {
		return total, err
	}

	n2, err := dst.Write(r.Token)
	total += int64(n2)
	return total, err
}

// String returns a human-readable representation.
func (r *GSSAPIRequest) String() string {
	return fmt.Sprintf(
		"GSSAPIRequest{Version=%d, MsgType=0x%02x, TokenLen=%d}",
		r.Version, r.MsgType, len(r.Token),
	)
}
