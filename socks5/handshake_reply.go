package socks5

import (
	"errors"
	"fmt"
	"io"
)

// Errors for SOCKS5 handshake replies.
var (
	ErrInvalidHandshakeReplyVersion = errors.New("invalid SOCKS version in handshake reply (must be 5)")
)

// HandshakeReply represents the server’s response to a SOCKS5 handshake request.
type HandshakeReply struct {
	Version byte // VER (should always be 0x05)
	Method  byte // METHOD; selected authentication method
}

// Init initializes a handshake reply with the given method.
func (h *HandshakeReply) Init(version byte, method byte) {
	h.Version = version
	h.Method = method
}

// Validate ensures the handshake reply is valid.
func (h *HandshakeReply) Validate() error {
	if h.Version != SocksVersion {
		return ErrInvalidHandshakeReplyVersion
	}
	return nil
}

// ReadFrom reads a SOCKS5 handshake reply from an io.Reader.
// Implements io.ReaderFrom.
func (h *HandshakeReply) ReadFrom(src io.Reader) (int64, error) {
	var buf [2]byte

	n, err := io.ReadFull(src, buf[:])
	if err != nil {
		return int64(n), err
	}

	h.Version = buf[0]
	h.Method = buf[1]

	return int64(n), h.Validate()
}

// WriteTo writes the handshake reply to an io.Writer.
// Implements io.WriterTo.
func (h *HandshakeReply) WriteTo(dst io.Writer) (int64, error) {
	buf := [2]byte{h.Version, h.Method}
	n, err := dst.Write(buf[:])
	return int64(n), err
}

// String returns a human-readable representation of the handshake reply.
func (h *HandshakeReply) String() string {
	var method string
	switch h.Method {
	case MethodNoAuth:
		method = "NoAuth"
	case MethodGSSAPI:
		method = "GSSAPI"
	case MethodUserPass:
		method = "UserPass"
	case MethodNoAcceptable:
		method = "NoAcceptable"
	default:
		method = fmt.Sprintf("Unknown(0x%02x)", h.Method)
	}

	return fmt.Sprintf(
		"SOCKS5 HandshakeReply{Version=%d, Method=%s}",
		h.Version, method,
	)
}
