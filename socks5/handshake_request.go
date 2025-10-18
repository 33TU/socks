package socks5

import (
	"errors"
	"fmt"
	"io"
)

// Errors for SOCKS5 handshake requests.
var (
	ErrInvalidHandshakeVersion = errors.New("invalid SOCKS version (must be 5)")
	ErrTooManyMethods          = errors.New("too many authentication methods")
	ErrNoMethodsProvided       = errors.New("no authentication methods provided")
)

// HandshakeRequest represents the initial SOCKS5 client handshake (method negotiation).
type HandshakeRequest struct {
	Version  byte   // VER (should always be 0x05)
	NMethods byte   // NMETHODS; number of methods
	Methods  []byte // METHODS; list of supported methods
}

// Init initializes a handshake request with the given methods.
func (h *HandshakeRequest) Init(version byte, methods ...byte) {
	h.Version = version
	h.NMethods = byte(len(methods))
	h.Methods = append([]byte(nil), methods...) // copy
}

// Validate ensures the handshake request is structurally valid.
func (h *HandshakeRequest) Validate() error {
	if h.Version != SocksVersion {
		return ErrInvalidHandshakeVersion
	}
	if h.NMethods == 0 {
		return ErrNoMethodsProvided
	}
	if len(h.Methods) != int(h.NMethods) {
		return ErrTooManyMethods
	}
	return nil
}

// ReadFrom reads a SOCKS5 handshake request from an io.Reader.
// Implements io.ReaderFrom.
func (h *HandshakeRequest) ReadFrom(src io.Reader) (int64, error) {
	var hdr [2]byte

	n, err := io.ReadFull(src, hdr[:])
	if err != nil {
		return int64(n), err
	}

	h.Version = hdr[0]
	h.NMethods = hdr[1]

	if h.NMethods == 0 {
		return int64(n), ErrNoMethodsProvided
	}

	methods := make([]byte, h.NMethods)
	n2, err := io.ReadFull(src, methods)
	total := int64(n + n2)
	if err != nil {
		return total, err
	}

	h.Methods = methods
	return total, h.Validate()
}

// WriteTo writes the handshake request to an io.Writer.
// Implements io.WriterTo.
func (h *HandshakeRequest) WriteTo(dst io.Writer) (int64, error) {
	buf := []byte{h.Version, h.NMethods}
	n, err := dst.Write(buf)
	total := int64(n)
	if err != nil {
		return total, err
	}

	n2, err := dst.Write(h.Methods)
	total += int64(n2)
	return total, err
}

// String returns a human-readable representation of the handshake request.
func (h *HandshakeRequest) String() string {
	return fmt.Sprintf(
		"SOCKS5 HandshakeRequest{Version=%d, Methods=%v}",
		h.Version, h.Methods,
	)
}
