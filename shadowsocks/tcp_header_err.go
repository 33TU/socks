package shadowsocks

import "errors"

// Common validation and decode/encode errors for Shadowsocks TCP headers.
var (
	ErrInvalidTCPHeaderType      = errors.New("invalid TCP header type")
	ErrInvalidTCPPaddingLength   = errors.New("invalid TCP padding length")
	ErrMissingTCPHeaderData      = errors.New("missing TCP header data")
	ErrShortTCPHeader            = errors.New("short TCP header")
	ErrShortTCPHeaderBuffer      = errors.New("short TCP header buffer")
	ErrMissingTCPResponseSalt    = errors.New("missing TCP response salt")
	ErrInvalidTCPResponseSaltLen = errors.New("invalid TCP response salt length")
)
