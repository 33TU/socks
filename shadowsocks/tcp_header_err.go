package shadowsocks

import "errors"

// Common validation and decode errors for Shadowsocks TCP headers.
var (
	ErrInvalidTCPHeaderType      = errors.New("invalid TCP header type")
	ErrInvalidTCPPaddingLength   = errors.New("invalid TCP padding length")
	ErrMissingTCPHeaderData      = errors.New("missing TCP header data")
	ErrShortTCPHeader            = errors.New("short TCP header")
	ErrMissingTCPResponseSalt    = errors.New("missing TCP response salt")
	ErrInvalidTCPResponseSaltLen = errors.New("invalid TCP response salt length")
)
