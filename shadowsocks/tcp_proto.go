package shadowsocks

import (
	"errors"
)

// TCP header types for Shadowsocks 2022 stream protocol.
const (
	TCPHeaderTypeClientStream = 0x00
	TCPHeaderTypeServerStream = 0x01
)

const (
	TcpRequestFixedHeaderLen = 1 + 8 + 2
	TcpResponseFixedBaseLen  = 1 + 8 + 2
)

const (
	AeadNonceSize = 12
	AeadTagSize   = 16
)

const TcpChunkLengthLen = 2

// Common validation and decode errors for Shadowsocks TCP headers.
var (
	ErrInvalidTCPHeaderType      = errors.New("invalid TCP header type")          // res and req
	ErrInvalidTCPPaddingLength   = errors.New("invalid TCP padding length")       // req
	ErrMissingTCPHeaderData      = errors.New("missing TCP header data")          // req
	ErrShortTCPHeader            = errors.New("short TCP header")                 // res and req
	ErrMissingTCPResponseSalt    = errors.New("missing TCP response salt")        // res
	ErrInvalidTCPResponseSaltLen = errors.New("invalid TCP response salt length") // res
)
