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

// ErrReplayDetected is returned when a request salt has already been seen
// within the replay window.
var ErrReplayDetected = errors.New("replay detected")

// MaxTCPChunkPayloadLength is the largest plaintext payload a single TCP chunk
// can carry. Unlike Shadowsocks AEAD, this edition allows the full u16 range.
const MaxTCPChunkPayloadLength = 0xFFFF
