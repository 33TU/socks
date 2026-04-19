package shadowsocks

import (
	"encoding/binary"
	"fmt"
)

// TCPResponseHeader represents the fixed-length response header used by
// Shadowsocks 2022 TCP streams.
type TCPResponseHeader struct {
	Type        byte
	Timestamp   uint64
	RequestSalt []byte
	Length      uint16
}

// Init initializes a TCPResponseHeader.
func (h *TCPResponseHeader) Init(typ byte, timestamp uint64, requestSalt []byte, length uint16) {
	h.Type = typ
	h.Timestamp = timestamp
	h.RequestSalt = requestSalt
	h.Length = length
}

// Validate checks the correctness of the response header fields.
func (h *TCPResponseHeader) Validate() error {
	if h.Type != TCPHeaderTypeServerStream {
		return ErrInvalidTCPHeaderType
	}
	if len(h.RequestSalt) == 0 {
		return ErrMissingTCPResponseSalt
	}
	return nil
}

// EncodedLen returns the number of bytes required to encode the response header.
func (h *TCPResponseHeader) EncodedLen() int {
	return 1 + 8 + len(h.RequestSalt) + 2
}

// Decode decodes a response header from src using the expected request salt length.
// It returns the number of bytes consumed.
func (h *TCPResponseHeader) Decode(src []byte, requestSaltLen int) (int, error) {
	if requestSaltLen <= 0 {
		return 0, ErrInvalidTCPResponseSaltLen
	}

	need := 1 + 8 + requestSaltLen + 2
	if len(src) < need {
		return 0, ErrShortTCPHeader
	}

	h.Type = src[0]
	h.Timestamp = binary.BigEndian.Uint64(src[1:9])
	h.RequestSalt = append(h.RequestSalt[:0], src[9:9+requestSaltLen]...)
	h.Length = binary.BigEndian.Uint16(src[9+requestSaltLen : 9+requestSaltLen+2])

	if err := h.Validate(); err != nil {
		return 0, err
	}

	return need, nil
}

// EncodeTo encodes the response header into dst and returns the extended slice.
func (h *TCPResponseHeader) EncodeTo(dst []byte) ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}

	dst = append(dst, h.Type)
	dst = binary.BigEndian.AppendUint64(dst, h.Timestamp)
	dst = append(dst, h.RequestSalt...)
	dst = binary.BigEndian.AppendUint16(dst, h.Length)

	return dst, nil
}

// String returns a human-readable representation of the response header.
func (h *TCPResponseHeader) String() string {
	return fmt.Sprintf(
		"TCPResponseHeader{Type:%d Timestamp:%d RequestSaltLen:%d Length:%d}",
		h.Type, h.Timestamp, len(h.RequestSalt), h.Length,
	)
}
