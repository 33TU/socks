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
	if int(h.Length) != len(h.RequestSalt) {
		return ErrInvalidTCPResponseSaltLen
	}

	return nil
}

// EncodedLen returns the number of bytes required to encode the response header.
func (h *TCPResponseHeader) EncodedLen() int {
	return TcpResponseFixedBaseLen + len(h.RequestSalt)
}

// Decode decodes a response header from src.
// It returns the number of bytes consumed.
func (h *TCPResponseHeader) Decode(src []byte) (int, error) {
	if len(src) < TcpResponseFixedBaseLen {
		return 0, ErrShortTCPHeader
	}

	h.Type = src[0]
	h.Timestamp = binary.BigEndian.Uint64(src[1:9])
	h.Length = binary.BigEndian.Uint16(src[9:11])

	need := TcpResponseFixedBaseLen + int(h.Length)
	if len(src) < need {
		return 0, ErrShortTCPHeader
	}

	h.RequestSalt = append(h.RequestSalt[:0], src[11:need]...)

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
	dst = binary.BigEndian.AppendUint16(dst, h.Length)
	dst = append(dst, h.RequestSalt...)

	return dst, nil
}

// String returns a human-readable representation of the response header.
func (h *TCPResponseHeader) String() string {
	return fmt.Sprintf(
		"TCPResponseHeader{Type:%d Timestamp:%d RequestSaltLen:%d Length:%d}",
		h.Type, h.Timestamp, len(h.RequestSalt), h.Length,
	)
}
