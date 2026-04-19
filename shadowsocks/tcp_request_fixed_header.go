package shadowsocks

import (
	"encoding/binary"
	"fmt"
)

// TCPRequestFixedHeader represents the fixed-length request header used by
// Shadowsocks 2022 TCP streams.
type TCPRequestFixedHeader struct {
	Type      byte
	Timestamp uint64
	Length    uint16
}

// Init initializes a TCPRequestFixedHeader.
func (h *TCPRequestFixedHeader) Init(typ byte, timestamp uint64, length uint16) {
	h.Type = typ
	h.Timestamp = timestamp
	h.Length = length
}

// Validate checks the correctness of the fixed request header fields.
func (h *TCPRequestFixedHeader) Validate() error {
	if h.Type != TCPHeaderTypeClientStream {
		return ErrInvalidTCPHeaderType
	}

	return nil
}

// EncodedLen returns the number of bytes required to encode the fixed request header.
func (h *TCPRequestFixedHeader) EncodedLen() int {
	return TcpRequestFixedHeaderLen
}

// Decode decodes a fixed request header from src.
// It returns the number of bytes consumed.
func (h *TCPRequestFixedHeader) Decode(src []byte) (int, error) {
	if len(src) < TcpRequestFixedHeaderLen {
		return 0, ErrShortTCPHeader
	}

	h.Type = src[0]
	h.Timestamp = binary.BigEndian.Uint64(src[1:9])
	h.Length = binary.BigEndian.Uint16(src[9:11])

	return TcpRequestFixedHeaderLen, h.Validate()
}

// EncodeTo encodes the fixed request header into dst.
func (h *TCPRequestFixedHeader) EncodeTo(dst []byte) ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}

	dst = append(dst, h.Type)
	dst = binary.BigEndian.AppendUint64(dst, h.Timestamp)
	dst = binary.BigEndian.AppendUint16(dst, h.Length)

	return dst, nil
}

// String returns a human-readable representation of the fixed request header.
func (h *TCPRequestFixedHeader) String() string {
	return fmt.Sprintf(
		"TCPRequestFixedHeader{Type:%d Timestamp:%d Length:%d}",
		h.Type, h.Timestamp, h.Length,
	)
}
