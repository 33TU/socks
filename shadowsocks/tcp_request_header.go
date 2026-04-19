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

////////

// TCPRequestVariableHeader represents the variable-length request header used by
// Shadowsocks 2022 TCP streams.
type TCPRequestVariableHeader struct {
	Target      Addr
	PaddingLen  uint16
	Padding     []byte
	InitialData []byte
}

// Init initializes a TCPRequestVariableHeader.
func (h *TCPRequestVariableHeader) Init(target Addr, padding, initialData []byte) {
	h.Target = target
	h.PaddingLen = uint16(len(padding))
	h.Padding = padding
	h.InitialData = initialData
}

// Validate checks the correctness of the variable request header fields.
func (h *TCPRequestVariableHeader) Validate() error {
	if err := h.Target.Validate(); err != nil {
		return err
	}
	if int(h.PaddingLen) != len(h.Padding) {
		return ErrInvalidTCPPaddingLength
	}
	if len(h.Padding) == 0 && len(h.InitialData) == 0 {
		return ErrMissingTCPHeaderData
	}

	return nil
}

// EncodedLen returns the number of bytes required to encode the variable request header.
func (h *TCPRequestVariableHeader) EncodedLen() int {
	return h.Target.EncodedLen() + 2 + len(h.Padding) + len(h.InitialData)
}

// Decode decodes a variable request header from src.
// It returns the number of bytes consumed.
func (h *TCPRequestVariableHeader) Decode(src []byte) (int, error) {
	h.Target = Addr{}
	h.PaddingLen = 0
	h.Padding = nil
	h.InitialData = nil

	n, err := h.Target.Decode(src)
	if err != nil {
		return 0, err
	}
	if len(src[n:]) < 2 {
		return 0, ErrShortTCPHeader
	}

	h.PaddingLen = binary.BigEndian.Uint16(src[n : n+2])
	n += 2

	if len(src[n:]) < int(h.PaddingLen) {
		return 0, ErrShortTCPHeader
	}

	if h.PaddingLen > 0 {
		h.Padding = append(h.Padding[:0], src[n:n+int(h.PaddingLen)]...)
		n += int(h.PaddingLen)
	}

	if len(src[n:]) > 0 {
		h.InitialData = append(h.InitialData[:0], src[n:]...)
		n = len(src)
	}

	if err := h.Validate(); err != nil {
		return 0, err
	}

	return n, nil
}

// EncodeTo encodes the variable request header into dst.
func (h *TCPRequestVariableHeader) EncodeTo(dst []byte) ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}

	var err error
	dst, err = h.Target.EncodeTo(dst)
	if err != nil {
		return nil, err
	}

	dst = binary.BigEndian.AppendUint16(dst, h.PaddingLen)
	dst = append(dst, h.Padding...)
	dst = append(dst, h.InitialData...)

	return dst, nil
}

// String returns a human-readable representation of the variable request header.
func (h *TCPRequestVariableHeader) String() string {
	return fmt.Sprintf(
		"TCPRequestVariableHeader{Target:%s PaddingLen:%d InitialDataLen:%d}",
		h.Target.String(), h.PaddingLen, len(h.InitialData),
	)
}
