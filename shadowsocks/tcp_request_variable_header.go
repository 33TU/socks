package shadowsocks

import (
	"encoding/binary"
	"fmt"
)

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
// It returns the number of bytes written.
func (h *TCPRequestVariableHeader) EncodeTo(dst []byte) (int, error) {
	if err := h.Validate(); err != nil {
		return 0, err
	}

	n := h.EncodedLen()
	if len(dst) < n {
		return 0, ErrShortTCPHeaderBuffer
	}

	off, err := h.Target.EncodeTo(dst)
	if err != nil {
		return 0, err
	}

	binary.BigEndian.PutUint16(dst[off:off+2], h.PaddingLen)
	off += 2

	copy(dst[off:off+len(h.Padding)], h.Padding)
	off += len(h.Padding)

	copy(dst[off:off+len(h.InitialData)], h.InitialData)
	off += len(h.InitialData)

	return off, nil
}

// String returns a human-readable representation of the variable request header.
func (h *TCPRequestVariableHeader) String() string {
	return fmt.Sprintf(
		"TCPRequestVariableHeader{Target:%s PaddingLen:%d InitialDataLen:%d}",
		h.Target.String(), h.PaddingLen, len(h.InitialData),
	)
}
