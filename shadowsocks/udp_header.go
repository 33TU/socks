package shadowsocks

import (
	"encoding/binary"
	"fmt"
)

// UDPClientHeader is the main header of a client-to-server packet. The payload
// follows the header directly in the packet body.
type UDPClientHeader struct {
	Type       byte
	Timestamp  uint64
	PaddingLen uint16
	Padding    []byte
	Target     Addr
}

// Init initializes a UDPClientHeader.
func (h *UDPClientHeader) Init(typ byte, timestamp uint64, padding []byte, target Addr) {
	h.Type = typ
	h.Timestamp = timestamp
	h.PaddingLen = uint16(len(padding))
	h.Padding = padding
	h.Target = target
}

// Validate checks the correctness of the client header fields.
func (h *UDPClientHeader) Validate() error {
	if h.Type != UDPHeaderTypeClientPacket {
		return ErrInvalidUDPHeaderType
	}
	if int(h.PaddingLen) != len(h.Padding) {
		return ErrInvalidTCPPaddingLength
	}
	return h.Target.Validate()
}

// EncodedLen returns the number of bytes required to encode the client header.
func (h *UDPClientHeader) EncodedLen() int {
	return UDPClientHeaderFixedLen + len(h.Padding) + h.Target.EncodedLen()
}

// Decode decodes a client header from src.
// It returns the number of bytes consumed, so the payload is src[n:].
func (h *UDPClientHeader) Decode(src []byte) (int, error) {
	if len(src) < UDPClientHeaderFixedLen {
		return 0, ErrShortUDPHeader
	}

	h.Type = src[0]
	h.Timestamp = binary.BigEndian.Uint64(src[1:9])
	h.PaddingLen = binary.BigEndian.Uint16(src[9:11])
	h.Padding = nil
	h.Target = Addr{}

	if h.Type != UDPHeaderTypeClientPacket {
		return 0, ErrInvalidUDPHeaderType
	}

	n := UDPClientHeaderFixedLen
	if len(src)-n < int(h.PaddingLen) {
		return 0, ErrUDPPaddingExceedsPacket
	}
	if h.PaddingLen > 0 {
		h.Padding = append(h.Padding[:0], src[n:n+int(h.PaddingLen)]...)
		n += int(h.PaddingLen)
	}

	addrLen, err := h.Target.Decode(src[n:])
	if err != nil {
		return 0, err
	}

	return n + addrLen, nil
}

// EncodeTo encodes the client header into dst and returns the extended slice.
func (h *UDPClientHeader) EncodeTo(dst []byte) ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}

	dst = append(dst, h.Type)
	dst = binary.BigEndian.AppendUint64(dst, h.Timestamp)
	dst = binary.BigEndian.AppendUint16(dst, h.PaddingLen)
	dst = append(dst, h.Padding...)

	return h.Target.EncodeTo(dst)
}

// String returns a human-readable representation of the client header.
func (h *UDPClientHeader) String() string {
	return fmt.Sprintf(
		"UDPClientHeader{Type:%d Timestamp:%d PaddingLen:%d Target:%s}",
		h.Type, h.Timestamp, h.PaddingLen, h.Target.String(),
	)
}

////////

// UDPServerHeader is the main header of a server-to-client packet. It carries
// the client session ID that maps the server session back to a client session.
type UDPServerHeader struct {
	Type            byte
	Timestamp       uint64
	ClientSessionID uint64
	PaddingLen      uint16
	Padding         []byte
	Source          Addr
}

// Init initializes a UDPServerHeader.
func (h *UDPServerHeader) Init(typ byte, timestamp, clientSessionID uint64, padding []byte, source Addr) {
	h.Type = typ
	h.Timestamp = timestamp
	h.ClientSessionID = clientSessionID
	h.PaddingLen = uint16(len(padding))
	h.Padding = padding
	h.Source = source
}

// Validate checks the correctness of the server header fields.
func (h *UDPServerHeader) Validate() error {
	if h.Type != UDPHeaderTypeServerPacket {
		return ErrInvalidUDPHeaderType
	}
	if int(h.PaddingLen) != len(h.Padding) {
		return ErrInvalidTCPPaddingLength
	}
	return h.Source.Validate()
}

// EncodedLen returns the number of bytes required to encode the server header.
func (h *UDPServerHeader) EncodedLen() int {
	return UDPServerHeaderFixedLen + len(h.Padding) + h.Source.EncodedLen()
}

// Decode decodes a server header from src.
// It returns the number of bytes consumed, so the payload is src[n:].
func (h *UDPServerHeader) Decode(src []byte) (int, error) {
	if len(src) < UDPServerHeaderFixedLen {
		return 0, ErrShortUDPHeader
	}

	h.Type = src[0]
	h.Timestamp = binary.BigEndian.Uint64(src[1:9])
	h.ClientSessionID = binary.BigEndian.Uint64(src[9:17])
	h.PaddingLen = binary.BigEndian.Uint16(src[17:19])
	h.Padding = nil
	h.Source = Addr{}

	if h.Type != UDPHeaderTypeServerPacket {
		return 0, ErrInvalidUDPHeaderType
	}

	n := UDPServerHeaderFixedLen
	if len(src)-n < int(h.PaddingLen) {
		return 0, ErrUDPPaddingExceedsPacket
	}
	if h.PaddingLen > 0 {
		h.Padding = append(h.Padding[:0], src[n:n+int(h.PaddingLen)]...)
		n += int(h.PaddingLen)
	}

	addrLen, err := h.Source.Decode(src[n:])
	if err != nil {
		return 0, err
	}

	return n + addrLen, nil
}

// EncodeTo encodes the server header into dst and returns the extended slice.
func (h *UDPServerHeader) EncodeTo(dst []byte) ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}

	dst = append(dst, h.Type)
	dst = binary.BigEndian.AppendUint64(dst, h.Timestamp)
	dst = binary.BigEndian.AppendUint64(dst, h.ClientSessionID)
	dst = binary.BigEndian.AppendUint16(dst, h.PaddingLen)
	dst = append(dst, h.Padding...)

	return h.Source.EncodeTo(dst)
}

// String returns a human-readable representation of the server header.
func (h *UDPServerHeader) String() string {
	return fmt.Sprintf(
		"UDPServerHeader{Type:%d Timestamp:%d ClientSessionID:%d PaddingLen:%d Source:%s}",
		h.Type, h.Timestamp, h.ClientSessionID, h.PaddingLen, h.Source.String(),
	)
}
