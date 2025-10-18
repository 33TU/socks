package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Errors for GSSAPI authentication replies.
var (
	ErrInvalidGSSAPIReplyVersion = errors.New("invalid GSSAPI reply version (must be 1)")
	ErrEmptyGSSAPIReplyToken     = errors.New("GSSAPI reply token cannot be empty")
	ErrGSSAPIReplyTooLong        = errors.New("GSSAPI reply token too long (max 65535)")
)

// GSSAPIReply represents a GSSAPI authentication reply message (RFC 1961 §3.7).
type GSSAPIReply struct {
	Version byte   // VER (should always be 0x01)
	MsgType byte   // MTYP (0x02 = reply token, 0xFF = failure)
	Token   []byte // TOKEN (optional; none if MTYP=0xFF)
}

// Init initializes the GSSAPI reply.
func (r *GSSAPIReply) Init(version, msgType byte, token []byte) {
	r.Version = version
	r.MsgType = msgType
	r.Token = token
}

// Validate checks for protocol correctness.
func (r *GSSAPIReply) Validate() error {
	if r.Version != 0x01 {
		return ErrInvalidGSSAPIReplyVersion
	}
	if r.MsgType == GSSAPITypeAbort {
		return nil
	}
	if len(r.Token) == 0 {
		return ErrEmptyGSSAPIReplyToken
	}
	if len(r.Token) > 65535 {
		return ErrGSSAPIReplyTooLong
	}
	return nil
}

// ReadFrom reads a GSSAPI reply from a reader.
func (r *GSSAPIReply) ReadFrom(src io.Reader) (int64, error) {
	var hdr [4]byte
	n, err := io.ReadFull(src, hdr[:2])
	if err != nil {
		return int64(n), err
	}

	r.Version = hdr[0]
	r.MsgType = hdr[1]
	if r.MsgType == GSSAPITypeAbort {
		return int64(n), nil
	}

	n2, err := io.ReadFull(src, hdr[2:4])
	n += n2
	if err != nil {
		return int64(n), err
	}
	length := binary.BigEndian.Uint16(hdr[2:4])
	if length == 0 {
		return int64(n), ErrEmptyGSSAPIReplyToken
	}

	token := make([]byte, length)
	n3, err := io.ReadFull(src, token)
	total := int64(n + n3)
	if err != nil {
		return total, err
	}
	r.Token = token
	return total, r.Validate()
}

// WriteTo writes the GSSAPI reply to a writer.
func (r *GSSAPIReply) WriteTo(dst io.Writer) (int64, error) {
	if err := r.Validate(); err != nil {
		return 0, err
	}

	if r.MsgType == GSSAPITypeAbort {
		buf := [2]byte{r.Version, r.MsgType}
		n, err := dst.Write(buf[:])
		return int64(n), err
	}

	var hdr [4]byte
	hdr[0] = r.Version
	hdr[1] = r.MsgType
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(r.Token)))

	n, err := dst.Write(hdr[:])
	total := int64(n)
	if err != nil {
		return total, err
	}

	n2, err := dst.Write(r.Token)
	total += int64(n2)
	return total, err
}

// String returns a human-readable representation.
func (r *GSSAPIReply) String() string {
	return fmt.Sprintf(
		"GSSAPIReply{Version=%d, MsgType=0x%02x, TokenLen=%d}",
		r.Version, r.MsgType, len(r.Token),
	)
}
