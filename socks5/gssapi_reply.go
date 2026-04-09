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
	ErrInvalidGSSAPIMsgType      = errors.New("invalid GSSAPI message type")
	ErrGSSAPIReplyTooLong        = errors.New("GSSAPI reply token too long (max 65535)")
)

// GSSAPIReply represents a GSSAPI authentication reply message (RFC 1961 §3.7).
type GSSAPIReply struct {
	Version byte   // VER (should always be 0x01)
	MsgType byte   // MTYP (0x02 = reply token, 0xFF = failure)
	Token   []byte // TOKEN (optional; may be empty for final success)
}

// Init initializes the GSSAPI reply.
func (r *GSSAPIReply) Init(version, msgType byte, token []byte) {
	r.Version = version
	r.MsgType = msgType
	r.Token = token
}

// Validate checks for protocol correctness.
func (r *GSSAPIReply) Validate() error {
	if r.Version != GSSAPIVersion {
		return ErrInvalidGSSAPIReplyVersion
	}

	switch r.MsgType {
	case GSSAPITypeReply:
		// Token MAY be empty (final step)
	case GSSAPITypeAbort:
		// Token should be empty (but we don't strictly enforce)
	default:
		return ErrInvalidGSSAPIMsgType
	}

	if len(r.Token) > 65535 {
		return ErrGSSAPIReplyTooLong
	}

	return nil
}

// ReadFrom reads a GSSAPI reply from a reader.
func (r *GSSAPIReply) ReadFrom(src io.Reader) (int64, error) {
	var hdr [4]byte

	// Read VER + MTYP
	n, err := io.ReadFull(src, hdr[:2])
	if err != nil {
		return int64(n), err
	}

	r.Version = hdr[0]
	r.MsgType = hdr[1]

	// Abort message has no token
	if r.MsgType == GSSAPITypeAbort {
		r.Token = nil
		return int64(n), r.Validate()
	}

	// Read token length
	n2, err := io.ReadFull(src, hdr[2:4])
	n += n2
	if err != nil {
		return int64(n), err
	}

	length := binary.BigEndian.Uint16(hdr[2:4])

	// Zero-length token is valid (final step)
	if length == 0 {
		r.Token = nil
		return int64(n), r.Validate()
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

	// Abort message: only VER + MTYP
	if r.MsgType == GSSAPITypeAbort {
		buf := [2]byte{r.Version, r.MsgType}
		n, err := dst.Write(buf[:])
		return int64(n), err
	}

	tokenLen := len(r.Token)

	var bufArr [512]byte
	buf := bufArr[:0]

	totalLen := 4 + tokenLen
	if totalLen > cap(bufArr) {
		buf = make([]byte, 0, totalLen)
	}

	buf = append(buf,
		r.Version,
		r.MsgType,
		byte(tokenLen>>8),
		byte(tokenLen),
	)
	buf = append(buf, r.Token...)

	n, err := dst.Write(buf)
	return int64(n), err
}

// String returns a human-readable representation.
func (r *GSSAPIReply) String() string {
	return fmt.Sprintf(
		"GSSAPIReply{Version=%d, MsgType=0x%02x, TokenLen=%d}",
		r.Version, r.MsgType, len(r.Token),
	)
}
