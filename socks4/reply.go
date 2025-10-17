package socks4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// SOCKS4 reply error codes and helpers.
var (
	ErrInvalidReplyVersion = errors.New("invalid SOCKS4 reply version (must be 0x00)")
	ErrInvalidReplyCode    = errors.New("invalid SOCKS4 reply code")
)

// Reply represents a SOCKS4 or SOCKS4a CONNECT/BIND server reply.
type Reply struct {
	Version byte    // VN; always 0x00 per SOCKS4 spec
	Code    byte    // CD; reply code (0x5A = granted, 0x5B–0x5D = failure)
	Port    uint16  // DSTPORT; server-assigned or echoed port
	IP      [4]byte // DSTIP; server-assigned or echoed address
}

// Init initializes a SOCKS4 reply.
func (r *Reply) Init(version, code byte, port uint16, ip net.IP) {
	r.Version = version
	r.Code = code
	r.Port = port
	copy(r.IP[:], ip.To4())
}

// Validate checks the correctness of the SOCKS4 reply fields.
func (r *Reply) Validate() error {
	if r.Version != 0x00 {
		return ErrInvalidReplyVersion
	}
	switch r.Code {
	case RepGranted, RepRejected, RepIdentFailed, RepUserIDMismatch:
		return nil
	default:
		return ErrInvalidReplyCode
	}
}

// IsGranted reports whether the reply indicates success.
func (r *Reply) IsGranted() bool {
	return r.Code == RepGranted
}

// GetIP returns the IPv4 address as net.IP.
func (r *Reply) GetIP() net.IP {
	return net.IP(r.IP[:]).To4()
}

// ReadFrom reads a SOCKS4 reply from an io.Reader.
// Implements io.ReaderFrom.
func (r *Reply) ReadFrom(src io.Reader) (int64, error) {
	var hdr [8]byte
	n, err := io.ReadFull(src, hdr[:])
	if err != nil {
		return int64(n), err
	}
	r.Version = hdr[0]
	r.Code = hdr[1]
	r.Port = binary.BigEndian.Uint16(hdr[2:4])
	copy(r.IP[:], hdr[4:8])
	return int64(n), r.Validate()
}

// WriteTo writes a SOCKS4 reply to an io.Writer.
// Implements io.WriterTo.
func (r *Reply) WriteTo(dst io.Writer) (int64, error) {
	var hdr [8]byte
	hdr[0] = r.Version
	hdr[1] = r.Code
	binary.BigEndian.PutUint16(hdr[2:4], r.Port)
	copy(hdr[4:8], r.IP[:])
	n, err := dst.Write(hdr[:])
	return int64(n), err
}

// String returns a string representation of the SOCKS4 reply.
func (r *Reply) String() string {
	var desc string
	switch r.Code {
	case RepGranted:
		desc = "granted"
	case RepRejected:
		desc = "rejected"
	case RepIdentFailed:
		desc = "identd failed"
	case RepUserIDMismatch:
		desc = "userid mismatch"
	default:
		desc = fmt.Sprintf("unknown(0x%02x)", r.Code)
	}
	return fmt.Sprintf("SOCKS4 reply{Version:%d Code:%s Port:%d IP:%s}", r.Version, desc, r.Port, net.IP(r.IP[:]).String())
}
