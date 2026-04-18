package socks4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

var (
	ErrInvalidVersion = errors.New("invalid SOCKS version (must be 4)")
	ErrInvalidCommand = errors.New("invalid command (must be 1=CONNECT or 2=BIND)")
	ErrInvalidIP      = errors.New("invalid IP (must be IPv4)")
	ErrInvalidDomain  = errors.New("invalid SOCKS4a domain usage")
)

// Request represents a SOCKS4 or SOCKS4a CONNECT/BIND request.
type Request struct {
	Version byte    // VN; SOCKS protocol version (should always be 4)
	Command byte    // CD; command code (1 = CONNECT, 2 = BIND)
	Port    uint16  // DSTPORT; destination port (big-endian)
	IP      [4]byte // DSTIP; destination IPv4 address, or 0.0.0.x for SOCKS4a
	UserID  string  // USERID; null-terminated user identifier
	Domain  string  // DOMAIN; null-terminated domain name (SOCKS4a only)
}

// IsSOCKS4a returns true if the request is a SOCKS4a request.
func (r *Request) IsSOCKS4a() bool {
	ip := net.IP(r.IP[:])
	return ip != nil &&
		ip[0] == 0 &&
		ip[1] == 0 &&
		ip[2] == 0 &&
		ip[3] != 0
}

// IsSOCKS4 returns true if the request is a SOCKS4 request.
func (r *Request) IsSOCKS4() bool {
	ip := net.IP(r.IP[:])
	return ip != nil &&
		!(ip[0] == 0 &&
			ip[1] == 0 &&
			ip[2] == 0 &&
			ip[3] != 0)
}

// IPv4 returns the destination IPv4 address.
func (r *Request) IPv4() net.IP {
	return net.IP(r.IP[:]).To4()
}

// Host returns the destination host.
func (r *Request) Host() string {
	if r.IsSOCKS4a() {
		return r.Domain
	}
	return r.IPv4().String()
}

// Addr returns the destination address in "host:port" format.
func (r *Request) Addr() string {
	return net.JoinHostPort(r.Host(), fmt.Sprintf("%d", r.Port))
}

// Init initializes a SOCKS4 or SOCKS4a CONNECT/BIND request.
func (r *Request) Init(
	version byte,
	command byte,
	port uint16,
	ip net.IP,
	userID string,
	domain string,
) {
	r.Version = version
	r.Command = command
	r.Port = port
	copy(r.IP[:], ip.To4())
	r.UserID = userID
	r.Domain = domain
}

// ValidateHeader validates a SOCKS4 or SOCKS4a CONNECT/BIND request header (first 8 bytes).
func (r *Request) ValidateHeader() error {
	if r.Version != SocksVersion {
		return ErrInvalidVersion
	}
	if r.Command != CmdConnect && r.Command != CmdBind {
		return ErrInvalidCommand
	}

	ip := net.IP(r.IP[:]).To4()
	if ip == nil {
		return ErrInvalidIP
	}

	// 0.0.0.0 is invalid for CONNECT, valid for BIND
	if ip.Equal(net.IPv4zero) && r.Command == CmdConnect {
		return ErrInvalidIP
	}

	return nil
}

// Validate validates a SOCKS4 or SOCKS4a CONNECT/BIND request (SOCKS4a only).
func (r *Request) ValidateDomain() error {
	if r.IsSOCKS4a() {
		if len(r.Domain) == 0 {
			return ErrInvalidDomain
		}
	} else {
		if len(r.Domain) > 0 {
			return ErrInvalidDomain
		}
	}
	return nil
}

// Validate validates a SOCKS4 or SOCKS4a CONNECT/BIND request.
func (r *Request) Validate() error {
	if err := r.ValidateHeader(); err != nil {
		return err
	}
	return r.ValidateDomain()
}

// ReadFromWithLimits reads a 8-byte SOCKS4 or SOCKS4a CONNECT/BIND request from a Reader.
func (r *Request) ReadFromWithLimits(src io.Reader, maxUserIDLen, maxDomainLen int64) (int64, error) {
	var (
		total   int64
		hdr     [8]byte
		scratch [512]byte
	)

	// HEADER
	n, err := io.ReadFull(src, hdr[:])
	total += int64(n)
	if err != nil {
		return total, err
	}

	r.Version = hdr[0]
	r.Command = hdr[1]
	r.Port = binary.BigEndian.Uint16(hdr[2:4])
	copy(r.IP[:], hdr[4:8])

	if err := r.ValidateHeader(); err != nil {
		return total, err
	}

	// USERID
	userID, n, err := readCString(src, scratch[:], maxUserIDLen)
	total += int64(n)
	if err != nil {
		return total, fmt.Errorf("failed to read USERID: %w", err)
	}
	r.UserID = userID

	// DOMAIN (SOCKS4a only)
	if r.IsSOCKS4a() {
		domain, n, err := readCString(src, scratch[:], maxDomainLen)
		total += int64(n)
		if err != nil {
			return total, fmt.Errorf("failed to read DOMAIN: %w", err)
		}
		r.Domain = domain
	}

	return total, r.ValidateDomain()
}

// ReadFrom reads a SOCKS4 or SOCKS4a CONNECT/BIND request from a Reader.
// Implements the io.ReaderFrom interface.
func (r *Request) ReadFrom(src io.Reader) (int64, error) {
	return r.ReadFromWithLimits(src, DefaultMaxUserIDLen, DefaultMaxDomainLen)
}

// WriteTo writes a SOCKS4 or SOCKS4a CONNECT/BIND request to a Writer.
// Implements the io.WriterTo interface.
func (r *Request) WriteTo(dst io.Writer) (int64, error) {
	var bufArr [512]byte // safe upper bound
	buf := bufArr[:0]

	// Header (8 bytes)
	buf = append(buf,
		r.Version,
		r.Command,
		byte(r.Port>>8),
		byte(r.Port),
	)
	buf = append(buf, r.IP[:]...)

	// USERID (cstring)
	if len(r.UserID) > 0 {
		buf = append(buf, r.UserID...)
	}
	buf = append(buf, 0)

	// DOMAIN (SOCKS4a only)
	if r.IsSOCKS4a() {
		if len(r.Domain) > 0 {
			buf = append(buf, r.Domain...)
		}
		buf = append(buf, 0)
	}

	// Single write
	n, err := dst.Write(buf)
	return int64(n), err
}

// String returns a string representation of the SOCKS4(a) Request.
func (r *Request) String() string {
	var cmd string
	switch r.Command {
	case CmdConnect:
		cmd = "CONNECT"
	case CmdBind:
		cmd = "BIND"
	default:
		cmd = fmt.Sprintf("UNKNOWN(0x%02x)", r.Command)
	}

	if r.IsSOCKS4a() {
		return fmt.Sprintf(
			"SOCKS4a Request{Cmd=%s, Host=%s, Port=%d, UserID=%q, Version=%d}",
			cmd, r.Domain, r.Port, r.UserID, r.Version,
		)
	}

	return fmt.Sprintf(
		"SOCKS4 Request{Cmd=%s, IP=%s, Port=%d, UserID=%q, Version=%d}",
		cmd, r.IPv4(), r.Port, r.UserID, r.Version,
	)
}

// readCString reads a null-terminated string from src (excluding the null terminator).
func readCString(src io.Reader, scratch []byte, limit int64) (string, int, error) {
	if limit < 0 {
		return "", 0, fmt.Errorf("invalid limit")
	}

	var (
		total int
		one   [1]byte
		buf   = scratch[:0]
	)

	for range limit + 1 { // +1 to allow the terminating NUL
		nn, err := src.Read(one[:])

		if nn > 0 {
			total += nn

			if one[0] == 0 {
				return string(buf), total, nil
			}

			buf = append(buf, one[0])
		}

		if err != nil {
			return "", total, err
		}
	}

	return "", total, fmt.Errorf("string exceeds maximum length of %d", limit)
}
