package socks4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/33TU/socks/internal"
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

// GetIP returns the destination IPv4 address.
func (r *Request) GetIP() net.IP {
	return net.IP(r.IP[:]).To4()
}

// GetHost returns the destination host.
func (r *Request) GetHost() string {
	if r.IsSOCKS4a() {
		return r.Domain
	}
	return r.GetIP().String()
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

// ReadHeaderFrom reads a 8-byte SOCKS4 or SOCKS4a CONNECT/BIND request from a Reader.
func (r *Request) ReadHeaderFrom(src io.Reader) (int64, error) {
	var hdr [8]byte

	n, err := io.ReadFull(src, hdr[:])
	if err != nil {
		return int64(n), err
	}

	r.Version = hdr[0]
	r.Command = hdr[1]
	r.Port = binary.BigEndian.Uint16(hdr[2:4])
	copy(r.IP[:], hdr[4:8])
	return int64(n), r.ValidateHeader()
}

// ReadUserIDAndDomain reads a 8-byte SOCKS4 or SOCKS4a CONNECT/BIND request from a Reader.
// Note that the limits do not include the null-terminator.
// Beware if there is data beyond request it can be dropped.
func (r *Request) ReadUserIDAndDomain(src io.Reader, maxUserIDLen, maxDomainLen int64) (int64, error) {
	var lr internal.LimitedReader
	rdr := internal.GetReader(&lr)
	defer internal.PutReader(rdr)

	// total number of bytes read
	var total int64

	// read USERID
	lr.Init(src, maxUserIDLen+1)
	userID, err := rdr.ReadString(0x00)
	total += int64(len(userID))
	if err != nil {
		return total, err
	}
	r.UserID = userID[:len(userID)-1]

	// read DOMAIN
	if r.IsSOCKS4a() {
		lr.Init(src, maxDomainLen+1)
		domain, err := rdr.ReadString(0x00)
		total += int64(len(domain))
		if err != nil {
			return total, err
		}
		r.Domain = domain[:len(domain)-1]
	}

	return total, nil
}

// ReadFromWithLimits reads a 8-byte SOCKS4 or SOCKS4a CONNECT/BIND request from a Reader.
// Note that the limits do not include the null-terminator.
func (r *Request) ReadFromWithLimits(src io.Reader, maxUserIDLen, maxDomainLen int64) (int64, error) {
	n1, err := r.ReadHeaderFrom(src)
	if err != nil {
		return n1, err
	}

	n2, err := r.ReadUserIDAndDomain(src, maxUserIDLen, maxDomainLen)
	return n1 + n2, err
}

// ReadFrom reads a SOCKS4 or SOCKS4a CONNECT/BIND request from a Reader.
// Implements the io.ReaderFrom interface.
func (r *Request) ReadFrom(src io.Reader) (int64, error) {
	return r.ReadFromWithLimits(src, DefaultMaxUserIDLen, DefaultMaxDomainLen)
}

// WriteTo writes a SOCKS4 or SOCKS4a CONNECT/BIND request to a Writer.
// Implements the io.WriterTo interface.
func (r *Request) WriteTo(dst io.Writer) (int64, error) {
	var (
		hdr   [8]byte
		total int64
	)

	// write header
	hdr[0] = r.Version
	hdr[1] = r.Command
	binary.BigEndian.PutUint16(hdr[2:4], r.Port)
	copy(hdr[4:8], r.IP[:])

	n, err := dst.Write(hdr[:])
	total += int64(n)
	if err != nil {
		return total, err
	}

	// write USERID
	ns, err := writeCString(dst, r.UserID)
	total += ns
	if err != nil {
		return total, err
	}

	// write DOMAIN
	if r.IsSOCKS4a() {
		ns, err := writeCString(dst, r.Domain)
		total += ns
		if err != nil {
			return total, err
		}
	}

	return total, nil
}

func writeCString(dst io.Writer, s string) (int64, error) {
	var (
		total int64
		null  = [1]byte{0}
	)

	if len(s) != 0 {
		n, err := io.WriteString(dst, s)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}

	n, err := dst.Write(null[:])
	total += int64(n)
	return total, err
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
		cmd, r.GetIP(), r.Port, r.UserID, r.Version,
	)
}
