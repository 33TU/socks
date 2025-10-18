package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Common validation errors for replies.
var (
	ErrInvalidReplyVersion = errors.New("invalid SOCKS version in reply (must be 5)")
	ErrInvalidReplyRSV     = errors.New("invalid reserved byte in reply (must be 0x00)")
	ErrInvalidReplyAddr    = errors.New("invalid address or address type in reply")
	ErrInvalidReplyDomain  = errors.New("invalid domain in reply (empty or too long)")
)

// Reply represents a SOCKS5 server reply.
type Reply struct {
	Version  byte   // VER; SOCKS protocol version (always 5)
	Reply    byte   // REP; reply code
	Reserved byte   // RSV; must be 0x00
	AddrType byte   // ATYP; address type (IPv4, DOMAIN, IPv6)
	IP       net.IP // BND.ADDR; Bound IP (if IPv4/IPv6)
	Domain   string // BND.ADDR; Bound domain (if ATYP=DOMAIN)
	Port     uint16 // BND.PORT; Bound port
}

// Init initializes a SOCKS5 reply.
func (r *Reply) Init(version, rep, reserved, addrType byte, ip net.IP, domain string, port uint16) {
	r.Version = version
	r.Reply = rep
	r.Reserved = reserved
	r.AddrType = addrType
	r.IP = ip
	r.Domain = domain
	r.Port = port
}

// GetHost returns the bound host (domain or IP string).
func (r *Reply) GetHost() string {
	if r.AddrType == AddrTypeDomain {
		return r.Domain
	}
	return r.IP.String()
}

// Addr returns a combined "host:port" string.
func (r *Reply) Addr() string {
	return net.JoinHostPort(r.GetHost(), fmt.Sprint(r.Port))
}

// ValidateHeader validates the reply header fields.
func (r *Reply) ValidateHeader() error {
	if r.Version != SocksVersion {
		return ErrInvalidReplyVersion
	}
	if r.Reserved != 0x00 {
		return ErrInvalidReplyRSV
	}
	switch r.AddrType {
	case AddrTypeIPv4, AddrTypeDomain, AddrTypeIPv6:
	default:
		return ErrInvalidReplyAddr
	}
	return nil
}

// Validate validates the full reply.
func (r *Reply) Validate() error {
	if err := r.ValidateHeader(); err != nil {
		return err
	}
	switch r.AddrType {
	case AddrTypeDomain:
		if len(r.Domain) == 0 || len(r.Domain) > 255 {
			return ErrInvalidReplyDomain
		}
	case AddrTypeIPv4, AddrTypeIPv6:
		if r.IP == nil {
			return ErrInvalidReplyAddr
		}
	}
	return nil
}

// ReadFrom reads a SOCKS5 reply from a Reader.
// Implements io.ReaderFrom.
func (r *Reply) ReadFrom(src io.Reader) (int64, error) {
	var (
		hdr   [4]byte
		total int64
	)

	n, err := io.ReadFull(src, hdr[:])
	total += int64(n)
	if err != nil {
		return total, err
	}

	r.Version = hdr[0]
	r.Reply = hdr[1]
	r.Reserved = hdr[2]
	r.AddrType = hdr[3]

	if err := r.ValidateHeader(); err != nil {
		return total, err
	}

	switch r.AddrType {
	case AddrTypeIPv4:
		var ip [4]byte
		n, err = io.ReadFull(src, ip[:])
		total += int64(n)
		if err != nil {
			return total, err
		}
		r.IP = net.IP(ip[:])

	case AddrTypeIPv6:
		var ip [16]byte
		n, err = io.ReadFull(src, ip[:])
		total += int64(n)
		if err != nil {
			return total, err
		}
		r.IP = net.IP(ip[:])

	case AddrTypeDomain:
		var ln [1]byte
		n, err = io.ReadFull(src, ln[:])
		total += int64(n)
		if err != nil {
			return total, err
		}
		buf := make([]byte, ln[0])
		n, err = io.ReadFull(src, buf)
		total += int64(n)
		if err != nil {
			return total, err
		}
		r.Domain = string(buf)
	}

	var portBuf [2]byte
	n, err = io.ReadFull(src, portBuf[:])
	total += int64(n)
	if err != nil {
		return total, err
	}
	r.Port = binary.BigEndian.Uint16(portBuf[:])

	return total, r.Validate()
}

// WriteTo writes a SOCKS5 reply to a Writer.
// Implements io.WriterTo.
func (r *Reply) WriteTo(dst io.Writer) (int64, error) {
	if err := r.Validate(); err != nil {
		return 0, err
	}

	hdr := [4]byte{r.Version, r.Reply, r.Reserved, r.AddrType}
	total := int64(0)

	n, err := dst.Write(hdr[:])
	total += int64(n)
	if err != nil {
		return total, err
	}

	switch r.AddrType {
	case AddrTypeIPv4:
		n, err = dst.Write(r.IP.To4())
	case AddrTypeIPv6:
		n, err = dst.Write(r.IP.To16())
	case AddrTypeDomain:
		n, err = dst.Write([]byte{byte(len(r.Domain))})
		total += int64(n)
		if err == nil {
			n, err = io.WriteString(dst, r.Domain)
		}
	}
	total += int64(n)
	if err != nil {
		return total, err
	}

	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], r.Port)
	n, err = dst.Write(portBuf[:])
	total += int64(n)

	return total, err
}

// String returns a human-readable representation of the reply.
func (r *Reply) String() string {
	var rep string
	switch r.Reply {
	case RepSuccess:
		rep = "SUCCESS"
	case RepGeneralFailure:
		rep = "GENERAL_FAILURE"
	case RepConnectionNotAllowed:
		rep = "CONNECTION_NOT_ALLOWED"
	case RepNetworkUnreachable:
		rep = "NETWORK_UNREACHABLE"
	case RepHostUnreachable:
		rep = "HOST_UNREACHABLE"
	case RepConnectionRefused:
		rep = "CONNECTION_REFUSED"
	case RepTTLExpired:
		rep = "TTL_EXPIRED"
	case RepCommandNotSupported:
		rep = "COMMAND_NOT_SUPPORTED"
	case RepAddrTypeNotSupported:
		rep = "ADDR_TYPE_NOT_SUPPORTED"
	default:
		rep = fmt.Sprintf("UNKNOWN(0x%02X)", r.Reply)
	}

	var atype string
	switch r.AddrType {
	case AddrTypeIPv4:
		atype = "IPv4"
	case AddrTypeDomain:
		atype = "DOMAIN"
	case AddrTypeIPv6:
		atype = "IPv6"
	default:
		atype = fmt.Sprintf("0x%02X", r.AddrType)
	}

	return fmt.Sprintf(
		"SOCKS5 Reply{Reply=%s, AddrType=%s, Host=%s, Port=%d, Version=%d, RSV=%#02x}",
		rep, atype, r.GetHost(), r.Port, r.Version, r.Reserved,
	)
}
