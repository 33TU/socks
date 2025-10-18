package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Common validation errors.
var (
	ErrInvalidVersion = errors.New("invalid SOCKS version (must be 5)")
	ErrInvalidCommand = errors.New("invalid command (must be 1=CONNECT, 2=BIND, 3=UDP ASSOCIATE, F0=RESOLVE, or F1=RESOLVE_PTR)")
	ErrInvalidAddr    = errors.New("invalid address or address type")
	ErrInvalidDomain  = errors.New("invalid domain (empty or too long)")
	ErrInvalidRSV     = errors.New("invalid reserved byte (must be 0x00)")
)

// Request represents a SOCKS5 CONNECT/BIND/UDP ASSOCIATE/RESOLVE request.
type Request struct {
	Version  byte   // VER; SOCKS protocol version (always 5)
	Command  byte   // CMD; CONNECT, BIND, UDP ASSOCIATE, RESOLVE, etc.
	Reserved byte   // RSV; reserved byte (must be 0x00)
	AddrType byte   // ATYP; address type (IPv4, DOMAIN, IPv6)
	IP       net.IP // BND.ADDR; Destination IP (IPv4 or IPv6)
	Domain   string // BND.ADDR; Destination domain (if ATYP=DOMAIN)
	Port     uint16 // BND.PORT; Destination port (big-endian)
}

// GetHost returns the destination hostname or IP string.
func (r *Request) GetHost() string {
	if r.AddrType == AddrTypeDomain {
		return r.Domain
	}
	return r.IP.String()
}

// Addr returns the full "host:port" string form.
func (r *Request) Addr() string {
	return net.JoinHostPort(r.GetHost(), fmt.Sprint(r.Port))
}

// Init initializes a SOCKS5 request.
func (r *Request) Init(
	version byte,
	command byte,
	reserved byte,
	addrType byte,
	ip net.IP,
	domain string,
	port uint16,
) {
	r.Version = version
	r.Command = command
	r.Reserved = reserved
	r.AddrType = addrType
	r.IP = ip
	r.Domain = domain
	r.Port = port
}

// ValidateHeader validates the SOCKS5 request header.
func (r *Request) ValidateHeader() error {
	if r.Version != SocksVersion {
		return ErrInvalidVersion
	}
	if r.Reserved != 0x00 {
		return ErrInvalidRSV
	}
	switch r.Command {
	case CmdConnect, CmdBind, CmdUDPAssociate, CmdResolve, CmdResolvePTR:
	default:
		return ErrInvalidCommand
	}
	switch r.AddrType {
	case AddrTypeIPv4, AddrTypeDomain, AddrTypeIPv6:
	default:
		return ErrInvalidAddr
	}
	return nil
}

// Validate validates the full SOCKS5 request.
func (r *Request) Validate() error {
	if err := r.ValidateHeader(); err != nil {
		return err
	}

	switch r.AddrType {
	case AddrTypeDomain:
		if len(r.Domain) == 0 || len(r.Domain) > 255 {
			return ErrInvalidDomain
		}
		return nil // domain is valid, IP may be nil
	case AddrTypeIPv4, AddrTypeIPv6:
		if r.IP == nil {
			return ErrInvalidAddr
		}
	}
	return nil
}

// ReadFrom reads a SOCKS5 request from a Reader.
// Implements the io.ReaderFrom interface.
func (r *Request) ReadFrom(src io.Reader) (int64, error) {
	var (
		total int64
		hdr   [4]byte
	)

	n, err := io.ReadFull(src, hdr[:])
	total += int64(n)
	if err != nil {
		return total, err
	}

	r.Version = hdr[0]
	r.Command = hdr[1]
	r.Reserved = hdr[2]
	r.AddrType = hdr[3]

	if err := r.ValidateHeader(); err != nil {
		return total, err
	}

	switch r.AddrType {
	case AddrTypeIPv4:
		var buf [4]byte
		n, err = io.ReadFull(src, buf[:])
		total += int64(n)
		if err != nil {
			return total, err
		}
		r.IP = net.IP(buf[:])

	case AddrTypeIPv6:
		var buf [16]byte
		n, err = io.ReadFull(src, buf[:])
		total += int64(n)
		if err != nil {
			return total, err
		}
		r.IP = net.IP(buf[:])

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

// WriteTo writes a SOCKS5 request to a Writer.
// Implements the io.WriterTo interface.
// Note: returns error if domain is too long.
func (r *Request) WriteTo(dst io.Writer) (int64, error) {
	if r.AddrType == AddrTypeDomain {
		domainLen := len(r.Domain)
		if domainLen == 0 || domainLen > 255 {
			return 0, ErrInvalidReplyDomain
		}
	}

	var total int64
	hdr := [4]byte{r.Version, r.Command, r.Reserved, r.AddrType}

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

// String returns a string representation of the SOCKS5 Request.
func (r *Request) String() string {
	var cmd string
	switch r.Command {
	case CmdConnect:
		cmd = "CONNECT"
	case CmdBind:
		cmd = "BIND"
	case CmdUDPAssociate:
		cmd = "UDP_ASSOCIATE"
	case CmdResolve:
		cmd = "RESOLVE"
	case CmdResolvePTR:
		cmd = "RESOLVE_PTR"
	default:
		cmd = fmt.Sprintf("UNKNOWN(0x%02X)", r.Command)
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
		"SOCKS5 Request{Cmd=%s, AddrType=%s, Host=%s, Port=%d, Version=%d, RSV=%#02x}",
		cmd, atype, r.GetHost(), r.Port, r.Version, r.Reserved,
	)
}
