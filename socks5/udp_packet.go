package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Common validation errors for UDP packets.
var (
	ErrInvalidUDPReserved = errors.New("invalid UDP reserved bytes (must be 0x0000)")
	ErrUnsupportedFrag    = errors.New("unsupported UDP fragmentation (FRAG must be 0x00)")
	ErrInvalidUDPAddrType = errors.New("invalid UDP address type")
	ErrInvalidUDPDomain   = errors.New("invalid UDP domain (empty or too long)")
	ErrMissingUDPData     = errors.New("missing UDP payload data")
)

// UDPPacket represents a SOCKS5 UDP ASSOCIATE packet.
type UDPPacket struct {
	Reserved [2]byte // RSV; must be 0x0000
	Frag     byte    // FRAG; must be 0x00 (no fragmentation)
	AddrType byte    // ATYP; IPv4, DOMAIN, or IPv6
	IP       net.IP  // Destination IP (if ATYP=IPv4 or IPv6)
	Domain   string  // Destination domain (if ATYP=DOMAIN)
	Port     uint16  // Destination port
	Data     []byte  // UDP payload data
}

// Init initializes a UDPPacket with given values.
func (p *UDPPacket) Init(
	reserved [2]byte,
	frag byte,
	addrType byte,
	ip net.IP,
	domain string,
	port uint16,
	data []byte,
) {
	p.Reserved = reserved
	p.Frag = frag
	p.AddrType = addrType
	p.IP = ip
	p.Domain = domain
	p.Port = port
	p.Data = data
}

// Validate checks for protocol correctness.
func (p *UDPPacket) Validate() error {
	if p.Reserved != [2]byte{0x00, 0x00} {
		return ErrInvalidUDPReserved
	}
	if p.Frag != 0x00 {
		return ErrUnsupportedFrag
	}

	switch p.AddrType {
	case AddrTypeIPv4, AddrTypeIPv6:
		if p.IP == nil {
			return ErrInvalidUDPAddrType
		}
	case AddrTypeDomain:
		if len(p.Domain) == 0 || len(p.Domain) > 255 {
			return ErrInvalidUDPDomain
		}
	default:
		return ErrInvalidUDPAddrType
	}

	if len(p.Data) == 0 {
		return ErrMissingUDPData
	}

	return nil
}

// UnmarshalFrom parses a SOCKS5 UDP packet from raw bytes.
func (p *UDPPacket) UnmarshalFrom(b []byte) (int, error) {
	if len(b) < 4 {
		return 0, io.ErrUnexpectedEOF
	}

	// Header
	copy(p.Reserved[:], b[0:2])
	p.Frag = b[2]
	p.AddrType = b[3]

	if err := p.ValidateHeader(); err != nil {
		return 0, err
	}

	i := 4

	// Address
	switch p.AddrType {
	case AddrTypeIPv4:
		if len(b) < i+4 {
			return 0, io.ErrUnexpectedEOF
		}
		p.IP = net.IP(b[i : i+4])
		i += 4

	case AddrTypeIPv6:
		if len(b) < i+16 {
			return 0, io.ErrUnexpectedEOF
		}
		p.IP = net.IP(b[i : i+16])
		i += 16

	case AddrTypeDomain:
		if len(b) < i+1 {
			return 0, io.ErrUnexpectedEOF
		}
		dlen := int(b[i])
		i++

		if dlen == 0 || len(b) < i+dlen {
			return 0, ErrInvalidUDPDomain
		}

		p.Domain = string(b[i : i+dlen])
		i += dlen
	}

	// Port
	if len(b) < i+2 {
		return 0, io.ErrUnexpectedEOF
	}
	p.Port = binary.BigEndian.Uint16(b[i : i+2])
	i += 2

	// Data (zero-copy slice)
	if len(b) <= i {
		return 0, ErrMissingUDPData
	}
	p.Data = b[i:]

	return len(b), p.Validate()
}

// MarshalTo writes the packet into b and returns bytes written.
func (p *UDPPacket) MarshalTo(b []byte) (int, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}

	i := 0

	// Header
	if len(b) < 4 {
		return 0, io.ErrShortBuffer
	}
	b[0] = p.Reserved[0]
	b[1] = p.Reserved[1]
	b[2] = p.Frag
	b[3] = p.AddrType
	i += 4

	// Address
	switch p.AddrType {
	case AddrTypeIPv4:
		ip := p.IP.To4()
		if ip == nil || len(b) < i+4 {
			return 0, io.ErrShortBuffer
		}
		copy(b[i:], ip)
		i += 4

	case AddrTypeIPv6:
		ip := p.IP.To16()
		if ip == nil || len(b) < i+16 {
			return 0, io.ErrShortBuffer
		}
		copy(b[i:], ip)
		i += 16

	case AddrTypeDomain:
		dlen := len(p.Domain)
		if len(b) < i+1+dlen {
			return 0, io.ErrShortBuffer
		}
		b[i] = byte(dlen)
		i++
		copy(b[i:], p.Domain)
		i += dlen
	}

	// Port
	if len(b) < i+2 {
		return 0, io.ErrShortBuffer
	}
	binary.BigEndian.PutUint16(b[i:], p.Port)
	i += 2

	// Data
	if len(b) < i+len(p.Data) {
		return 0, io.ErrShortBuffer
	}
	copy(b[i:], p.Data)
	i += len(p.Data)

	return i, nil
}

// ValidateHeader checks RSV/FRAG/ATYP fields before full read.
func (p *UDPPacket) ValidateHeader() error {
	if p.Reserved != [2]byte{0x00, 0x00} {
		return ErrInvalidUDPReserved
	}
	if p.Frag != 0x00 {
		return ErrUnsupportedFrag
	}
	switch p.AddrType {
	case AddrTypeIPv4, AddrTypeIPv6, AddrTypeDomain:
	default:
		return ErrInvalidUDPAddrType
	}
	return nil
}

// String returns a human-readable representation.
func (p *UDPPacket) String() string {
	var atype string
	switch p.AddrType {
	case AddrTypeIPv4:
		atype = "IPv4"
	case AddrTypeDomain:
		atype = "DOMAIN"
	case AddrTypeIPv6:
		atype = "IPv6"
	default:
		atype = fmt.Sprintf("0x%02X", p.AddrType)
	}

	return fmt.Sprintf(
		"UDPPacket{AddrType=%s, Host=%s, Port=%d, DataLen=%d, Frag=%d, RSV=%#02x%#02x}",
		atype, p.hostString(), p.Port, len(p.Data), p.Frag, p.Reserved[0], p.Reserved[1],
	)
}

// hostString returns the effective destination host string.
func (p *UDPPacket) hostString() string {
	if p.AddrType == AddrTypeDomain {
		return p.Domain
	}
	return p.IP.String()
}

func (p *UDPPacket) Size() int {
	size := 4 // RSV + FRAG + ATYP

	switch p.AddrType {
	case AddrTypeIPv4:
		size += 4
	case AddrTypeIPv6:
		size += 16
	case AddrTypeDomain:
		size += 1 + len(p.Domain)
	}

	size += 2 // PORT
	size += len(p.Data)

	return size
}
