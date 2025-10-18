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

// ReadFrom reads a UDP ASSOCIATE packet from a Reader.
// Implements io.ReaderFrom.
func (p *UDPPacket) ReadFrom(src io.Reader) (int64, error) {
	var total int64

	// Read RSV + FRAG + ATYP
	var hdr [4]byte
	n, err := io.ReadFull(src, hdr[:])
	total += int64(n)
	if err != nil {
		return total, err
	}

	copy(p.Reserved[:], hdr[0:2])
	p.Frag = hdr[2]
	p.AddrType = hdr[3]

	if err := p.ValidateHeader(); err != nil {
		return total, err
	}

	// Read DST.ADDR
	switch p.AddrType {
	case AddrTypeIPv4:
		var ip [4]byte
		n, err = io.ReadFull(src, ip[:])
		total += int64(n)
		if err != nil {
			return total, err
		}
		p.IP = net.IP(ip[:])

	case AddrTypeIPv6:
		var ip [16]byte
		n, err = io.ReadFull(src, ip[:])
		total += int64(n)
		if err != nil {
			return total, err
		}
		p.IP = net.IP(ip[:])

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
		p.Domain = string(buf)
	}

	// Read DST.PORT
	var portBuf [2]byte
	n, err = io.ReadFull(src, portBuf[:])
	total += int64(n)
	if err != nil {
		return total, err
	}
	p.Port = binary.BigEndian.Uint16(portBuf[:])

	// Remaining bytes are DATA
	data, err := io.ReadAll(src)
	total += int64(len(data))
	if err != nil {
		return total, err
	}
	p.Data = data

	return total, p.Validate()
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

// WriteTo writes a UDP ASSOCIATE packet to a Writer.
// Implements io.WriterTo.
func (p *UDPPacket) WriteTo(dst io.Writer) (int64, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}

	var total int64

	// Write RSV + FRAG + ATYP
	hdr := [4]byte{p.Reserved[0], p.Reserved[1], p.Frag, p.AddrType}
	n, err := dst.Write(hdr[:])
	total += int64(n)
	if err != nil {
		return total, err
	}

	switch p.AddrType {
	case AddrTypeIPv4:
		n, err = dst.Write(p.IP.To4())
	case AddrTypeIPv6:
		n, err = dst.Write(p.IP.To16())
	case AddrTypeDomain:
		dlen := len(p.Domain)
		n, err = dst.Write([]byte{byte(dlen)})
		total += int64(n)
		if err == nil {
			n, err = io.WriteString(dst, p.Domain)
		}
	}
	total += int64(n)
	if err != nil {
		return total, err
	}

	// Write DST.PORT
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], p.Port)
	n, err = dst.Write(portBuf[:])
	total += int64(n)
	if err != nil {
		return total, err
	}

	// Write DATA
	n, err = dst.Write(p.Data)
	total += int64(n)
	return total, err
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
