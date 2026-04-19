package shadowsocks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Common validation and decode/encode errors for Shadowsocks addresses.
var (
	ErrInvalidAddrType = errors.New("invalid address type")
	ErrInvalidAddr     = errors.New("invalid address")
	ErrInvalidDomain   = errors.New("invalid domain")
	ErrShortAddr       = errors.New("short address")
	ErrShortAddrBuffer = errors.New("short address buffer")
)

// Addr represents a SOCKS5-style address field used by Shadowsocks.
type Addr struct {
	AddrType byte
	IP       net.IP
	Domain   string
	Port     uint16
}

// Init initializes an Addr.
func (a *Addr) Init(addrType byte, ip net.IP, domain string, port uint16) {
	a.AddrType = addrType
	a.IP = ip
	a.Domain = domain
	a.Port = port
}

// GetHost returns the address host as either the domain or IP string.
func (a *Addr) GetHost() string {
	if a.AddrType == AddrTypeDomain {
		return a.Domain
	}
	if a.IP == nil {
		return ""
	}
	return a.IP.String()
}

// Addr returns the address as a combined host:port string.
func (a *Addr) Addr() string {
	return net.JoinHostPort(a.GetHost(), fmt.Sprint(a.Port))
}

// Validate checks the correctness of the address fields.
func (a *Addr) Validate() error {
	switch a.AddrType {
	case AddrTypeIPv4:
		if a.IP == nil || a.IP.To4() == nil {
			return ErrInvalidAddr
		}
	case AddrTypeIPv6:
		if a.IP == nil || a.IP.To16() == nil || a.IP.To4() != nil {
			return ErrInvalidAddr
		}
	case AddrTypeDomain:
		if len(a.Domain) == 0 || len(a.Domain) > 255 {
			return ErrInvalidDomain
		}
	default:
		return ErrInvalidAddrType
	}

	return nil
}

// EncodedLen returns the number of bytes required to encode the address.
func (a *Addr) EncodedLen() int {
	switch a.AddrType {
	case AddrTypeIPv4:
		return 1 + 4 + 2
	case AddrTypeIPv6:
		return 1 + 16 + 2
	case AddrTypeDomain:
		return 1 + 1 + len(a.Domain) + 2
	default:
		return 0
	}
}

// Decode decodes an address from src.
// It returns the number of bytes consumed.
func (a *Addr) Decode(src []byte) (int, error) {
	if len(src) < 1 {
		return 0, ErrShortAddr
	}

	a.AddrType = src[0]
	a.IP = nil
	a.Domain = ""

	switch a.AddrType {
	case AddrTypeIPv4:
		if len(src) < 1+4+2 {
			return 0, ErrShortAddr
		}
		a.IP = net.IP(src[1 : 1+4]).To4()
		if a.IP == nil {
			return 0, ErrInvalidAddr
		}
		a.Port = binary.BigEndian.Uint16(src[5:7])
		return 7, nil

	case AddrTypeIPv6:
		if len(src) < 1+16+2 {
			return 0, ErrShortAddr
		}
		a.IP = net.IP(src[1 : 1+16]).To16()
		if a.IP == nil || a.IP.To4() != nil {
			return 0, ErrInvalidAddr
		}
		a.Port = binary.BigEndian.Uint16(src[17:19])
		return 19, nil

	case AddrTypeDomain:
		if len(src) < 2 {
			return 0, ErrShortAddr
		}
		n := int(src[1])
		if len(src) < 1+1+n+2 {
			return 0, ErrShortAddr
		}
		a.Domain = string(src[2 : 2+n])
		a.Port = binary.BigEndian.Uint16(src[2+n : 2+n+2])
		if err := a.Validate(); err != nil {
			return 0, err
		}
		return 1 + 1 + n + 2, nil

	default:
		return 0, ErrInvalidAddrType
	}
}

// EncodeTo encodes the address into dst.
// It returns the number of bytes written.
func (a *Addr) EncodeTo(dst []byte) (int, error) {
	if err := a.Validate(); err != nil {
		return 0, err
	}

	n := a.EncodedLen()
	if len(dst) < n {
		return 0, ErrShortAddrBuffer
	}

	dst[0] = a.AddrType

	switch a.AddrType {
	case AddrTypeIPv4:
		copy(dst[1:5], a.IP.To4())
		binary.BigEndian.PutUint16(dst[5:7], a.Port)
		return 7, nil

	case AddrTypeIPv6:
		copy(dst[1:17], a.IP.To16())
		binary.BigEndian.PutUint16(dst[17:19], a.Port)
		return 19, nil

	case AddrTypeDomain:
		dst[1] = byte(len(a.Domain))
		copy(dst[2:2+len(a.Domain)], a.Domain)
		binary.BigEndian.PutUint16(dst[2+len(a.Domain):2+len(a.Domain)+2], a.Port)
		return 1 + 1 + len(a.Domain) + 2, nil

	default:
		return 0, ErrInvalidAddrType
	}
}

// String returns a human-readable representation of the address.
func (a *Addr) String() string {
	var atype string
	switch a.AddrType {
	case AddrTypeIPv4:
		atype = "IPv4"
	case AddrTypeDomain:
		atype = "DOMAIN"
	case AddrTypeIPv6:
		atype = "IPv6"
	default:
		atype = fmt.Sprintf("0x%02X", a.AddrType)
	}

	return fmt.Sprintf(
		"Addr{AddrType=%s, Host=%s, Port=%d}",
		atype, a.GetHost(), a.Port,
	)
}
