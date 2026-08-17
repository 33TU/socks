package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/33TU/socks/internal"
	"golang.org/x/crypto/chacha20poly1305"
)

// UDPCipher encrypts and decrypts Shadowsocks 2022 UDP packets.
//
// The AES methods encrypt the separate header, holding the session and packet
// ID, with a block cipher keyed by the PSK, and the body with a session subkey
// derived from the session ID. The nonce is taken from the plaintext separate
// header, so no nonce is transmitted:
//
//	+---------------------------+---------------------------+
//	| encrypted separate header |       encrypted body      |
//	+---------------------------+---------------------------+
//	|            16B            | variable length + 16B tag |
//	+---------------------------+---------------------------+
//
// The ChaCha method has no separate header. It uses XChaCha20-Poly1305 with the
// PSK directly and a random nonce per packet, and carries the session and
// packet ID at the front of the encrypted body:
//
//	+-------+---------------------------+
//	| nonce |       encrypted body      |
//	+-------+---------------------------+
//	|  24B  | variable length + 16B tag |
//	+-------+---------------------------+
type UDPCipher struct {
	Method Method

	psk   []byte
	block cipher.Block // AES methods only

	// aead and pskSession belong to the ChaCha method, where the PSK opens every
	// packet and sessions therefore share one cipher.
	aead       cipher.AEAD
	pskSession *UDPSessionCipher
}

// NewUDPCipher creates a UDP packet cipher for the method and PSK.
func NewUDPCipher(method Method, psk []byte) (*UDPCipher, error) {
	if err := method.Validate(); err != nil {
		return nil, err
	}
	if len(psk) != method.KeySize {
		return nil, fmt.Errorf("invalid PSK length: got %d, want %d", len(psk), method.KeySize)
	}

	c := &UDPCipher{
		Method: method,
		psk:    append([]byte(nil), psk...),
	}

	switch method.Kind {
	case MethodKindAESGCM:
		block, err := aes.NewCipher(c.psk)
		if err != nil {
			return nil, fmt.Errorf("create AES cipher: %w", err)
		}
		if block.BlockSize() != UDPSeparateHeaderLen {
			return nil, fmt.Errorf("unexpected block size: got %d, want %d", block.BlockSize(), UDPSeparateHeaderLen)
		}
		c.block = block

	case MethodKindChaCha20Poly1305:
		aead, err := chacha20poly1305.NewX(c.psk)
		if err != nil {
			return nil, fmt.Errorf("create XChaCha20-Poly1305: %w", err)
		}
		c.aead = aead
		c.pskSession = &UDPSessionCipher{cipher: c, aead: aead}

	default:
		return nil, fmt.Errorf("unsupported method kind: %d", method.Kind)
	}

	return c, nil
}

// HasSeparateHeader reports whether packets start with an encrypted separate
// header, which lets the session and packet ID be read before the packet is
// authenticated. It is true for the AES methods only.
func (c *UDPCipher) HasSeparateHeader() bool {
	return c != nil && c.block != nil
}

// HeaderOverhead returns the number of bytes a packet carries in front of the
// encrypted body.
func (c *UDPCipher) HeaderOverhead() int {
	if c.HasSeparateHeader() {
		return UDPSeparateHeaderLen
	}
	return UDPNonceLen
}

// PacketOverhead returns the total per-packet overhead, excluding the message header.
func (c *UDPCipher) PacketOverhead() int {
	overhead := c.HeaderOverhead() + c.Method.TagSize
	if !c.HasSeparateHeader() {
		// The session and packet ID are carried inside the encrypted body.
		overhead += UDPSeparateHeaderLen
	}
	return overhead
}

// PeekSeparateHeader decrypts the separate header of an incoming packet and
// returns its session and packet ID.
//
// The packet is not authenticated at this point, so the result MUST only be
// used to route the packet to a session. It is not available for methods
// without a separate header, which report ok as false.
func (c *UDPCipher) PeekSeparateHeader(packet []byte) (sessionID, packetID uint64, ok bool, err error) {
	if !c.HasSeparateHeader() {
		return 0, 0, false, nil
	}
	if len(packet) < UDPSeparateHeaderLen {
		return 0, 0, false, ErrShortUDPPacket
	}

	var separate [UDPSeparateHeaderLen]byte
	c.block.Decrypt(separate[:], packet[:UDPSeparateHeaderLen])

	sessionID = binary.BigEndian.Uint64(separate[:UDPSessionIDLen])
	packetID = binary.BigEndian.Uint64(separate[UDPSessionIDLen:])

	return sessionID, packetID, true, nil
}

// NewSession returns the cipher used to seal and open packets of a session.
func (c *UDPCipher) NewSession(sessionID uint64) (*UDPSessionCipher, error) {
	if c == nil {
		return nil, fmt.Errorf("nil UDP cipher")
	}

	s := &UDPSessionCipher{cipher: c, sessionID: sessionID}

	if !c.HasSeparateHeader() {
		// The PSK opens every packet; sessions share one AEAD.
		s.aead = c.aead
		return s, nil
	}

	// The session ID doubles as the salt for the session subkey.
	var salt [UDPSessionIDLen]byte
	binary.BigEndian.PutUint64(salt[:], sessionID)

	subkey := internal.GetBytes(c.Method.KeySize)
	defer internal.PutBytes(subkey)

	if err := deriveSubkeyTo(subkey, c.Method, c.psk, salt[:]); err != nil {
		return nil, err
	}

	aead, err := c.Method.NewAEAD(subkey)
	if err != nil {
		return nil, err
	}
	s.aead = aead

	return s, nil
}

// UDPSessionCipher seals and opens the packets of one UDP relay session.
type UDPSessionCipher struct {
	cipher    *UDPCipher
	sessionID uint64
	aead      cipher.AEAD
}

// SessionID returns the session this cipher belongs to.
func (s *UDPSessionCipher) SessionID() uint64 {
	return s.sessionID
}

// SealTo encrypts a packet carrying body as packetID and appends it to dst.
func (s *UDPSessionCipher) SealTo(dst []byte, packetID uint64, body []byte) ([]byte, error) {
	if s == nil || s.aead == nil {
		return nil, fmt.Errorf("nil UDP session cipher")
	}

	var separate [UDPSeparateHeaderLen]byte
	binary.BigEndian.PutUint64(separate[:UDPSessionIDLen], s.sessionID)
	binary.BigEndian.PutUint64(separate[UDPSessionIDLen:], packetID)

	if !s.cipher.HasSeparateHeader() {
		// A fresh random nonce per packet, with the IDs inside the body.
		var nonce [UDPNonceLen]byte
		if err := FillRandomBytes(nonce[:]); err != nil {
			return nil, err
		}

		plaintext := internal.GetBytes(UDPSeparateHeaderLen + len(body))
		defer internal.PutBytes(plaintext)
		copy(plaintext, separate[:])
		copy(plaintext[UDPSeparateHeaderLen:], body)

		dst = append(dst, nonce[:]...)
		return s.aead.Seal(dst, nonce[:], plaintext, nil), nil
	}

	// The nonce comes from the plaintext separate header, which is block
	// encrypted afterwards so it never appears on the wire in the clear.
	nonce := separate[UDPSeparateHeaderLen-AeadNonceSize:]

	start := len(dst)
	dst = append(dst, separate[:]...)
	dst = s.aead.Seal(dst, nonce, body, nil)
	s.cipher.block.Encrypt(dst[start:start+UDPSeparateHeaderLen], dst[start:start+UDPSeparateHeaderLen])

	return dst, nil
}

// OpenTo decrypts a packet, appending the plaintext body to dst. It returns the
// packet's session ID, packet ID, and the body.
//
// The session ID is returned rather than checked: callers route packets to a
// session before opening them.
func (s *UDPSessionCipher) OpenTo(dst, packet []byte) (sessionID, packetID uint64, body []byte, err error) {
	if s == nil || s.aead == nil {
		return 0, 0, nil, fmt.Errorf("nil UDP session cipher")
	}

	if !s.cipher.HasSeparateHeader() {
		if len(packet) < UDPNonceLen+UDPSeparateHeaderLen+s.cipher.Method.TagSize {
			return 0, 0, nil, ErrShortUDPPacket
		}

		plaintext, err := s.aead.Open(dst, packet[:UDPNonceLen], packet[UDPNonceLen:], nil)
		if err != nil {
			return 0, 0, nil, err
		}
		if len(plaintext) < UDPSeparateHeaderLen {
			return 0, 0, nil, ErrShortUDPPacket
		}

		sessionID = binary.BigEndian.Uint64(plaintext[:UDPSessionIDLen])
		packetID = binary.BigEndian.Uint64(plaintext[UDPSessionIDLen:UDPSeparateHeaderLen])

		return sessionID, packetID, plaintext[UDPSeparateHeaderLen:], nil
	}

	if len(packet) < UDPSeparateHeaderLen+s.cipher.Method.TagSize {
		return 0, 0, nil, ErrShortUDPPacket
	}

	var separate [UDPSeparateHeaderLen]byte
	s.cipher.block.Decrypt(separate[:], packet[:UDPSeparateHeaderLen])

	sessionID = binary.BigEndian.Uint64(separate[:UDPSessionIDLen])
	packetID = binary.BigEndian.Uint64(separate[UDPSessionIDLen:])
	nonce := separate[UDPSeparateHeaderLen-AeadNonceSize:]

	body, err = s.aead.Open(dst, nonce, packet[UDPSeparateHeaderLen:], nil)
	if err != nil {
		return 0, 0, nil, err
	}

	return sessionID, packetID, body, nil
}

// UDPUnpacked is a decrypted UDP packet.
type UDPUnpacked struct {
	SessionID uint64
	PacketID  uint64
	Body      []byte
}

// OpenPacketTo decrypts a packet into dst, resolving the session it belongs to.
//
// For methods with a separate header, the session and packet ID are decrypted
// first and passed to resolve, which returns the cipher able to open the
// packet. Callers use resolve to route by session, reject unknown sessions, and
// screen the packet ID against their sliding window before doing any AEAD work.
//
// For methods without a separate header, the packet is opened with the PSK and
// resolve is called afterwards with the IDs carried inside the body; a nil
// cipher from resolve is then accepted, since the packet is already open.
func (c *UDPCipher) OpenPacketTo(
	dst, packet []byte,
	resolve func(sessionID, packetID uint64) (*UDPSessionCipher, error),
) (UDPUnpacked, error) {
	if c == nil {
		return UDPUnpacked{}, fmt.Errorf("nil UDP cipher")
	}
	if resolve == nil {
		return UDPUnpacked{}, fmt.Errorf("nil UDP session resolver")
	}

	if c.HasSeparateHeader() {
		sessionID, packetID, _, err := c.PeekSeparateHeader(packet)
		if err != nil {
			return UDPUnpacked{}, err
		}

		session, err := resolve(sessionID, packetID)
		if err != nil {
			return UDPUnpacked{}, err
		}
		if session == nil {
			return UDPUnpacked{}, ErrUDPUnknownSession
		}

		gotSessionID, gotPacketID, body, err := session.OpenTo(dst, packet)
		if err != nil {
			return UDPUnpacked{}, err
		}
		if gotSessionID != sessionID {
			return UDPUnpacked{}, ErrUDPSessionIDMismatch
		}

		return UDPUnpacked{SessionID: gotSessionID, PacketID: gotPacketID, Body: body}, nil
	}

	// Without a separate header the packet must be opened before its session is known.
	sessionID, packetID, body, err := c.pskSession.OpenTo(dst, packet)
	if err != nil {
		return UDPUnpacked{}, err
	}

	if _, err := resolve(sessionID, packetID); err != nil {
		return UDPUnpacked{}, err
	}

	return UDPUnpacked{SessionID: sessionID, PacketID: packetID, Body: body}, nil
}
