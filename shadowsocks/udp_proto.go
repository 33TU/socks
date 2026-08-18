package shadowsocks

import "errors"

// UDP header types for the Shadowsocks 2022 packet protocol.
const (
	UDPHeaderTypeClientPacket = 0x00
	UDPHeaderTypeServerPacket = 0x01
)

// UDP packet framing sizes.
const (
	// UDPSessionIDLen is the length of a session ID.
	UDPSessionIDLen = 8

	// UDPPacketIDLen is the length of a packet ID.
	UDPPacketIDLen = 8

	// UDPSeparateHeaderLen is the length of the separate header, which the AES
	// methods encrypt with a block cipher keyed by the PSK.
	UDPSeparateHeaderLen = UDPSessionIDLen + UDPPacketIDLen

	// UDPNonceLen is the XChaCha20-Poly1305 nonce prepended to packets by the
	// ChaCha method, which has no separate header.
	UDPNonceLen = 24

	// UDPClientHeaderFixedLen covers type, timestamp and padding length.
	UDPClientHeaderFixedLen = 1 + 8 + 2

	// UDPServerHeaderFixedLen covers type, timestamp, client session ID and padding length.
	UDPServerHeaderFixedLen = 1 + 8 + 8 + 2
)

// DefaultUDPBufferSize is the default read buffer size for UDP relays. It is
// large enough for any datagram that fits in a single IP packet.
const DefaultUDPBufferSize = 64 * 1024

// Common validation and decode errors for Shadowsocks UDP packets.
var (
	ErrInvalidUDPHeaderType     = errors.New("invalid UDP header type")
	ErrShortUDPHeader           = errors.New("short UDP header")
	ErrShortUDPPacket           = errors.New("short UDP packet")
	ErrUDPPaddingExceedsPacket  = errors.New("UDP padding exceeds packet")
	ErrUDPSessionIDMismatch     = errors.New("UDP session ID mismatch")
	ErrUDPClientSessionMismatch = errors.New("UDP client session ID mismatch")
	ErrUDPReplay                = errors.New("UDP packet ID replay")
	ErrUDPUnknownSession        = errors.New("unknown UDP session")
	ErrTooManyUDPServerSessions = errors.New("server session changed more than once within the replay window")
)
