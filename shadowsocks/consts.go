package shadowsocks

// Encryption method constants for Shadowsocks AEAD-2022.
const (
	Method2022Blake3AES128GCM        = "2022-blake3-aes-128-gcm"
	Method2022Blake3AES256GCM        = "2022-blake3-aes-256-gcm"
	Method2022Blake3ChaCha20Poly1305 = "2022-blake3-chacha20-poly1305"
)

// SOCKS5-style address types used inside Shadowsocks headers.
const (
	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04
)

// TCP header types for Shadowsocks 2022 stream protocol.
const (
	TCPHeaderTypeClientStream = 0x00
	TCPHeaderTypeServerStream = 0x01
)

const (
	TcpRequestFixedHeaderLen = 1 + 8 + 2
	TcpResponseFixedBaseLen  = 1 + 8 + 2
)
