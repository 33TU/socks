package shadowsocks

import "time"

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

// Padding limits for Shadowsocks 2022 request and packet headers.
const (
	MinPaddingLength = 0
	MaxPaddingLength = 900
)

// Replay protection timing parameters.
const (
	// MaxTimestampDiff is the largest allowed difference between a received
	// timestamp and system time. Messages outside the window are replays.
	MaxTimestampDiff = 30 * time.Second

	// ReplayWindowDuration is how long a salt or relay session must be
	// remembered to reliably reject replays.
	ReplayWindowDuration = 2 * MaxTimestampDiff
)
