package socks4

// Protocol version.
const (
	SocksVersion = 4
)

// Command codes (CD) for client requests.
const (
	CmdConnect = 1
	CmdBind    = 2
)

// Default maximum lengths for SOCKS4a string fields.
const (
	DefaultMaxUserIDLen = 256
	DefaultMaxDomainLen = 256
)

// Reply codes (CD) for server replies.
const (
	RepGranted        = 90
	RepRejected       = 91
	RepIdentFailed    = 92
	RepUserIDMismatch = 93
)
