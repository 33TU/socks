package socks5

// Protocol version.
const (
	SocksVersion = 5
)

// Command codes (CMD) for client requests.
const (
	CmdConnect      = 1    // Establish a TCP/IP stream connection
	CmdBind         = 2    // Establish a TCP/IP port binding
	CmdUDPAssociate = 3    // Associate UDP relay
	CmdResolve      = 0xF0 // Name resolution (non-standard)
	CmdResolvePTR   = 0xF1 // Reverse lookup (non-standard)
)

// Address types (ATYP) used in requests and responses.
const (
	AddrTypeIPv4   = 1 // IPv4 address
	AddrTypeDomain = 3 // Domain name
	AddrTypeIPv6   = 4 // IPv6 address
)

// Reply codes (REP) for server responses.
const (
	RepSuccess              = 0 // Request granted
	RepGeneralFailure       = 1 // General SOCKS server failure
	RepConnectionNotAllowed = 2 // Connection not allowed by ruleset
	RepNetworkUnreachable   = 3 // Network unreachable
	RepHostUnreachable      = 4 // Host unreachable
	RepConnectionRefused    = 5 // Connection refused
	RepTTLExpired           = 6 // TTL expired
	RepCommandNotSupported  = 7 // Command not supported
	RepAddrTypeNotSupported = 8 // Address type not supported
)

// Authentication methods (METHOD) for initial greeting.
const (
	MethodNoAuth       = 0x00 // No authentication required
	MethodGSSAPI       = 0x01 // GSS-API authentication
	MethodUserPass     = 0x02 // Username/password authentication
	MethodNoAcceptable = 0xFF // No acceptable methods
)

// Authentication sub-negotiation versions.
const (
	AuthVersionUserPass = 1 // Username/password sub-negotiation version
)

// GSS-API message types (MTYP) per RFC 1961.
const (
	GSSAPITypeInit  = 0x01 // Client initial token
	GSSAPITypeReply = 0x02 // Server reply token
	GSSAPITypeAbort = 0xFF // Abort / failure
)
