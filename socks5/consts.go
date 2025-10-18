package socks5

// Protocol version.
const (
	SocksVersion = 5
)

// Command codes (CMD) for client requests.
const (
	CmdConnect      = 1
	CmdBind         = 2
	CmdUDPAssociate = 3
	CmdResolve      = 0xF0
	CmdResolvePTR   = 0xF1
)

// Address types (ATYP) used in requests and responses.
const (
	AddrTypeIPv4   = 1
	AddrTypeDomain = 3
	AddrTypeIPv6   = 4
)

// Reply codes (REP) for server responses.
const (
	RepSuccess              = 0
	RepGeneralFailure       = 1
	RepConnectionNotAllowed = 2
	RepNetworkUnreachable   = 3
	RepHostUnreachable      = 4
	RepConnectionRefused    = 5
	RepTTLExpired           = 6
	RepCommandNotSupported  = 7
	RepAddrTypeNotSupported = 8
)

// Authentication methods (METHOD) for initial greeting.
const (
	MethodNoAuth       = 0x00
	MethodGSSAPI       = 0x01
	MethodUserPass     = 0x02
	MethodNoAcceptable = 0xFF
)

// Authentication sub-negotiation versions.
const (
	AuthVersionUserPass = 1
)

// GSS-API message types (MTYP)
const (
	GSSAPITypeInit  = 0x01
	GSSAPITypeReply = 0x02
	GSSAPITypeAbort = 0xFF
)

// GSS-API protocol version. (VER)
const (
	GSSAPIVersion = 1
)
