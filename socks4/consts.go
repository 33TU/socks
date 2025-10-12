package socks4

const (
	SocksVersion = 4
)

const (
	CmdConnect = 1
	CmdBind    = 2
)

const (
	DefaultMaxUserIDLen = 256
	DefaultMaxDomainLen = 256
)

const (
	ReqGranted        = 90
	ReqRejected       = 91
	ReqIdentFailed    = 92
	ReqUserIDMismatch = 93
)
