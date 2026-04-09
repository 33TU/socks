package chain

import (
	"errors"

	socksnet "github.com/33TU/socks/net"
	"github.com/33TU/socks/socks4"
	"github.com/33TU/socks/socks5"
)

var (
	ErrLeastOneDialerRequired = errors.New("at least one dialer is required in chain")
	ErrUnsupportedDialerType  = errors.New("unsupported dialer type in chain")
)

// Chain creates a chained dialer from a list of SOCKS dialers (SOCKS5, SOCKS4a and SOCKS4 supported).
func Chain(dialers ...socksnet.Dialer) (socksnet.Dialer, error) {
	if len(dialers) == 0 {
		return nil, ErrLeastOneDialerRequired
	}

	for i := 1; i < len(dialers); i++ {
		switch d := dialers[i].(type) {
		case *socks5.Dialer:
			d.Dialer = dialers[i-1]
		case *socks4.Dialer:
			d.Dialer = dialers[i-1]
		default:
			return nil, ErrUnsupportedDialerType
		}
	}

	return dialers[len(dialers)-1], nil
}
