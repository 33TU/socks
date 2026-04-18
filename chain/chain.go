package chain

import (
	"context"
	"errors"
	"net"

	socksnet "github.com/33TU/socks/net"
)

var (
	ErrAtLeastOneChainDialerRequired = errors.New("at least one chain dialer is required")
)

// Dialer is a chain dialer that can either establish a new connection from scratch or extend an existing one.
type Dialer interface {
	socksnet.Dialer
	socksnet.ConnDialer
}

// ChainDialer represents a single proxy hop in a chain.
//
// A ChainDialer must be able to:
//
//   - establish a fresh connection to a target with DialContext
//   - extend an existing connection to the next hop with DialConnContext
//
// ProxyAddress must return an address suitable for dialing the proxy as the
// next hop in the chain, typically in host:port form.
type ChainDialer interface {
	Dialer
	ProxyAddress() string
}

// New creates a multi-hop proxy dialer from the provided chain dialers.
func New(chainDialers ...ChainDialer) (Dialer, error) {
	if len(chainDialers) == 0 {
		return nil, ErrAtLeastOneChainDialerRequired
	}

	return &multiChainDialer{
		dialers: chainDialers,
	}, nil
}

// multiChainDialer implements a multi-hop proxy dialer.
type multiChainDialer struct {
	dialers []ChainDialer
}

// DialContext establishes a connection through the configured proxy chain.
func (c *multiChainDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialers := c.dialers

	// Fast path: a single dialer connects directly to the final target.
	if len(dialers) == 1 {
		return dialers[0].DialContext(ctx, network, address)
	}

	var (
		conn net.Conn
		err  error
	)

	defer func() {
		if err != nil && conn != nil {
			_ = conn.Close()
		}
	}()

	for i, d := range dialers {
		target := address
		if i < len(dialers)-1 {
			target = dialers[i+1].ProxyAddress()
		}

		if i == 0 {
			conn, err = d.DialContext(ctx, network, target)
		} else {
			conn, err = d.DialConnContext(ctx, conn, network, target)
		}

		if err != nil {
			return nil, err
		}
	}

	return conn, nil
}

// DialConnContext establishes a connection through the configured proxy chain
// over an existing connection.
//
// Unlike DialContext, this method does not automatically close the provided
// connection on error, since ownership of the input connection belongs to the
// caller and a dialer may have protocol-specific failure semantics.
func (c *multiChainDialer) DialConnContext(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error) {
	dialers := c.dialers

	if len(dialers) == 0 {
		return nil, ErrAtLeastOneChainDialerRequired
	}

	// Fast path: a single dialer extends the provided connection directly to the target.
	if len(dialers) == 1 {
		return dialers[0].DialConnContext(ctx, conn, network, address)
	}

	var err error

	for i, d := range dialers {
		target := address
		if i < len(dialers)-1 {
			target = dialers[i+1].ProxyAddress()
		}

		conn, err = d.DialConnContext(ctx, conn, network, target)
		if err != nil {
			return nil, err
		}
	}

	return conn, nil
}
