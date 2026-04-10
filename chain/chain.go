package chain

import (
	"context"
	"errors"
	"net"

	socksnet "github.com/33TU/socks/net"
)

var (
	ErrLeastOneConnDialerRequired = errors.New("at least one conn dialer is required in chain")
)

// ChainDialer represents a proxy hop in the chain.
type ChainDialer interface {
	socksnet.Dialer
	socksnet.ConnDialer
	ProxyAddress() string
}

// Chain creates a multi-hop proxy dialer from the provided chain dialers.
func Chain(connDialers ...ChainDialer) (socksnet.Dialer, error) {
	if len(connDialers) == 0 {
		return nil, ErrLeastOneConnDialerRequired
	}

	return &mutliChainDialer{
		dialers: connDialers,
	}, nil
}

// mutliChainDialer implements a multi-hop proxy dialer.
type mutliChainDialer struct {
	dialers []ChainDialer
}

func (c *mutliChainDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialers := c.dialers

	// fast path, single dialer just dials the target directly
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
		// determine target, last hop targets final address, others target next proxy
		target := address
		if i < len(dialers)-1 {
			target = dialers[i+1].ProxyAddress()
		}

		// first hop uses DialContext, rest use DialConnContext
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
