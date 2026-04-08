package net

import (
	"context"
	"net"
)

// DefaultDialer is the default underlying dialer, which uses net.Dialer.DialContext.
var DefaultDialer Dialer = &net.Dialer{}

// Dialer is an interface for dialing network connections.
type Dialer interface {
	DialContext(ctx context.Context, network string, address string) (net.Conn, error)
}
