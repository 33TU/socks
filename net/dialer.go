package net

import (
	"context"
	"net"
)

// DefaultDialer is the default Dialer using net.Dialer.
var DefaultDialer Dialer = &net.Dialer{}

// Dialer represents a type capable of creating network connections.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ConnDialer represents a type capable of upgrading an existing connection.
type ConnDialer interface {
	DialConnContext(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error)
}
