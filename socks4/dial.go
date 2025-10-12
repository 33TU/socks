package socks4

import (
	"context"
	"fmt"
	"net"
)

var (
	// DefaultDialer is the default internal net.Dialer.
	DefaultDialer = &net.Dialer{}
)

// Dialer implements a SOCKS4/4a proxy dialer.
type Dialer struct {
	ProxyAddr    string      // e.g. "127.0.0.1:1080"
	ProxyNetwork string      // e.g. "tcp"
	UserID       string      // optional SOCKS4 user ID
	BaseDialer   *net.Dialer // optional underlying dialer (nil=DefaultDialer)
}

// NewDialer creates a new SOCKS4 dialer instance.
func NewDialer(proxyAddr, proxyNetwork, userID string, base *net.Dialer) *Dialer {
	return &Dialer{
		ProxyAddr:    proxyAddr,
		ProxyNetwork: proxyNetwork,
		UserID:       userID,
		BaseDialer:   base,
	}
}

// ConnectContext establishes a connection via SOCKS4/4a proxy (CMD_CONNECT).
func (d *Dialer) ConnectContext(ctx context.Context, addr string) (net.Conn, error) {
	base := d.BaseDialer
	if base == nil {
		base = DefaultDialer
	}

	// Connect to proxy
	proxyConn, err := base.DialContext(ctx, d.ProxyNetwork, d.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to proxy: %w", err)
	}

	// Close proxy connection on context cancellation
	exitCh := make(chan struct{})
	defer close(exitCh)

	go func() {
		select {
		case <-ctx.Done():
			proxyConn.Close()
		case <-exitCh:
			return
		}
	}()

	// Parse target host/port
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("invalid target address: %w", err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("invalid target port %q: %w", portStr, err)
	}

	// Build SOCKS4 request
	var req Request
	req.Init(SocksVersion, CmdConnect, port, net.ParseIP(host), d.UserID, "")
	if net.ParseIP(host) == nil {
		// SOCKS4a fallback
		copy(req.IP[:], []byte{0, 0, 0, 1})
		req.Domain = host
	}

	// Send request
	if _, err := req.WriteTo(proxyConn); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("send request: %w", err)
	}

	// Read response
	var resp Response
	if _, err := resp.ReadFrom(proxyConn); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}

	if !resp.IsGranted() {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy rejected request (code 0x%02x)", resp.Code)
	}

	// Connection established
	return proxyConn, nil
}

// Connect connects to the specified address via SOCKS4/4a proxy.
func (d *Dialer) Connect(addr string) (net.Conn, error) {
	return d.ConnectContext(context.Background(), addr)
}

// BindContext establishes a passive BIND connection via SOCKS4 proxy (CMD_BIND).
// It returns the active connection and the proxy’s bind address once ready.
func (d *Dialer) BindContext(ctx context.Context, addr string) (net.Conn, *net.TCPAddr, <-chan error, error) {
	base := d.BaseDialer
	if base == nil {
		base = DefaultDialer
	}

	// Connect to proxy
	proxyConn, err := base.DialContext(ctx, d.ProxyNetwork, d.ProxyAddr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connect to proxy: %w", err)
	}

	// Close proxy connection on context cancellation
	exitCh := make(chan struct{})
	defer close(exitCh)

	go func() {
		select {
		case <-ctx.Done():
			proxyConn.Close()
		case <-exitCh:
			return
		}
	}()

	// Parse target host:port
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		proxyConn.Close()
		return nil, nil, nil, fmt.Errorf("invalid target address: %w", err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		proxyConn.Close()
		return nil, nil, nil, fmt.Errorf("invalid target port %q: %w", portStr, err)
	}

	// Build SOCKS4 BIND request
	var req Request
	req.Init(SocksVersion, CmdBind, port, net.ParseIP(host), d.UserID, "")
	if net.ParseIP(host) == nil {
		copy(req.IP[:], []byte{0, 0, 0, 1})
		req.Domain = host
	}

	// Send BIND request
	if _, err := req.WriteTo(proxyConn); err != nil {
		proxyConn.Close()
		return nil, nil, nil, fmt.Errorf("send BIND request: %w", err)
	}

	// Read first response (proxy bind address)
	var resp1 Response
	if _, err := resp1.ReadFrom(proxyConn); err != nil {
		proxyConn.Close()
		return nil, nil, nil, fmt.Errorf("read first BIND response: %w", err)
	}
	if !resp1.IsGranted() {
		proxyConn.Close()
		return nil, nil, nil, fmt.Errorf("proxy rejected BIND setup (code 0x%02x)", resp1.Code)
	}

	bindAddr := &net.TCPAddr{
		IP:   resp1.GetIP(),
		Port: int(resp1.Port),
	}

	readyCh := make(chan error, 1)
	go func() {
		defer close(readyCh)

		// Wait for second response (remote host connected)
		var resp2 Response
		if _, err := resp2.ReadFrom(proxyConn); err != nil {
			readyCh <- fmt.Errorf("read second BIND response: %w", err)
		}
		if !resp2.IsGranted() {
			readyCh <- fmt.Errorf("proxy rejected BIND finalization (code 0x%02x)", resp2.Code)
		}
		readyCh <- nil
	}()

	// Connection established
	return proxyConn, bindAddr, readyCh, nil
}

// Bind establishes a passive BIND connection using a background context.
func (d *Dialer) Bind(addr string) (net.Conn, *net.TCPAddr, <-chan error, error) {
	return d.BindContext(context.Background(), addr)
}

// parsePort converts a port string to uint16.
func parsePort(p string) (uint16, error) {
	n, err := net.LookupPort("tcp", p)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}
