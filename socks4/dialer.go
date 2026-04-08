package socks4

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/33TU/socks/internal"
	socksnet "github.com/33TU/socks/net"
)

// Dialer implements a SOCKS4/4a proxy dialer.
type Dialer struct {
	ProxyAddr string          // e.g. "127.0.0.1:1080"
	UserID    string          // optional SOCKS4 user ID
	Dialer    socksnet.Dialer // optional underlying dialer (nil=DefaultDialer)
}

// NewDialer creates a new SOCKS4 dialer instance.
func NewDialer(proxyAddr, userID string, dialer socksnet.Dialer) *Dialer {
	return &Dialer{
		ProxyAddr: proxyAddr,
		UserID:    userID,
		Dialer:    dialer,
	}
}

// DialContext establishes a connection via SOCKS4/4a proxy (CMD_CONNECT).
func (d *Dialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	dialer := d.Dialer
	if dialer == nil {
		dialer = socksnet.DefaultDialer
	}

	// Parse target host/port
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}
	port, err := parsePort(ctx, portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid target port %q: %w", portStr, err)
	}

	// Connect to proxy
	proxyConn, err := dialer.DialContext(ctx, network, d.ProxyAddr)
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

	// Build SOCKS4 request
	var req Request
	req.Init(SocksVersion, CmdConnect, port, net.ParseIP(host), d.UserID, "")
	if net.ParseIP(host) == nil {
		// SOCKS4a fallback
		copy(req.IP[:], []byte{0, 0, 0, 1})
		req.Domain = host
	}

	// Send request using pooled writer
	writer := internal.GetWriter(proxyConn)
	defer internal.PutWriter(writer)

	if _, err := req.WriteTo(writer); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("send request: %w", err)
	}
	if err := writer.Flush(); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("flush request: %w", err)
	}

	// Read response using pooled reader
	reader := internal.GetReader(proxyConn)
	defer internal.PutReader(reader)

	var resp Reply
	if _, err := resp.ReadFrom(reader); err != nil {
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

// Dial establishes a connection via SOCKS4/4a proxy (CMD_CONNECT).
func (d *Dialer) Dial(network string, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// BindContext establishes a passive BIND connection via SOCKS4 proxy (CMD_BIND).
// It returns the active connection and the proxy’s bind address once ready.
func (d *Dialer) BindContext(ctx context.Context, network string, address string) (net.Conn, *net.TCPAddr, <-chan error, error) {
	dialer := d.Dialer
	if dialer == nil {
		dialer = socksnet.DefaultDialer
	}

	// Parse target host:port
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid target address: %w", err)
	}
	port, err := parsePort(ctx, portStr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid target port %q: %w", portStr, err)
	}

	// Connect to proxy
	proxyConn, err := dialer.DialContext(ctx, network, d.ProxyAddr)
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

	// Build SOCKS4 BIND request
	var req Request
	req.Init(SocksVersion, CmdBind, port, net.ParseIP(host), d.UserID, "")
	if net.ParseIP(host) == nil {
		copy(req.IP[:], []byte{0, 0, 0, 1})
		req.Domain = host
	}

	// Send BIND request using pooled writer
	writer := internal.GetWriter(proxyConn)
	defer internal.PutWriter(writer)

	if _, err := req.WriteTo(writer); err != nil {
		proxyConn.Close()
		return nil, nil, nil, fmt.Errorf("send BIND request: %w", err)
	}
	if err := writer.Flush(); err != nil {
		proxyConn.Close()
		return nil, nil, nil, fmt.Errorf("flush BIND request: %w", err)
	}

	// Read first response using pooled reader
	reader := internal.GetReader(proxyConn)
	defer internal.PutReader(reader)

	var resp1 Reply
	if _, err := resp1.ReadFrom(reader); err != nil {
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

		// Wait for second response using pooled reader
		reader2 := internal.GetReader(proxyConn)
		defer internal.PutReader(reader2)

		var resp2 Reply
		if _, err := resp2.ReadFrom(reader2); err != nil {
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

// Bind establishes a passive BIND connection via SOCKS4 proxy (CMD_BIND).
// It returns the active connection and the proxy’s bind address once ready.
func (d *Dialer) Bind(network string, address string) (net.Conn, *net.TCPAddr, <-chan error, error) {
	return d.BindContext(context.Background(), network, address)
}

// parsePort converts a port string to uint16.
func parsePort(ctx context.Context, p string) (uint16, error) {
	// Try parsing as number first (common case)
	if n, err := strconv.ParseUint(p, 10, 16); err == nil {
		return uint16(n), nil
	}

	// Fall back to name resolution
	n, err := net.DefaultResolver.LookupPort(ctx, "tcp", p)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}
