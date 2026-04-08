package socks4

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

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
	if dialer == nil {
		dialer = socksnet.DefaultDialer
	}
	return &Dialer{
		ProxyAddr: proxyAddr,
		UserID:    userID,
		Dialer:    dialer,
	}
}

// DialContext establishes a connection via SOCKS4/4a proxy (CONNECT command).
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := splitHostPort(ctx, address)
	if err != nil {
		return nil, err
	}

	conn, err := d.dialProxy(ctx, network)
	if err != nil {
		return nil, err
	}

	// Set connection deadline from context if available
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	reply, err := d.doRequest(conn, CmdConnect, host, port)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if !reply.IsGranted() {
		conn.Close()
		return nil, replyToError(reply.Code)
	}

	// Reset deadline after successful SOCKS negotiation
	if ok {
		conn.SetDeadline(time.Time{})
	}

	return conn, nil
}

// Dial establishes a connection via SOCKS4/4a proxy using background context.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// BindContext establishes a passive BIND connection via SOCKS4 proxy (CMD_BIND).
// It returns the active connection and the proxy’s bind address once ready.
// BindContext establishes a passive BIND connection via SOCKS4 proxy.
func (d *Dialer) BindContext(
	ctx context.Context,
	network, address string,
) (net.Conn, *net.TCPAddr, <-chan error, error) {
	host, port, err := splitHostPort(ctx, address)
	if err != nil {
		return nil, nil, nil, err
	}

	conn, err := d.dialProxy(ctx, network)
	if err != nil {
		return nil, nil, nil, err
	}

	// Set connection deadline from context if available
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	reply, err := d.doRequest(conn, CmdBind, host, port)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	if !reply.IsGranted() {
		conn.Close()
		return nil, nil, nil, replyToError(reply.Code)
	}

	// Reset deadline after successful SOCKS negotiation
	if ok {
		conn.SetDeadline(time.Time{})
	}

	bindAddr := &net.TCPAddr{
		IP:   reply.GetIP(),
		Port: int(reply.Port),
	}

	// Wait for second reply indicating incoming connection
	readyCh := make(chan error, 1)
	go func() {
		defer close(readyCh)

		reader := internal.GetReader(conn)
		defer internal.PutReader(reader)

		var resp2 Reply
		if _, err := resp2.ReadFrom(reader); err != nil {
			readyCh <- err
			return
		}
		if !resp2.IsGranted() {
			readyCh <- replyToError(resp2.Code)
			return
		}
		readyCh <- nil
	}()

	return conn, bindAddr, readyCh, nil
}

// Bind establishes a passive BIND connection using background context.
func (d *Dialer) Bind(network, address string) (net.Conn, *net.TCPAddr, <-chan error, error) {
	return d.BindContext(context.Background(), network, address)
}

// dialProxy connects to the SOCKS4 proxy server.
func (d *Dialer) dialProxy(ctx context.Context, network string) (net.Conn, error) {
	dialer := d.Dialer
	if dialer == nil {
		dialer = socksnet.DefaultDialer
	}
	return dialer.DialContext(ctx, network, d.ProxyAddr)
}

// doRequest sends a SOCKS4 request and reads the reply.
func (d *Dialer) doRequest(
	conn net.Conn,
	cmd byte,
	host string,
	port uint16,
) (*Reply, error) {
	// Build SOCKS4 request
	var req Request
	req.Init(SocksVersion, cmd, port, net.ParseIP(host), d.UserID, "")
	if net.ParseIP(host) == nil {
		// SOCKS4a fallback
		copy(req.IP[:], []byte{0, 0, 0, 1})
		req.Domain = host
	}

	writer := internal.GetWriter(conn)
	defer internal.PutWriter(writer)

	if _, err := req.WriteTo(writer); err != nil {
		return nil, err
	}
	if err := writer.Flush(); err != nil {
		return nil, err
	}

	reader := internal.GetReader(conn)
	defer internal.PutReader(reader)

	var reply Reply
	if _, err := reply.ReadFrom(reader); err != nil {
		return nil, err
	}

	return &reply, nil
}

// splitHostPort parses address into host and port with context for DNS resolution.
func splitHostPort(ctx context.Context, addr string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}

	port, err := parsePort(ctx, portStr)
	if err != nil {
		return "", 0, err
	}

	return host, port, nil
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

// replyToError converts a SOCKS4 reply code to an error.
func replyToError(code byte) error {
	switch code {
	case RepRejected:
		return fmt.Errorf("socks4: request rejected")
	case RepIdentFailed:
		return fmt.Errorf("socks4: failed to connect to identd")
	case RepUserIDMismatch:
		return fmt.Errorf("socks4: user ID does not match identd")
	default:
		return fmt.Errorf("socks4: unknown error (code 0x%02x)", code)
	}
}
