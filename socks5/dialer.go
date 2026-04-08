package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/33TU/socks/internal"
	socksnet "github.com/33TU/socks/net"
)

// GSSAPIContext interface for GSSAPI authentication operations.
type GSSAPIContext interface {
	// InitSecContext generates initial GSSAPI token
	InitSecContext() ([]byte, error)
	// AcceptSecContext processes server tokens and generates response
	// Returns: (responseToken, authComplete, error)
	AcceptSecContext(serverToken []byte) ([]byte, bool, error)
	// IsComplete returns true when authentication is finished
	IsComplete() bool
}

// Auth holds username/password credentials for SOCKS5 authentication.
type Auth struct {
	Username string
	Password string
}

// GSSAPIAuth holds GSSAPI authentication context.
type GSSAPIAuth struct {
	Context GSSAPIContext
}

// Dialer implements a SOCKS5 proxy dialer.
type Dialer struct {
	ProxyAddr  string
	Auth       *Auth
	GSSAPIAuth *GSSAPIAuth
	Dialer     socksnet.Dialer
}

// NewDialer creates a new SOCKS5 dialer instance.
func NewDialer(proxyAddr string, auth *Auth, dialer socksnet.Dialer) *Dialer {
	if dialer == nil {
		dialer = socksnet.DefaultDialer
	}
	return &Dialer{
		ProxyAddr: proxyAddr,
		Auth:      auth,
		Dialer:    dialer,
	}
}

// NewDialerWithGSSAPI creates a new SOCKS5 dialer instance with GSSAPI support.
func NewDialerWithGSSAPI(proxyAddr string, auth *Auth, gssapiAuth *GSSAPIAuth, dialer socksnet.Dialer) *Dialer {
	if dialer == nil {
		dialer = socksnet.DefaultDialer
	}
	return &Dialer{
		ProxyAddr:  proxyAddr,
		Auth:       auth,
		GSSAPIAuth: gssapiAuth,
		Dialer:     dialer,
	}
}

// DialContext establishes a connection via SOCKS5 proxy (CONNECT command).
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

	// Handle context cancellation
	exitCh := make(chan struct{})
	defer close(exitCh)

	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-exitCh:
			return
		}
	}()

	if err := d.handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}

	reply, err := d.doRequest(conn, CmdConnect, host, port)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if reply.Reply != RepSuccess {
		conn.Close()
		return nil, replyToError(reply.Reply)
	}

	// Reset deadline after successful SOCKS negotiation
	if ok {
		conn.SetDeadline(time.Time{})
	}

	return conn, nil
}

// Dial establishes a connection via SOCKS5 proxy using background context.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// BindContext establishes a passive BIND connection via SOCKS5 proxy.
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

	// Handle context cancellation
	exitCh := make(chan struct{})
	defer close(exitCh)

	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-exitCh:
			return
		}
	}()

	if err := d.handshake(conn); err != nil {
		conn.Close()
		return nil, nil, nil, err
	}

	reply, err := d.doRequest(conn, CmdBind, host, port)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}

	if reply.Reply != RepSuccess {
		conn.Close()
		return nil, nil, nil, replyToError(reply.Reply)
	}

	// Reset deadline after successful SOCKS negotiation
	if ok {
		conn.SetDeadline(time.Time{})
	}

	addr := replyToTCPAddr(reply)

	ready := make(chan error, 1)

	go func() {
		defer close(ready)

		reader := internal.GetReader(conn)
		defer internal.PutReader(reader)

		var second Reply
		_, err := second.ReadFrom(reader)
		if err != nil {
			ready <- err
			return
		}

		if second.Reply != RepSuccess {
			ready <- replyToError(second.Reply)
			return
		}

		ready <- nil
	}()

	return conn, addr, ready, nil
}

// Bind establishes a passive BIND connection using background context.
func (d *Dialer) Bind(network, address string) (net.Conn, *net.TCPAddr, <-chan error, error) {
	return d.BindContext(context.Background(), network, address)
}

// UDPAssociateContext establishes a UDP association via SOCKS5 proxy.
func (d *Dialer) UDPAssociateContext(
	ctx context.Context,
	network string,
	clientAddr *net.UDPAddr,
) (net.Conn, *net.UDPAddr, error) {

	conn, err := d.dialProxy(ctx, network)
	if err != nil {
		return nil, nil, err
	}

	// Set connection deadline from context if available
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	// Handle context cancellation
	exitCh := make(chan struct{})
	defer close(exitCh)

	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-exitCh:
			return
		}
	}()

	if err := d.handshake(conn); err != nil {
		conn.Close()
		return nil, nil, err
	}

	host := "0.0.0.0"
	port := uint16(0)

	if clientAddr != nil {
		host = clientAddr.IP.String()
		port = uint16(clientAddr.Port)
	}

	reply, err := d.doRequest(conn, CmdUDPAssociate, host, port)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	if reply.Reply != RepSuccess {
		conn.Close()
		return nil, nil, replyToError(reply.Reply)
	}

	// Reset deadline after successful SOCKS negotiation
	if ok {
		conn.SetDeadline(time.Time{})
	}

	udpAddr := replyToUDPAddr(reply)

	return conn, udpAddr, nil
}

// UDPAssociate establishes a UDP association using background context.
func (d *Dialer) UDPAssociate(network string, clientAddr *net.UDPAddr) (net.Conn, *net.UDPAddr, error) {
	return d.UDPAssociateContext(context.Background(), network, clientAddr)
}

// ResolveContext resolves a hostname via SOCKS5 proxy (Tor-style extension).
func (d *Dialer) ResolveContext(ctx context.Context, network, host string) (net.IP, error) {
	conn, err := d.dialProxy(ctx, network)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Set connection deadline from context if available
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	// Handle context cancellation (ResolveContext uses defer conn.Close)
	go func() {
		<-ctx.Done()
		conn.Close() // Safe to call multiple times
	}()

	if err := d.handshake(conn); err != nil {
		return nil, err
	}

	reply, err := d.doRequest(conn, CmdResolve, host, 0)
	if err != nil {
		return nil, err
	}

	if reply.Reply != RepSuccess {
		return nil, replyToError(reply.Reply)
	}

	// Reset deadline after successful SOCKS negotiation
	if ok {
		conn.SetDeadline(time.Time{})
	}

	return reply.IP, nil
}

// dialProxy connects to the SOCKS5 proxy server.
func (d *Dialer) dialProxy(ctx context.Context, network string) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, d.ProxyAddr)
}

// handshake performs SOCKS5 method negotiation.
func (d *Dialer) handshake(conn net.Conn) error {
	methods := []byte{MethodNoAuth}

	if d.Auth != nil {
		methods = append(methods, MethodUserPass)
	}

	if d.GSSAPIAuth != nil {
		methods = append(methods, MethodGSSAPI)
	}

	var req HandshakeRequest
	req.Init(SocksVersion, methods...)

	writer := internal.GetWriter(conn)
	defer internal.PutWriter(writer)

	if _, err := req.WriteTo(writer); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	reader := internal.GetReader(conn)
	defer internal.PutReader(reader)

	var reply HandshakeReply
	if _, err := reply.ReadFrom(reader); err != nil {
		return err
	}

	switch reply.Method {
	case MethodNoAuth:
		return nil

	case MethodUserPass:
		if d.Auth == nil {
			return errors.New("socks5: server requires authentication")
		}
		return d.authUserPass(conn)

	case MethodGSSAPI:
		if d.GSSAPIAuth == nil {
			return errors.New("socks5: server requires GSSAPI authentication")
		}
		return d.authGSSAPI(conn)

	default:
		return errors.New("socks5: no acceptable authentication method")
	}
}

// authUserPass performs SOCKS5 username/password authentication.
func (d *Dialer) authUserPass(conn net.Conn) error {
	req := UserPassRequest{
		Version:  1,
		Username: d.Auth.Username,
		Password: d.Auth.Password,
	}

	writer := internal.GetWriter(conn)
	defer internal.PutWriter(writer)

	if _, err := req.WriteTo(writer); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	reader := internal.GetReader(conn)
	defer internal.PutReader(reader)

	var reply UserPassReply
	if _, err := reply.ReadFrom(reader); err != nil {
		return err
	}

	if reply.Status != 0 {
		return errors.New("socks5: authentication failed")
	}

	return nil
}

// authGSSAPI performs SOCKS5 GSSAPI authentication exchange.
func (d *Dialer) authGSSAPI(conn net.Conn) error {
	// Get initial token from GSSAPI context
	initialToken, err := d.GSSAPIAuth.Context.InitSecContext()
	if err != nil {
		return fmt.Errorf("socks5: failed to initialize GSSAPI context: %w", err)
	}

	// Send initial GSSAPI request
	req := GSSAPIRequest{
		Version: GSSAPIVersion,
		MsgType: GSSAPITypeInit,
		Token:   initialToken,
	}

	writer := internal.GetWriter(conn)
	defer internal.PutWriter(writer)

	if _, err := req.WriteTo(writer); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	reader := internal.GetReader(conn)
	defer internal.PutReader(reader)

	// GSSAPI may require multiple round trips
	for !d.GSSAPIAuth.Context.IsComplete() {
		var reply GSSAPIReply
		if _, err := reply.ReadFrom(reader); err != nil {
			return err
		}

		if reply.Version != GSSAPIVersion {
			return errors.New("socks5: invalid GSSAPI version in reply")
		}

		switch reply.MsgType {
		case GSSAPITypeReply:
			// Process server token and get next client token
			nextToken, complete, err := d.GSSAPIAuth.Context.AcceptSecContext(reply.Token)
			if err != nil {
				return fmt.Errorf("socks5: GSSAPI context error: %w", err)
			}

			if complete {
				return nil // Authentication successful
			}

			// Send continuation token if available
			if len(nextToken) > 0 {
				contReq := GSSAPIRequest{
					Version: GSSAPIVersion,
					MsgType: GSSAPITypeInit,
					Token:   nextToken,
				}

				if _, err := contReq.WriteTo(writer); err != nil {
					return err
				}
				if err := writer.Flush(); err != nil {
					return err
				}
			}

		case GSSAPITypeAbort:
			return errors.New("socks5: GSSAPI authentication aborted by server")

		default:
			return fmt.Errorf("socks5: unknown GSSAPI message type: %d", reply.MsgType)
		}
	}

	return nil
}

// doRequest sends a SOCKS5 request and reads the reply.
func (d *Dialer) doRequest(
	conn net.Conn,
	cmd byte,
	host string,
	port uint16,
) (*Reply, error) {

	ip := net.ParseIP(host)

	req := Request{
		Version: SocksVersion,
		Command: cmd,
		Port:    port,
	}

	switch {
	case ip == nil:
		req.AddrType = AddrTypeDomain
		req.Domain = host

	case ip.To4() != nil:
		req.AddrType = AddrTypeIPv4
		req.IP = ip.To4()

	default:
		req.AddrType = AddrTypeIPv6
		req.IP = ip.To16()
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

// replyToTCPAddr converts a SOCKS5 reply to a TCP address.
func replyToTCPAddr(r *Reply) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   r.IP,
		Port: int(r.Port),
	}
}

// replyToUDPAddr converts a SOCKS5 reply to a UDP address.
func replyToUDPAddr(r *Reply) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   r.IP,
		Port: int(r.Port),
	}
}

// replyToError converts a SOCKS5 reply code to an error.
func replyToError(rep byte) error {
	switch rep {
	case RepGeneralFailure:
		return errors.New("socks5: general failure")
	case RepConnectionNotAllowed:
		return errors.New("socks5: connection not allowed")
	case RepNetworkUnreachable:
		return errors.New("socks5: network unreachable")
	case RepHostUnreachable:
		return errors.New("socks5: host unreachable")
	case RepConnectionRefused:
		return errors.New("socks5: connection refused")
	case RepTTLExpired:
		return errors.New("socks5: ttl expired")
	case RepCommandNotSupported:
		return errors.New("socks5: command not supported")
	case RepAddrTypeNotSupported:
		return errors.New("socks5: address type not supported")
	default:
		return fmt.Errorf("socks5: unknown error (%d)", rep)
	}
}
