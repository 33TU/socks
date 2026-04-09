package socks5

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"time"

	socksnet "github.com/33TU/socks/net"
	"golang.org/x/sync/errgroup"
)

// BaseServerHandler provides a basic implementation of ServerHandler with configurable options.
type BaseServerHandler struct {
	Dialer              socksnet.Dialer
	RequestTimeout      time.Duration
	BindAcceptTimeout   time.Duration
	BindConnTimeout     time.Duration
	ConnectDialTimeout  time.Duration
	ConnectConnTimeout  time.Duration
	UDPAssociateTimeout time.Duration
	ConnectBufferSize   int
	AllowConnect        bool
	AllowBind           bool
	AllowUDPAssociate   bool
	AllowResolve        bool

	SupportedMethods []byte

	UserPassAuthenticator func(ctx context.Context, username, password string) error
	GSSAPIAuthenticator   func(ctx context.Context, token []byte) (resp []byte, done bool, err error)
}

func (d *BaseServerHandler) OnAccept(ctx context.Context, conn net.Conn) error {
	slog.InfoContext(ctx, "accepted connection", "from", conn.RemoteAddr())

	if d.RequestTimeout != 0 {
		conn.SetDeadline(time.Now().Add(d.RequestTimeout))
	}
	return nil
}

func (d *BaseServerHandler) OnHandshake(ctx context.Context, conn net.Conn, req *HandshakeRequest) (byte, error) {
	slog.InfoContext(ctx, "handshake request", "from", conn.RemoteAddr(), "methods", req.Methods)

	selectedMethod, err := BaseOnHandshake(ctx, conn, req, d.GetSupportedMethods())
	if err != nil {
		slog.ErrorContext(ctx, "handshake failed", "error", err)
		return MethodNoAcceptable, err
	}

	slog.InfoContext(ctx, "handshake completed", "from", conn.RemoteAddr(), "selected_method", selectedMethod)
	return selectedMethod, nil
}

func (d *BaseServerHandler) OnAuthUserPass(ctx context.Context, conn net.Conn, username, password string) error {
	slog.InfoContext(ctx, "validating username/password", "from", conn.RemoteAddr(), "username", username)

	if d.UserPassAuthenticator != nil {
		return d.UserPassAuthenticator(ctx, username, password)
	}
	return nil // Allow all by default
}

func (d *BaseServerHandler) OnAuthGSSAPI(ctx context.Context, conn net.Conn, token []byte) ([]byte, bool, error) {
	slog.InfoContext(ctx, "validating GSSAPI token", "from", conn.RemoteAddr())

	if d.GSSAPIAuthenticator != nil {
		return d.GSSAPIAuthenticator(ctx, token)
	}
	return nil, true, nil // Allow all by default, and mark as complete
}

func (d *BaseServerHandler) OnRequest(ctx context.Context, conn net.Conn, req *Request) error {
	err := BaseOnRequest(ctx, d, conn, req)
	if err != nil {
		slog.ErrorContext(ctx, "request handling failed", "error", err, "from", conn.RemoteAddr(), "request", req)
	}
	return err
}

func (d *BaseServerHandler) OnConnect(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowConnect {
		writeReject(conn, RepConnectionNotAllowed)
		return fmt.Errorf("CONNECT command not allowed")
	}

	addr := req.Addr()
	slog.InfoContext(ctx, "CONNECT request", "from", conn.RemoteAddr(), "target", addr)

	if err := BaseOnConnect(ctx, conn, req, d.Dialer, d.ConnectDialTimeout, d.ConnectConnTimeout, d.ConnectBufferSize); err != nil {
		return fmt.Errorf("CONNECT failed to %s: %w", addr, err)
	}

	slog.InfoContext(ctx, "CONNECT completed", "from", conn.RemoteAddr(), "target", addr)
	return nil
}

func (d *BaseServerHandler) OnBind(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowBind {
		writeReject(conn, RepConnectionNotAllowed)
		return fmt.Errorf("BIND command not allowed")
	}

	slog.InfoContext(ctx, "BIND request", "from", conn.RemoteAddr(), "target", req.Addr())

	if err := BaseOnBind(ctx, conn, req, d.BindAcceptTimeout, d.BindConnTimeout, d.ConnectBufferSize); err != nil {
		return fmt.Errorf("BIND failed: %w", err)
	}

	slog.InfoContext(ctx, "BIND completed", "from", conn.RemoteAddr())
	return nil
}

func (d *BaseServerHandler) OnUDPAssociate(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowUDPAssociate {
		writeReject(conn, RepConnectionNotAllowed)
		return fmt.Errorf("UDP ASSOCIATE command not allowed")
	}

	addr := req.Addr()
	slog.InfoContext(ctx, "UDP ASSOCIATE request", "from", conn.RemoteAddr(), "target", addr)

	if err := BaseOnUDPAssociate(ctx, conn, req, d.UDPAssociateTimeout, d.ConnectBufferSize); err != nil {
		return fmt.Errorf("UDP ASSOCIATE failed to %s: %w", addr, err)
	}

	slog.InfoContext(ctx, "UDP ASSOCIATE completed", "from", conn.RemoteAddr(), "target", addr)
	return nil
}

func (d *BaseServerHandler) OnResolve(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowResolve {
		writeReject(conn, RepConnectionNotAllowed)
		return fmt.Errorf("RESOLVE command not allowed")
	}

	addr := req.Addr()
	slog.InfoContext(ctx, "RESOLVE request", "from", conn.RemoteAddr(), "target", addr)

	if err := BaseOnResolve(ctx, conn, req, d.Dialer, d.ConnectDialTimeout, d.ConnectConnTimeout, d.ConnectBufferSize); err != nil {
		return fmt.Errorf("RESOLVE failed for %s: %w", addr, err)
	}

	slog.InfoContext(ctx, "RESOLVE completed", "from", conn.RemoteAddr(), "target", addr)
	return nil
}

func (d *BaseServerHandler) OnError(ctx context.Context, conn net.Conn, err error) {
	slog.ErrorContext(ctx, "error occurred", "error", err)
}

func (d *BaseServerHandler) OnPanic(ctx context.Context, conn net.Conn, r any) {
	slog.WarnContext(ctx, "panic occurred", "error", r)
}

// GetSupportedMethods returns the supported authentication methods.
func (d *BaseServerHandler) GetSupportedMethods() []byte {
	if d.SupportedMethods == nil {
		return []byte{MethodNoAuth}
	}
	return d.SupportedMethods
}

// BaseOnHandshake provides a default handshake implementation that selects the first matching authentication method.
func BaseOnHandshake(ctx context.Context, conn net.Conn, req *HandshakeRequest, supportedMethods []byte) (byte, error) {
	for _, clientMethod := range req.Methods {
		if slices.Contains(supportedMethods, clientMethod) {
			return clientMethod, nil
		}
	}

	return MethodNoAcceptable, fmt.Errorf(
		"no acceptable authentication methods: client=%v server=%v",
		req.Methods,
		supportedMethods,
	)
}

// BaseOnRequest provides request handling logic for CONNECT, BIND, UDP ASSOCIATE, and RESOLVE commands.
func BaseOnRequest(ctx context.Context, handler ServerHandler, conn net.Conn, req *Request) error {
	switch req.Command {
	case CmdConnect:
		return handler.OnConnect(ctx, conn, req)
	case CmdBind:
		return handler.OnBind(ctx, conn, req)
	case CmdUDPAssociate:
		return handler.OnUDPAssociate(ctx, conn, req)
	case CmdResolve:
		return handler.OnResolve(ctx, conn, req)
	default:
		writeReject(conn, RepCommandNotSupported)
		return fmt.Errorf("unsupported command: %d", req.Command)
	}
}

// BaseOnConnect provides CONNECT implementation
func BaseOnConnect(ctx context.Context, conn net.Conn, req *Request, dialer socksnet.Dialer, dialTimeout, connTimeout time.Duration, bufferSize int) error {
	if dialer == nil {
		dialer = socksnet.DefaultDialer
	}

	if dialTimeout > 0 {
		ctxDial, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()
		ctx = ctxDial
	}

	targetAddr := req.Addr()
	remote, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		// Determine appropriate SOCKS5 error code
		var code byte = RepGeneralFailure
		if ne, ok := err.(net.Error); ok {
			if ne.Timeout() {
				code = RepTTLExpired
			} else {
				code = RepConnectionRefused
			}
		}
		writeReject(conn, code)
		return fmt.Errorf("failed to connect to target %s: %w", targetAddr, err)
	}
	defer remote.Close()

	// Send success reply with bound address
	if err := WriteSuccessReply(conn, remote.LocalAddr()); err != nil {
		return fmt.Errorf("failed to write connect response: %w", err)
	}

	if bufferSize <= 0 {
		bufferSize = 1024 * 32
	}

	// Start bidirectional copying with coordinated error handling
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return socksnet.CopyConn(remote, conn, connTimeout, bufferSize)
	})

	g.Go(func() error {
		return socksnet.CopyConn(conn, remote, connTimeout, bufferSize)
	})

	return g.Wait()
}

// BaseOnBind provides BIND implementation
func BaseOnBind(ctx context.Context, conn net.Conn, req *Request, acceptTimeout, connTimeout time.Duration, bufferSize int) error {
	// Bind to any available port on all interfaces
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		writeReject(conn, RepGeneralFailure)
		return fmt.Errorf("failed to bind listening port: %w", err)
	}
	defer listener.Close()

	// Send first reply with bound address/port
	if err := WriteSuccessReply(conn, listener.Addr()); err != nil {
		return fmt.Errorf("failed to write bind response: %w", err)
	}

	// Set bind timeout for accepting incoming connection
	if acceptTimeout > 0 {
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(acceptTimeout))
	}

	// Wait for incoming connection
	incomingConn, err := listener.Accept()
	if err != nil {
		writeReject(conn, RepGeneralFailure)
		return fmt.Errorf("failed to accept incoming connection: %w", err)
	}
	defer incomingConn.Close()

	// Validate source address (if not 0.0.0.0/::)
	incomingAddr := incomingConn.RemoteAddr().(*net.TCPAddr)
	expectedIP := req.IP
	if expectedIP != nil && !expectedIP.IsUnspecified() && !expectedIP.Equal(incomingAddr.IP) {
		writeReject(conn, RepConnectionNotAllowed)
		return fmt.Errorf("incoming connection from %s, expected %s", incomingAddr.IP, expectedIP)
	}

	// Send second reply indicating successful connection
	if err := WriteSuccessReply(conn, incomingConn.RemoteAddr()); err != nil {
		return fmt.Errorf("failed to write connection response: %w", err)
	}

	if bufferSize <= 0 {
		bufferSize = 1024 * 32
	}

	// Start bidirectional copying with coordinated error handling
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return socksnet.CopyConn(incomingConn, conn, connTimeout, bufferSize)
	})

	g.Go(func() error {
		return socksnet.CopyConn(conn, incomingConn, connTimeout, bufferSize)
	})

	return g.Wait()
}

// WriteSuccessReply writes a SOCKS5 success reply with the given network address.
func WriteSuccessReply(conn net.Conn, addr net.Addr) error {
	var ip net.IP
	var port uint16
	var domain string
	var addrType byte

	// Extract IP and port, fallback to 0.0.0.0:0 if not TCP
	if addr == nil {
		ip = net.IPv4zero
		port = 0
	} else if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		ip = tcpAddr.IP
		port = uint16(tcpAddr.Port)
	} else {
		// Fallback for non-TCP addresses
		ip = net.IPv4zero
		port = 0
	}

	// Determine address type for response
	if ip.To4() != nil {
		addrType = AddrTypeIPv4
		ip = ip.To4()
	} else if ip.To16() != nil {
		addrType = AddrTypeIPv6
	} else {
		addrType = AddrTypeIPv4
		ip = net.IPv4zero
	}

	// Send success reply
	var resp Reply
	resp.Init(SocksVersion, RepSuccess, 0, addrType, ip, domain, port)
	_, err := resp.WriteTo(conn)
	return err
}

// BaseOnUDPAssociate provides UDP ASSOCIATE implementation
func BaseOnUDPAssociate(ctx context.Context, conn net.Conn, req *Request, timeout time.Duration, bufferSize int) error {
	return nil
}

// BaseOnResolve provides RESOLVE implementation
func BaseOnResolve(ctx context.Context, conn net.Conn, req *Request, dialer socksnet.Dialer, dialTimeout, connTimeout time.Duration, bufferSize int) error {
	return nil
}
