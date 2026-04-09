package socks4

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.org/x/sync/errgroup"

	socksnet "github.com/33TU/socks/net"
)

// BaseServerHandler provides a basic implementation of ServerHandler with configurable options.
type BaseServerHandler struct {
	Dialer             socksnet.Dialer
	RequestTimeout     time.Duration
	BindAcceptTimeout  time.Duration
	BindConnTimeout    time.Duration
	ConnectDialTimeout time.Duration
	ConnectConnTimeout time.Duration
	ConnectBufferSize  int
	AllowConnect       bool
	AllowBind          bool

	// UserIDChecker is a function that validates the user ID from the SOCKS4 request.
	// It should return an error if the user ID is not allowed, or nil to accept the request.
	// If nil, all user IDs will be accepted by default.
	UserIDChecker func(ctx context.Context, userID string) error
}

func (d *BaseServerHandler) OnAccept(ctx context.Context, conn net.Conn) error {
	slog.InfoContext(ctx, "accepted connection", "from", conn.RemoteAddr())

	if d.RequestTimeout != 0 {
		conn.SetDeadline(time.Now().Add(d.RequestTimeout))
	}
	return nil
}

func (d *BaseServerHandler) OnBind(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowBind {
		writeReject(conn, RepRejected)
		return fmt.Errorf("BIND command not allowed")
	}

	slog.InfoContext(ctx, "BIND request", "from", conn.RemoteAddr(), "target", req.Addr())

	err := BaseOnBind(ctx, conn, req, d.BindAcceptTimeout, d.BindConnTimeout, d.ConnectBufferSize)
	if err != nil {
		slog.ErrorContext(ctx, "BIND failed", "error", err)
		return err
	}

	slog.InfoContext(ctx, "BIND completed", "from", conn.RemoteAddr())
	return nil
}

func (d *BaseServerHandler) OnConnect(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowConnect {
		writeReject(conn, RepRejected)
		return fmt.Errorf("CONNECT command not allowed")
	}

	addr := req.Addr()
	slog.InfoContext(ctx, "CONNECT request", "from", conn.RemoteAddr(), "target", addr)

	err := BaseOnConnect(ctx, conn, req, d.Dialer, d.ConnectDialTimeout, d.ConnectConnTimeout, d.ConnectBufferSize)
	if err != nil {
		slog.ErrorContext(ctx, "CONNECT failed", "error", err, "target", addr)
		return err
	}

	slog.InfoContext(ctx, "CONNECT completed", "from", conn.RemoteAddr(), "target", addr)
	return nil
}

func (d *BaseServerHandler) OnError(ctx context.Context, conn net.Conn, err error) {
	slog.ErrorContext(ctx, "error occurred", "error", err)
}

func (d *BaseServerHandler) OnPanic(ctx context.Context, conn net.Conn, r any) {
	slog.WarnContext(ctx, "panic occurred", "error", r)
}

func (d *BaseServerHandler) OnUserID(ctx context.Context, conn net.Conn, userID string, hasUserID bool) error {
	slog.InfoContext(ctx, "validating user ID", "from", conn.RemoteAddr(), "user_id", userID, "has_user_id", hasUserID)

	if d.UserIDChecker != nil {
		return d.UserIDChecker(ctx, userID)
	}
	return nil // Allow all by default
}

func (d *BaseServerHandler) OnRequest(ctx context.Context, conn net.Conn, req *Request) error {
	slog.InfoContext(ctx, "received request", "from", conn.RemoteAddr(), "request", req)
	return BaseOnRequest(ctx, d, conn, req)
}

// BaseOnRequest provides request handling logic for both CONNECT and BIND commands.
func BaseOnRequest(ctx context.Context, handler ServerHandler, conn net.Conn, req *Request) error {
	switch req.Command {
	case CmdConnect:
		return handler.OnConnect(ctx, conn, req)
	case CmdBind:
		return handler.OnBind(ctx, conn, req)
	default:
		writeReject(conn, RepRejected)
		return fmt.Errorf("unknown command: %d", req.Command)
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

	remote, err := dialer.DialContext(ctx, "tcp", req.Addr())
	if err != nil {
		writeReject(conn, RepRejected)
		return fmt.Errorf("failed to connect to target: %w", err)
	}
	defer remote.Close()

	var resp Reply
	resp.Init(0, RepGranted, req.Port, req.IPv4())
	resp.WriteTo(conn)

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
		writeReject(conn, RepRejected)
		return fmt.Errorf("failed to bind listening port: %w", err)
	}
	defer listener.Close()

	// Get the bound address
	boundAddr := listener.Addr().(*net.TCPAddr)
	boundIP := boundAddr.IP.To4()
	if boundIP == nil {
		boundIP = net.IPv4zero // Fallback if not IPv4
	}

	// Send first reply with bound address/port
	var resp Reply
	resp.Init(0, RepGranted, uint16(boundAddr.Port), boundIP)
	if _, err := resp.WriteTo(conn); err != nil {
		return fmt.Errorf("failed to write bind response: %w", err)
	}

	// Set bind timeout for accepting incoming connection
	if acceptTimeout > 0 {
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(acceptTimeout))
	}

	// Wait for incoming connection
	incomingConn, err := listener.Accept()
	if err != nil {
		writeReject(conn, RepRejected)
		return fmt.Errorf("failed to accept incoming connection: %w", err)
	}
	defer incomingConn.Close()

	// Validate source address (if not 0.0.0.0)
	incomingAddr := incomingConn.RemoteAddr().(*net.TCPAddr)
	expectedIP := req.IPv4()
	if !expectedIP.Equal(net.IPv4zero) && !expectedIP.Equal(incomingAddr.IP) {
		writeReject(conn, RepRejected)
		return fmt.Errorf("incoming connection from %s, expected %s", incomingAddr.IP, expectedIP)
	}

	// Send second reply indicating successful connection
	var resp2 Reply
	incomingIP := incomingAddr.IP.To4()
	if incomingIP == nil {
		incomingIP = net.IPv4zero
	}
	resp2.Init(0, RepGranted, uint16(incomingAddr.Port), incomingIP)
	if _, err := resp2.WriteTo(conn); err != nil {
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
