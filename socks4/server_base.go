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
		WriteRejectReply(conn, RepRejected)
		return fmt.Errorf("BIND command not allowed")
	}

	slog.InfoContext(ctx, "BIND request", "from", conn.RemoteAddr(), "target", req.Addr())

	if err := BaseOnBind(ctx, conn, req, d.BindAcceptTimeout, d.BindConnTimeout, d.ConnectBufferSize); err != nil {
		return fmt.Errorf("BIND failed: %w", err)
	}

	slog.InfoContext(ctx, "BIND completed", "from", conn.RemoteAddr())
	return nil
}

func (d *BaseServerHandler) OnConnect(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowConnect {
		WriteRejectReply(conn, RepRejected)
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
	err := BaseOnRequest(ctx, d, conn, req)
	if err != nil {
		slog.ErrorContext(ctx, "request handling failed", "error", err, "from", conn.RemoteAddr(), "request", req)
	}
	return err
}

// BaseOnRequest provides request handling logic for both CONNECT and BIND commands.
func BaseOnRequest(ctx context.Context, handler ServerHandler, conn net.Conn, req *Request) error {
	switch req.Command {
	case CmdConnect:
		return handler.OnConnect(ctx, conn, req)
	case CmdBind:
		return handler.OnBind(ctx, conn, req)
	default:
		WriteRejectReply(conn, RepRejected)
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
		WriteRejectReply(conn, RepRejected)
		return fmt.Errorf("failed to connect to target: %w", err)
	}
	defer remote.Close()

	// Send success reply
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
		WriteRejectReply(conn, RepRejected)
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
		WriteRejectReply(conn, RepRejected)
		return fmt.Errorf("failed to accept incoming connection: %w", err)
	}
	defer incomingConn.Close()

	// Validate source address (if not 0.0.0.0)
	incomingAddr := incomingConn.RemoteAddr().(*net.TCPAddr)
	expectedIP := req.IPv4()
	if !expectedIP.Equal(net.IPv4zero) && !expectedIP.Equal(incomingAddr.IP) {
		WriteRejectReply(conn, RepRejected)
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
