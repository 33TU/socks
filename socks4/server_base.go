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

	UserIDChecker func(userID string) bool // Optional user ID validation function
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
		var resp Reply
		resp.Init(0, RepRejected, 0, net.IPv4zero)
		resp.WriteTo(conn)
		return fmt.Errorf("BIND command not allowed")
	}

	// Clear the deadline set by OnAccept
	conn.SetDeadline(time.Time{})

	// For BIND, we need to listen on a port and wait for incoming connections
	// Bind to any available port on all interfaces
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		var resp Reply
		resp.Init(0, RepRejected, 0, net.IPv4zero)
		resp.WriteTo(conn)
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

	slog.InfoContext(ctx, "BIND listening", "bound_addr", boundAddr, "expecting_from", req.GetAddr())

	// Set bind timeout for accepting incoming connection
	if d.BindAcceptTimeout > 0 {
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(d.BindAcceptTimeout))
	}

	// Wait for incoming connection
	incomingConn, err := listener.Accept()
	if err != nil {
		var resp Reply
		resp.Init(0, RepRejected, 0, net.IPv4zero)
		resp.WriteTo(conn)
		return fmt.Errorf("failed to accept incoming connection: %w", err)
	}
	defer incomingConn.Close()

	// Validate source address (if not 0.0.0.0)
	incomingAddr := incomingConn.RemoteAddr().(*net.TCPAddr)
	expectedIP := req.GetIP()
	if !expectedIP.Equal(net.IPv4zero) && !expectedIP.Equal(incomingAddr.IP) {
		var resp Reply
		resp.Init(0, RepRejected, 0, net.IPv4zero)
		resp.WriteTo(conn)
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

	slog.InfoContext(ctx, "BIND connection established", "from", incomingAddr)

	// Clear deadline for data transfer
	conn.SetDeadline(time.Time{})

	bufSize := d.ConnectBufferSize
	if bufSize <= 0 {
		bufSize = 1024 * 32
	}

	// Start bidirectional copying with coordinated error handling
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := socksnet.CopyConn(incomingConn, conn, d.BindConnTimeout, bufSize); err != nil {
			slog.ErrorContext(ctx, "error copying from client to incoming", "error", err)
			return err
		}
		return nil
	})

	g.Go(func() error {
		if err := socksnet.CopyConn(conn, incomingConn, d.BindConnTimeout, bufSize); err != nil {
			slog.ErrorContext(ctx, "error copying from incoming to client", "error", err)
			return err
		}
		return nil
	})

	return g.Wait()
}

func (d *BaseServerHandler) OnConnect(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowConnect {
		var resp Reply
		resp.Init(0, RepRejected, 0, net.IPv4zero)
		resp.WriteTo(conn)
		return fmt.Errorf("CONNECT command not allowed")
	}

	// Clear the deadline set by OnAccept
	conn.SetDeadline(time.Time{})

	dialer := d.Dialer
	if dialer == nil {
		dialer = socksnet.DefaultDialer
	}

	if d.ConnectDialTimeout > 0 {
		ctxDial, cancel := context.WithTimeout(ctx, d.ConnectDialTimeout)
		defer cancel()
		ctx = ctxDial
	}

	remote, err := dialer.DialContext(ctx, "tcp", req.GetAddr())
	if err != nil {
		var resp Reply
		resp.Init(0, RepRejected, 0, net.IPv4zero)
		resp.WriteTo(conn)
		return fmt.Errorf("failed to connect to target: %w", err)
	}
	defer remote.Close()

	var resp Reply
	resp.Init(0, RepGranted, req.Port, req.GetIP())
	resp.WriteTo(conn)

	bufSize := d.ConnectBufferSize
	if bufSize <= 0 {
		bufSize = 1024 * 32
	}

	// Start bidirectional copying with coordinated error handling
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := socksnet.CopyConn(remote, conn, d.ConnectConnTimeout, bufSize); err != nil {
			slog.ErrorContext(ctx, "error copying from client to remote", "error", err)
			return err
		}
		return nil
	})

	g.Go(func() error {
		if err := socksnet.CopyConn(conn, remote, d.ConnectConnTimeout, bufSize); err != nil {
			slog.ErrorContext(ctx, "error copying from remote to client", "error", err)
			return err
		}
		return nil
	})

	return g.Wait()
}

func (d *BaseServerHandler) OnError(ctx context.Context, conn net.Conn, err error) {
	slog.ErrorContext(ctx, "error occurred", "error", err)
}

func (d *BaseServerHandler) OnPanic(ctx context.Context, conn net.Conn, r any) {
	slog.WarnContext(ctx, "panic occurred", "error", r)
}

func (d *BaseServerHandler) OnRequest(ctx context.Context, conn net.Conn, req *Request) error {
	slog.InfoContext(ctx, "received request", "from", conn.RemoteAddr(), "request", req)

	// Check user ID if validator is provided
	if d.UserIDChecker != nil && !d.UserIDChecker(req.UserID) {
		var resp Reply
		resp.Init(0, RepRejected, 0, net.IPv4zero)
		resp.WriteTo(conn)
		return fmt.Errorf("user ID not allowed: %q", req.UserID)
	}

	switch req.Command {
	case CmdConnect:
		return d.OnConnect(ctx, conn, req)
	case CmdBind:
		return d.OnBind(ctx, conn, req)
	default:
		var resp Reply
		resp.Init(0, RepRejected, 0, net.IPv4zero)
		resp.WriteTo(conn)
		return fmt.Errorf("unknown command: %d", req.Command)
	}
}
