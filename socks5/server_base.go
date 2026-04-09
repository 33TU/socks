package socks5

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	socksnet "github.com/33TU/socks/net"
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
	GSSAPIAuthenticator   func(ctx context.Context, token []byte) ([]byte, error)
}

func (d *BaseServerHandler) OnAccept(ctx context.Context, conn net.Conn) error {
	slog.InfoContext(ctx, "accepted connection", "from", conn.RemoteAddr())

	if d.RequestTimeout != 0 {
		conn.SetDeadline(time.Now().Add(d.RequestTimeout))
	}
	return nil
}

func (d *BaseServerHandler) OnHandshake(ctx context.Context, conn net.Conn, req *HandshakeRequest) error {
	slog.InfoContext(ctx, "handshake request", "from", conn.RemoteAddr(), "methods", req.Methods)

	err := BaseOnHandshake(ctx, conn, req, d)
	if err != nil {
		slog.ErrorContext(ctx, "handshake failed", "error", err)
		return err
	}

	slog.InfoContext(ctx, "handshake completed", "from", conn.RemoteAddr())
	return nil
}

func (d *BaseServerHandler) OnAuthUserPass(ctx context.Context, conn net.Conn, username, password string) error {
	slog.InfoContext(ctx, "validating username/password", "from", conn.RemoteAddr(), "username", username)

	if d.UserPassAuthenticator != nil {
		return d.UserPassAuthenticator(ctx, username, password)
	}
	return nil // Allow all by default
}

func (d *BaseServerHandler) OnAuthGSSAPI(ctx context.Context, conn net.Conn, token []byte) ([]byte, error) {
	slog.InfoContext(ctx, "validating GSSAPI token", "from", conn.RemoteAddr())

	if d.GSSAPIAuthenticator != nil {
		return d.GSSAPIAuthenticator(ctx, token)
	}
	return nil, nil // Allow all by default
}

func (d *BaseServerHandler) OnRequest(ctx context.Context, conn net.Conn, req *Request) error {
	slog.InfoContext(ctx, "received request", "from", conn.RemoteAddr(), "request", req)
	return BaseOnRequest(ctx, d, conn, req)
}

func (d *BaseServerHandler) OnConnect(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowConnect {
		writeReject(conn, RepConnectionNotAllowed)
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

func (d *BaseServerHandler) OnBind(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowBind {
		writeReject(conn, RepConnectionNotAllowed)
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

func (d *BaseServerHandler) OnUDPAssociate(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowUDPAssociate {
		writeReject(conn, RepConnectionNotAllowed)
		return fmt.Errorf("UDP ASSOCIATE command not allowed")
	}

	addr := req.Addr()
	slog.InfoContext(ctx, "UDP ASSOCIATE request", "from", conn.RemoteAddr(), "target", addr)

	err := BaseOnUDPAssociate(ctx, conn, req, d.UDPAssociateTimeout, d.ConnectBufferSize)
	if err != nil {
		slog.ErrorContext(ctx, "UDP ASSOCIATE failed", "error", err, "target", addr)
		return err
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

	err := BaseOnResolve(ctx, conn, req, d.Dialer, d.ConnectDialTimeout, d.ConnectConnTimeout, d.ConnectBufferSize)
	if err != nil {
		slog.ErrorContext(ctx, "RESOLVE failed", "error", err, "target", addr)
		return err
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

// BaseOnHandshake provides a default handshake implementation that does nothing and allows all methods.
func BaseOnHandshake(ctx context.Context, conn net.Conn, req *HandshakeRequest, handler ServerHandler) error {
	return nil
}

// BaseOnRequest provides request handling logic for CONNECT, BIND, and UDP ASSOCIATE commands.
func BaseOnRequest(ctx context.Context, handler ServerHandler, conn net.Conn, req *Request) error {
	return nil
}

// BaseOnConnect provides CONNECT implementation
func BaseOnConnect(ctx context.Context, conn net.Conn, req *Request, dialer socksnet.Dialer, dialTimeout, connTimeout time.Duration, bufferSize int) error {
	return nil
}

// BaseOnBind provides BIND implementation
func BaseOnBind(ctx context.Context, conn net.Conn, req *Request, acceptTimeout, connTimeout time.Duration, bufferSize int) error {
	return nil
}

// BaseOnUDPAssociate provides UDP ASSOCIATE implementation
func BaseOnUDPAssociate(ctx context.Context, conn net.Conn, req *Request, timeout time.Duration, bufferSize int) error {
	return nil
}

// BaseOnResolve provides RESOLVE implementation
func BaseOnResolve(ctx context.Context, conn net.Conn, req *Request, dialer socksnet.Dialer, dialTimeout, connTimeout time.Duration, bufferSize int) error {
	return nil
}
