package shadowsocks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	socksnet "github.com/33TU/socks/net"
	"golang.org/x/sync/errgroup"
)

// Default limits applied by BaseServerHandler when left unset.
const (
	DefaultDrainTimeout = 30 * time.Second
	DefaultDrainLimit   = 64 * 1024
)

// BaseServerHandler provides a basic implementation of ServerHandler with configurable options.
type BaseServerHandler struct {
	// Config is the server's method and PSK. It is required.
	Config *Config

	// Dialer establishes connections to request targets.
	Dialer socksnet.Dialer

	// ReplayCache stores request salts for the replay window.
	// When nil, a cache is created on first use.
	ReplayCache *ReplayCache

	RequestTimeout     time.Duration
	ConnectConnTimeout time.Duration
	ConnectBufferSize  int
	AllowConnect       bool

	// DrainTimeout and DrainLimit bound how long, and how much, a rejected
	// connection is drained for. Zero means DefaultDrainTimeout/DefaultDrainLimit.
	DrainTimeout time.Duration
	DrainLimit   int64

	cipherOnce sync.Once
	cipher     *ServerCipher
	cipherErr  error
}

// Cipher returns the server crypto state, building it from Config on first use.
func (d *BaseServerHandler) Cipher(ctx context.Context) (*ServerCipher, error) {
	d.cipherOnce.Do(func() {
		replay := d.ReplayCache
		if replay == nil {
			replay = NewReplayCache()
		}
		d.cipher, d.cipherErr = NewServerCipher(d.Config, replay)
	})

	return d.cipher, d.cipherErr
}

func (d *BaseServerHandler) OnAccept(ctx context.Context, conn net.Conn) error {
	slog.InfoContext(ctx, "accepted connection", "from", conn.RemoteAddr())

	if d.RequestTimeout != 0 {
		conn.SetDeadline(time.Now().Add(d.RequestTimeout))
	}
	return nil
}

func (d *BaseServerHandler) OnRequest(ctx context.Context, conn *TCPConn, req *ParsedTCPRequestStart) error {
	// The request deadline covers the header only; the relay uses its own.
	if d.RequestTimeout != 0 {
		conn.SetDeadline(time.Time{})
	}

	err := BaseOnRequest(ctx, d, conn, req)
	if err != nil {
		slog.ErrorContext(ctx, "request handling failed", "error", err, "from", conn.RemoteAddr(), "target", req.Header.Target.Addr())
	}
	return err
}

func (d *BaseServerHandler) OnConnect(ctx context.Context, conn *TCPConn, req *ParsedTCPRequestStart) error {
	if !d.AllowConnect {
		return fmt.Errorf("CONNECT not allowed")
	}

	addr := req.Header.Target.Addr()
	slog.InfoContext(ctx, "CONNECT request", "from", conn.RemoteAddr(), "target", addr)

	if err := BaseOnConnect(ctx, conn, req, d.Dialer, d.ConnectConnTimeout, d.ConnectBufferSize); isUnexpectedNetErr(err) {
		return fmt.Errorf("CONNECT failed to %s: %w", addr, err)
	}

	slog.InfoContext(ctx, "CONNECT completed", "from", conn.RemoteAddr(), "target", addr)
	return nil
}

func (d *BaseServerHandler) OnHeaderError(ctx context.Context, conn net.Conn, err error) {
	slog.WarnContext(ctx, "rejecting connection", "from", conn.RemoteAddr(), "error", err)

	timeout := d.DrainTimeout
	if timeout == 0 {
		timeout = DefaultDrainTimeout
	}

	limit := d.DrainLimit
	if limit == 0 {
		limit = DefaultDrainLimit
	}

	_ = DrainConn(conn, timeout, limit)
}

func (d *BaseServerHandler) OnClose(ctx context.Context, conn net.Conn, errCause error) {
	slog.InfoContext(ctx, "connection closed", "from", conn.RemoteAddr(), "error", errCause)
}

func (d *BaseServerHandler) OnError(ctx context.Context, conn net.Conn, err error) {
	slog.ErrorContext(ctx, "error occurred", "error", err)
}

func (d *BaseServerHandler) OnPanic(ctx context.Context, conn net.Conn, r any) {
	slog.WarnContext(ctx, "panic occurred", "error", r)
}

// BaseOnRequest dispatches an accepted request stream to the target.
func BaseOnRequest(ctx context.Context, handler ServerHandler, conn *TCPConn, req *ParsedTCPRequestStart) error {
	return handler.OnConnect(ctx, conn, req)
}

// BaseOnConnect relays a request stream to its target address.
func BaseOnConnect(
	ctx context.Context,
	conn *TCPConn,
	req *ParsedTCPRequestStart,
	dialer socksnet.Dialer,
	connTimeout time.Duration,
	bufferSize int,
) error {
	if dialer == nil {
		dialer = socksnet.DefaultDialer
	}

	targetAddr := req.Header.Target.Addr()
	remote, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to target %s: %w", targetAddr, err)
	}
	defer remote.Close()

	// The initial payload from the request header is buffered in the reader, so
	// both directions are plain copies from here on. No reply is sent to the
	// client: the response stream starts with the target's first payload.
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return socksnet.CopyConn(remote, conn, connTimeout, bufferSize)
	})

	g.Go(func() error {
		return socksnet.CopyConn(conn, remote, connTimeout, bufferSize)
	})

	return g.Wait()
}

// isUnexpectedNetErr checks if an error is a network error that is not EOF or ErrClosed
func isUnexpectedNetErr(err error) bool {
	return err != nil &&
		!errors.Is(err, io.EOF) &&
		!errors.Is(err, net.ErrClosed)
}

var _ ServerHandler = (*BaseServerHandler)(nil)
