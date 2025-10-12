package socks4

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// ListenerOptions defines behavior for a SOCKS4 listener.
// If a callback returns an error, the client connection is closed.
type ListenerOptions struct {
	// BaseDialer is used for dialing. (nil=DefaultDialer)
	BaseDialer *net.Dialer

	// RequestReadTimeout is the maximum duration to wait for a request.
	RequestReadTimeout time.Duration

	// OnAccept is called for each accepted connection.
	OnAccept func(ctx context.Context, opts *ListenerOptions, conn net.Conn) error

	// OnRequest is called for each request.
	// Default is to to invoke OnConnect or OnBind.
	// Unknown commands are rejected.
	OnRequest func(ctx context.Context, opts *ListenerOptions, conn net.Conn, req *Request) error

	// OnConnect is called for each CONNECT request.
	// Default is to handle the request.
	OnConnect func(ctx context.Context, opts *ListenerOptions, conn net.Conn, req *Request) error

	// OnBind is called for each BIND request.
	// Default is to reject the request.
	OnBind func(ctx context.Context, opts *ListenerOptions, conn net.Conn, req *Request) error

	// OnError is called for each connection error.
	OnError func(ctx context.Context, opts *ListenerOptions, conn net.Conn, err error)

	// Called when a panic occurs in any handler goroutine.
	// The recovered value is passed as 'r'.
	OnPanic func(ctx context.Context, opts *ListenerOptions, conn net.Conn, r any)
}

func OnAcceptDefault(ctx context.Context, opts *ListenerOptions, conn net.Conn) error {
	return nil // no-op
}

func OnRequestDefault(ctx context.Context, opts *ListenerOptions, conn net.Conn, req *Request) error {
	switch req.Command {
	case CmdConnect:
		return opts.OnConnect(ctx, opts, conn, req)
	case CmdBind:
		return opts.OnBind(ctx, opts, conn, req)
	default:
		var resp Response
		resp.Init(0, ReqRejected, 0, net.IPv4zero)
		resp.WriteTo(conn)
		return fmt.Errorf("unknown command: %d", req.Command)
	}
}

func OnConnectDefault(ctx context.Context, opts *ListenerOptions, conn net.Conn, req *Request) error {
	host := req.GetHost()
	port := req.Port
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))

	dialer := opts.BaseDialer
	if dialer == nil {
		dialer = DefaultDialer
	}

	target, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		var resp Response
		resp.Init(0, ReqRejected, req.Port, req.GetIP())
		resp.WriteTo(conn)
		return fmt.Errorf("connect to %s failed: %w", address, err)
	}
	defer target.Close()

	var resp Response
	resp.Init(0, ReqGranted, req.Port, req.GetIP())
	resp.WriteTo(conn)

	// Bidirectional copy
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, conn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(conn, target)
		errc <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		return err
	}
}

func OnBindDefault(ctx context.Context, opts *ListenerOptions, conn net.Conn, req *Request) error {
	var resp Response
	resp.Init(0, ReqRejected, 0, net.IPv4zero)
	resp.WriteTo(conn)
	return nil
}

func OnErrorDefault(ctx context.Context, opts *ListenerOptions, conn net.Conn, err error) {
	// no-op
}

func OnPanicDefault(ctx context.Context, opts *ListenerOptions, conn net.Conn, r any) {
	// no-op
}

// ServeContext runs a SOCKS4 listener loop until the context is canceled.
// Each accepted connection runs in its own goroutine.
func ServeContext(ctx context.Context, listener net.Listener, opts *ListenerOptions) error {
	// Ensure listener closes on context cancel
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	// Init defaults
	if opts.OnAccept == nil {
		opts.OnAccept = OnAcceptDefault
	}
	if opts.OnRequest == nil {
		opts.OnRequest = OnRequestDefault
	}
	if opts.OnConnect == nil {
		opts.OnConnect = OnConnectDefault
	}
	if opts.OnBind == nil {
		opts.OnBind = OnBindDefault
	}
	if opts.OnError == nil {
		opts.OnError = OnErrorDefault
	}
	if opts.OnPanic == nil {
		opts.OnPanic = OnPanicDefault
	}

	// Main loop
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				opts.OnError(ctx, opts, nil, err)
				continue
			}

			go func() {
				defer func() {
					if r := recover(); r != nil {
						opts.OnPanic(ctx, opts, conn, r)
					}
					conn.Close()
				}()

				// Accept
				if err := opts.OnAccept(ctx, opts, conn); err != nil {
					opts.OnError(ctx, opts, conn, err)
					return
				}

				// Read request
				var req Request
				reqTimeout := opts.RequestReadTimeout != 0

				if reqTimeout {
					conn.SetReadDeadline(time.Now().Add(opts.RequestReadTimeout))
				}
				if _, err := req.ReadFrom(conn); err != nil {
					opts.OnError(ctx, opts, conn, err)
					return
				}
				if reqTimeout {
					conn.SetReadDeadline(time.Time{})
				}

				// Handle request
				if err := opts.OnRequest(ctx, opts, conn, &req); err != nil {
					opts.OnError(ctx, opts, conn, err)
					return
				}
			}()
		}
	}
}

// Serve runs ServeContext with a background context.
func Serve(listener net.Listener, opts *ListenerOptions) error {
	return ServeContext(context.Background(), listener, opts)
}
