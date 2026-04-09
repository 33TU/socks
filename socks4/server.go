package socks4

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/33TU/socks/internal"
)

// DefaultServerHandler is a default implementation used when no custom ServerHandler is provided to Serve or ListenAndServe.
var DefaultServerHandler ServerHandler = &BaseServerHandler{
	RequestTimeout:     10 * time.Second,
	BindAcceptTimeout:  10 * time.Second,
	BindConnTimeout:    60 * time.Second,
	ConnectDialTimeout: 10 * time.Second,
	ConnectConnTimeout: 60 * time.Second,
	ConnectBufferSize:  1024 * 32,
	AllowConnect:       true,
	AllowBind:          false,
}

// ServerHandler handles SOCKS4 server events.
type ServerHandler interface {
	// OnAccept is called for each accepted connection.
	OnAccept(ctx context.Context, conn net.Conn) error

	// OnUserID is called to validate the user ID from the SOCKS4 request.
	OnUserID(ctx context.Context, conn net.Conn, userID string, hasUserID bool) error

	// OnRequest is called for each request.
	OnRequest(ctx context.Context, conn net.Conn, req *Request) error

	// OnConnect is called for each CONNECT request.
	OnConnect(ctx context.Context, conn net.Conn, req *Request) error

	// OnBind is called for each BIND request.
	OnBind(ctx context.Context, conn net.Conn, req *Request) error

	// OnError is called for each connection error.
	OnError(ctx context.Context, conn net.Conn, err error)

	// OnPanic is called when a panic occurs in any handler goroutine.
	OnPanic(ctx context.Context, conn net.Conn, r any)
}

// Serve accepts incoming connections on the listener and serves SOCKS4 requests.
func Serve(ctx context.Context, listener net.Listener, handler ServerHandler) error {
	if handler == nil {
		handler = DefaultServerHandler
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				handler.OnError(ctx, nil, err)
				continue
			}

			go serveConn(ctx, handler, conn)
		}
	}
}

// ListenAndServe listens on the network address and serves SOCKS4 requests.
func ListenAndServe(ctx context.Context, network, address string, handler ServerHandler) error {
	ln, err := net.Listen(network, address)
	if err != nil {
		return err
	}

	return Serve(ctx, ln, handler)
}

// serveConn handles a single client connection, including reading the request and processing it.
func serveConn(ctx context.Context, handler ServerHandler, conn net.Conn) {
	defer conn.Close()

	defer func() {
		if r := recover(); r != nil {
			handler.OnPanic(ctx, conn, r)
		}
	}()

	// OnAccept callback
	if err := handler.OnAccept(ctx, conn); err != nil {
		handler.OnError(ctx, conn, err)
		return
	}

	// Use reused reader to reduce allocations
	reader := internal.GetReader(conn)
	released := false

	release := func() {
		if released {
			return
		}

		released = true
		internal.PutReader(reader)
	}
	defer release()

	// Read SOCKS4 request using pooled reader
	var req Request
	if _, err := req.ReadFrom(reader); err != nil {
		writeReject(conn, RepRejected)
		handler.OnError(ctx, conn, err)
		return
	}

	// Validate user ID
	if err := handler.OnUserID(ctx, conn, req.UserID, len(req.UserID) > 0); err != nil {
		writeReject(conn, RepRejected)
		handler.OnError(ctx, conn, fmt.Errorf("user ID validation failed: %w", err))
		return
	}

	// Release resources used for io
	release()

	// Handle the request
	if err := handler.OnRequest(ctx, conn, &req); err != nil {
		handler.OnError(ctx, conn, err)
		return
	}
}

// writeReject sends a SOCKS4 reply with the given rejection code.
func writeReject(conn net.Conn, code byte) {
	var resp Reply
	resp.Init(0, code, 0, net.IPv4zero)
	resp.WriteTo(conn)
}
