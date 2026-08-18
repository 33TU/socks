package shadowsocks

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	socksnet "github.com/33TU/socks/net"
)

// ServerCipher holds the crypto state a server uses to accept proxy connections.
type ServerCipher struct {
	Method Method
	PSK    []byte

	// Replay stores request salts seen within the replay window. It may be nil
	// to disable replay protection, which the protocol otherwise mandates.
	Replay *ReplayCache
}

// Validate checks whether the server cipher is internally valid.
func (c *ServerCipher) Validate() error {
	if c == nil {
		return fmt.Errorf("nil server cipher")
	}
	if err := c.Method.Validate(); err != nil {
		return err
	}
	if len(c.PSK) != c.Method.KeySize {
		return fmt.Errorf("invalid PSK length: got %d, want %d", len(c.PSK), c.Method.KeySize)
	}
	return nil
}

// NewServerCipher builds the server crypto state from a config.
func NewServerCipher(cfg *Config, replay *ReplayCache) (*ServerCipher, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	method, err := ParseMethod(cfg.Method)
	if err != nil {
		return nil, err
	}

	psk, err := DecodePSKTo(nil, method, cfg.PSK)
	if err != nil {
		return nil, err
	}

	return &ServerCipher{Method: method, PSK: psk, Replay: replay}, nil
}

// ServerHandler handles Shadowsocks server events.
type ServerHandler interface {
	// Cipher returns the crypto state used to accept proxy connections.
	Cipher(ctx context.Context) (*ServerCipher, error)

	// OnAccept is called for each accepted connection.
	OnAccept(ctx context.Context, conn net.Conn) error

	// OnRequest is called once a request stream has been accepted and validated.
	OnRequest(ctx context.Context, conn *TCPConn, req *ParsedTCPRequestStart) error

	// OnConnect is called to relay a request to its target.
	OnConnect(ctx context.Context, conn *TCPConn, req *ParsedTCPRequestStart) error

	// OnHeaderError is called when a request stream fails to decrypt or validate.
	//
	// Implementations MUST NOT close the connection right away: closing a socket
	// with unread data sends an RST that reveals exactly how many bytes the
	// server consumed, which lets a prober fingerprint the protocol. Use
	// DrainConn, or an equivalent strategy, before returning.
	OnHeaderError(ctx context.Context, conn net.Conn, err error)

	// OnClose is called when the connection lifecycle ends.
	// errCause is the reason the connection ended, if any.
	OnClose(ctx context.Context, conn net.Conn, errCause error)

	// OnError is called for each connection error.
	OnError(ctx context.Context, conn net.Conn, err error)

	// OnPanic is called when a panic occurs in any handler goroutine.
	OnPanic(ctx context.Context, conn net.Conn, r any)
}

// Serve accepts incoming connections on the listener and serves Shadowsocks requests.
//
// It returns when ctx is done or the listener fails permanently. Recoverable
// accept errors are retried with a backoff rather than spun on.
func Serve(ctx context.Context, listener net.Listener, handler ServerHandler) error {
	if handler == nil {
		return fmt.Errorf("nil handler provided")
	}

	return socksnet.AcceptLoop(ctx, listener,
		func(err error) { handler.OnError(ctx, nil, err) },
		func(conn net.Conn) { go ServeConn(ctx, handler, conn) },
	)
}

// ListenAndServe listens on the network address and serves Shadowsocks requests.
func ListenAndServe(ctx context.Context, network, address string, handler ServerHandler) error {
	ln, err := net.Listen(network, address)
	if err != nil {
		return err
	}

	return Serve(ctx, ln, handler)
}

// ServeConn handles a single client connection, including the request stream
// startup and relaying to the target.
func ServeConn(ctx context.Context, handler ServerHandler, conn net.Conn) (err error) {
	if handler == nil {
		return fmt.Errorf("nil handler provided")
	}

	defer func() {
		if r := recover(); r != nil {
			handler.OnPanic(ctx, conn, r)
		}

		handler.OnClose(ctx, conn, err)
		_ = conn.Close()
	}()

	if err = handler.OnAccept(ctx, conn); err != nil {
		handler.OnError(ctx, conn, err)
		return err
	}

	var cipher *ServerCipher
	if cipher, err = handler.Cipher(ctx); err != nil {
		handler.OnError(ctx, conn, err)
		return err
	}
	if err = cipher.Validate(); err != nil {
		handler.OnError(ctx, conn, err)
		return err
	}

	ssConn, req, err := NewServerTCPConn(conn, cipher.Method, cipher.PSK, time.Now(), cipher.Replay)
	if err != nil {
		// Any failure here must look identical from the outside, whatever the
		// cause and however many bytes were consumed.
		handler.OnHeaderError(ctx, conn, err)
		handler.OnError(ctx, conn, err)
		return err
	}

	if err = handler.OnRequest(ctx, ssConn, req); err != nil {
		handler.OnError(ctx, conn, err)
		return err
	}

	return nil
}

// DrainConn hides how many bytes a server consumed before rejecting a request.
//
// The write half is shut down first, so a FIN is sent even when unread data is
// pending, and the connection is then drained until EOF, limit, or timeout.
// Closing a socket with unread data would instead send an RST, revealing the
// exact number of bytes consumed to a prober sending one byte at a time.
//
// A non-positive limit drains until EOF or timeout.
func DrainConn(conn net.Conn, timeout time.Duration, limit int64) error {
	if conn == nil {
		return nil
	}

	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	if cw, ok := conn.(socksnet.CloseWriter); ok {
		_ = cw.CloseWrite()
	}

	var src io.Reader = conn
	if limit > 0 {
		src = io.LimitReader(conn, limit)
	}

	_, err := io.Copy(io.Discard, src)
	return err
}
