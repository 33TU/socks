package socks5

import (
	"bufio"
	"context"
	"net"
	"time"
)

// DefaultServerHandler is a default implementation used when no custom ServerHandler is provided to Serve or ListenAndServe.
var DefaultServerHandler ServerHandler = &BaseServerHandler{
	RequestTimeout:        10 * time.Second,
	BindAcceptTimeout:     10 * time.Second,
	BindConnTimeout:       60 * time.Second,
	ConnectDialTimeout:    10 * time.Second,
	ConnectConnTimeout:    60 * time.Second,
	UDPAssociateTimeout:   300 * time.Second,
	ConnectBufferSize:     1024 * 32,
	AllowConnect:          true,
	AllowBind:             false,
	AllowUDPAssociate:     false,
	SupportedMethods:      []byte{MethodNoAuth},
	UserPassAuthenticator: nil,
	GSSAPIAuthenticator:   nil,
}

// ServerHandler handles SOCKS5 server events.
type ServerHandler interface {
	// OnAccept is called for each accepted connection.
	OnAccept(ctx context.Context, conn net.Conn) error

	// OnHandshake is called during method negotiation phase.
	OnHandshake(ctx context.Context, conn net.Conn, req *HandshakeRequest) error

	// OnAuthUserPass is called for username/password authentication.
	OnAuthUserPass(ctx context.Context, conn net.Conn, username, password string) error

	// OnAuthGSSAPI is called for GSSAPI authentication.
	OnAuthGSSAPI(ctx context.Context, conn net.Conn, token []byte) ([]byte, error)

	// OnRequest is called for each SOCKS5 request after successful handshake/auth.
	OnRequest(ctx context.Context, conn net.Conn, req *Request) error

	// OnConnect is called for each CONNECT request.
	OnConnect(ctx context.Context, conn net.Conn, req *Request) error

	// OnBind is called for each BIND request.
	OnBind(ctx context.Context, conn net.Conn, req *Request) error

	// OnUDPAssociate is called for each UDP ASSOCIATE request.
	OnUDPAssociate(ctx context.Context, conn net.Conn, req *Request) error

	// OnResolve is called for each RESOLVE request.
	OnResolve(ctx context.Context, conn net.Conn, req *Request) error

	// OnError is called for each connection error.
	OnError(ctx context.Context, conn net.Conn, err error)

	// OnPanic is called when a panic occurs in any handler goroutine.
	OnPanic(ctx context.Context, conn net.Conn, r any)
}

// Serve accepts incoming connections on the listener and serves SOCKS5 requests.
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

// ListenAndServe listens on the network address and serves SOCKS5 requests.
func ListenAndServe(ctx context.Context, network, address string, handler ServerHandler) error {
	ln, err := net.Listen(network, address)
	if err != nil {
		return err
	}

	return Serve(ctx, ln, handler)
}

// serveConn handles a single client connection, including handshake, authentication, and request processing.
func serveConn(ctx context.Context, handler ServerHandler, conn net.Conn) {
	defer conn.Close()

	defer func() {
		if r := recover(); r != nil {
			handler.OnPanic(ctx, conn, r)
		}
	}()

}

// handleHandshake handles the SOCKS5 method negotiation phase and returns the chosen method.
func handleHandshake(ctx context.Context, handler ServerHandler, conn net.Conn, reader *bufio.Reader, writer *bufio.Writer) error {
	return nil
}

// handleAuthentication handles authentication sub-negotiation based on the chosen method.
func handleAuthentication(ctx context.Context, handler ServerHandler, conn net.Conn, method byte, reader *bufio.Reader, writer *bufio.Writer) error {
	return nil
}

// handleUserPassAuth handles username/password authentication.
func handleUserPassAuth(ctx context.Context, handler ServerHandler, conn net.Conn, reader *bufio.Reader, writer *bufio.Writer) error {
	return nil
}

// handleGSSAPIAuth handles GSSAPI authentication.
func handleGSSAPIAuth(ctx context.Context, handler ServerHandler, conn net.Conn, reader *bufio.Reader, writer *bufio.Writer) error {
	return nil
}

// handleRequest handles the actual SOCKS5 request after successful handshake.
func handleRequest(ctx context.Context, handler ServerHandler, conn net.Conn, reader *bufio.Reader) error {
	return nil
}

// writeReject sends a SOCKS5 reply with the given rejection code.
func writeReject(conn net.Conn, code byte) {
	var resp Reply
	resp.Init(SocksVersion, code, 0, AddrTypeIPv4, net.IPv4zero, "", 0)
	resp.WriteTo(conn)
}
