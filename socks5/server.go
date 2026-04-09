package socks5

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/33TU/socks/internal"
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
	OnHandshake(ctx context.Context, conn net.Conn, req *HandshakeRequest) (selectedMethod byte, err error)

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

	// OnAccept callback
	if err := handler.OnAccept(ctx, conn); err != nil {
		handler.OnError(ctx, conn, err)
		return
	}

	// Use reused reader/writer to reduce allocations
	reader := internal.GetReader(conn)
	writer := internal.GetWriter(conn)
	released := false

	release := func() {
		if released {
			return
		}

		released = true
		internal.PutReader(reader)
		internal.PutWriter(writer)
	}
	defer release()

	// Phase 1: Handshake (method negotiation)
	var handshakeReq HandshakeRequest
	if _, err := handshakeReq.ReadFrom(reader); err != nil {
		handler.OnError(ctx, conn, err)
		return
	}

	selectedMethod, err := handler.OnHandshake(ctx, conn, &handshakeReq)
	if err != nil {
		// Send "No acceptable methods" reply
		var handshakeReply HandshakeReply
		handshakeReply.Init(SocksVersion, MethodNoAcceptable)
		handshakeReply.WriteTo(writer)
		handler.OnError(ctx, conn, err)
		return
	}

	// Send handshake reply
	var handshakeReply HandshakeReply
	handshakeReply.Init(SocksVersion, selectedMethod)
	if _, err := handshakeReply.WriteTo(writer); err != nil {
		handler.OnError(ctx, conn, err)
		return
	}

	if selectedMethod == MethodNoAcceptable {
		handler.OnError(ctx, conn, fmt.Errorf("no acceptable authentication methods"))
		return
	}

	// Phase 2: Authentication (if required)
	switch selectedMethod {
	case MethodNoAuth:
		// No authentication required, proceed to request phase
	case MethodUserPass:
		if err := handleUserPassAuth(ctx, handler, conn, reader, writer); err != nil {
			handler.OnError(ctx, conn, err)
			return
		}
	case MethodGSSAPI:
		if err := handleGSSAPIAuth(ctx, handler, conn, reader, writer); err != nil {
			handler.OnError(ctx, conn, err)
			return
		}
	default:
		handler.OnError(ctx, conn, fmt.Errorf("unsupported authentication method: %d", selectedMethod))
		return
	}

	// Phase 3: Request processing
	var req Request
	if _, err := req.ReadFrom(reader); err != nil {
		handler.OnError(ctx, conn, err)
		return
	}

	// Release reader/writer resources before handling request
	release()

	// Handle the request through the handler
	if err := handler.OnRequest(ctx, conn, &req); err != nil {
		handler.OnError(ctx, conn, err)
		return
	}
}

// handleUserPassAuth handles username/password authentication.
func handleUserPassAuth(ctx context.Context, handler ServerHandler, conn net.Conn, reader *bufio.Reader, writer *bufio.Writer) error {
	var userPassReq UserPassRequest
	if _, err := userPassReq.ReadFrom(reader); err != nil {
		return err
	}

	err := handler.OnAuthUserPass(ctx, conn, userPassReq.Username, userPassReq.Password)
	var status byte = UserPassStatusSuccess
	if err != nil {
		status = UserPassStatusFailure
	}

	var userPassReply UserPassReply
	userPassReply.Init(AuthVersionUserPass, status)
	if _, err := userPassReply.WriteTo(writer); err != nil {
		return err
	}

	if status != UserPassStatusSuccess {
		return fmt.Errorf("username/password authentication failed: %w", err)
	}

	return nil
}

// handleGSSAPIAuth handles GSSAPI authentication.
func handleGSSAPIAuth(ctx context.Context, handler ServerHandler, conn net.Conn, reader *bufio.Reader, writer *bufio.Writer) error {
	// GSSAPI authentication can involve multiple round-trips
	for {
		var gssapiReq GSSAPIRequest
		if _, err := gssapiReq.ReadFrom(reader); err != nil {
			return err
		}

		// Check for abort message
		if gssapiReq.MsgType == GSSAPITypeAbort {
			return fmt.Errorf("GSSAPI authentication aborted by client")
		}

		responseToken, err := handler.OnAuthGSSAPI(ctx, conn, gssapiReq.Token)
		var msgType byte = GSSAPITypeReply
		if err != nil {
			msgType = GSSAPITypeAbort
		}

		var gssapiReply GSSAPIReply
		gssapiReply.Init(GSSAPIVersion, msgType, responseToken)
		if _, err := gssapiReply.WriteTo(writer); err != nil {
			return err
		}

		if msgType == GSSAPITypeAbort {
			return fmt.Errorf("GSSAPI authentication failed: %w", err)
		}

		// If no response token, authentication is complete
		if len(responseToken) == 0 {
			break
		}
	}

	return nil
}

// writeReject sends a SOCKS5 reply with the given rejection code.
func writeReject(conn net.Conn, code byte) {
	var resp Reply
	resp.Init(SocksVersion, code, 0, AddrTypeIPv4, net.IPv4zero, "", 0)
	resp.WriteTo(conn)
}
