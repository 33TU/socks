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
	OnAuthGSSAPI(ctx context.Context, conn net.Conn, token []byte) (resp []byte, done bool, err error)

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

			go ServeConn(ctx, handler, conn)
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

// ServeConn handles a single client connection, including handshake, authentication, and request processing.
func ServeConn(ctx context.Context, handler ServerHandler, conn net.Conn) error {
	defer conn.Close()

	if handler == nil {
		return fmt.Errorf("nil handler provided")
	}

	defer func() {
		if r := recover(); r != nil {
			handler.OnPanic(ctx, conn, r)
		}
	}()

	// OnAccept callback
	if err := handler.OnAccept(ctx, conn); err != nil {
		handler.OnError(ctx, conn, err)
		return err
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

	// Phase 1: Handshake (method negotiation)
	var handshakeReq HandshakeRequest
	if _, err := handshakeReq.ReadFrom(reader); err != nil {
		// Send "No acceptable methods" reply for malformed handshake
		WriteHandshake(conn, MethodNoAcceptable)
		handler.OnError(ctx, conn, err)
		return err
	}

	selectedMethod, err := handler.OnHandshake(ctx, conn, &handshakeReq)
	if err != nil {
		// Send "No acceptable methods" reply
		WriteHandshake(conn, MethodNoAcceptable)
		handler.OnError(ctx, conn, err)
		return err
	}

	// Send handshake reply
	if err := WriteHandshake(conn, selectedMethod); err != nil {
		handler.OnError(ctx, conn, err)
		return err
	}

	if selectedMethod == MethodNoAcceptable {
		err = fmt.Errorf("no acceptable authentication methods")
		handler.OnError(ctx, conn, err)
		return err
	}

	// Phase 2: Authentication (if required)
	switch selectedMethod {
	case MethodNoAuth:
		// No authentication required, proceed to request phase
	case MethodUserPass:
		if err := handleUserPassAuth(ctx, handler, conn, reader); err != nil {
			// Auth function already sent UserPassReply with failure status
			handler.OnError(ctx, conn, err)
			return err
		}
	case MethodGSSAPI:
		if err := handleGSSAPIAuth(ctx, handler, conn, reader); err != nil {
			// Auth function already sent GSSAPIReply with failure/abort
			handler.OnError(ctx, conn, err)
			return err
		}
	default:
		WriteRejectReply(conn, RepGeneralFailure)
		err = fmt.Errorf("unsupported authentication method: %d", selectedMethod)
		handler.OnError(ctx, conn, err)
		return err
	}

	// Phase 3: Request processing
	var req Request
	if _, err := req.ReadFrom(reader); err != nil {
		WriteRejectReply(conn, RepGeneralFailure)
		handler.OnError(ctx, conn, err)
		return err
	}

	// Release reader/writer resources before handling request
	release()

	// Handle the request through the handler
	if err := handler.OnRequest(ctx, conn, &req); err != nil {
		handler.OnError(ctx, conn, err)
		return err
	}

	return nil
}

// handleUserPassAuth handles username/password authentication.
func handleUserPassAuth(ctx context.Context, handler ServerHandler, conn net.Conn, reader *bufio.Reader) error {
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
	if _, err := userPassReply.WriteTo(conn); err != nil {
		return err
	}

	if status != UserPassStatusSuccess {
		return fmt.Errorf("username/password authentication failed: %w", err)
	}

	return nil
}

// handleGSSAPIAuth handles GSSAPI authentication.
func handleGSSAPIAuth(ctx context.Context, handler ServerHandler, conn net.Conn, reader *bufio.Reader) error {
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

		responseToken, done, err := handler.OnAuthGSSAPI(ctx, conn, gssapiReq.Token)
		var msgType byte = GSSAPITypeReply
		if err != nil {
			msgType = GSSAPITypeAbort
		}

		var gssapiReply GSSAPIReply
		gssapiReply.Init(GSSAPIVersion, msgType, responseToken)
		if _, err := gssapiReply.WriteTo(conn); err != nil {
			return err
		}

		if msgType == GSSAPITypeAbort {
			return fmt.Errorf("GSSAPI authentication failed: %w", err)
		}

		// Authentication is complete when done is true
		if done {
			break
		}
	}

	return nil
}

// WriteRejectReply sends a SOCKS5 reply with the given rejection code.
func WriteRejectReply(conn net.Conn, code byte) {
	var resp Reply
	resp.Init(SocksVersion, code, 0, AddrTypeIPv4, net.IPv4zero, "", 0)
	resp.WriteTo(conn)
}

// WriteSuccessReply writes a SOCKS5 success reply with the given network address.
func WriteSuccessReply(conn net.Conn, addr net.Addr) error {
	var ip net.IP
	var port uint16
	var domain string
	var addrType byte

	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
		port = uint16(a.Port)

	case *net.UDPAddr:
		ip = a.IP
		port = uint16(a.Port)

	default:
		ip = net.IPv4zero
		port = 0
	}

	// Replace 0.0.0.0 with actual interface IP
	if ip.IsUnspecified() {
		if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			ip = tcpAddr.IP
		}
	}

	// Determine address type
	if ip4 := ip.To4(); ip4 != nil {
		addrType = AddrTypeIPv4
		ip = ip4
	} else {
		addrType = AddrTypeIPv6
	}

	var resp Reply
	resp.Init(SocksVersion, RepSuccess, 0, addrType, ip, domain, port)
	_, err := resp.WriteTo(conn)
	return err
}

// WriteHandshake sends a SOCKS5 handshake reply with the given code.
func WriteHandshake(conn net.Conn, code byte) error {
	var handshakeReply HandshakeReply
	handshakeReply.Init(SocksVersion, code)
	_, err := handshakeReply.WriteTo(conn)
	return err
}
