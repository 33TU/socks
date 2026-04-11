// simple custom socks5 server that supports "connect" command with "no auth" method, and logs all events.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"time"

	"github.com/33TU/socks/socks5"
)

type customServerHandler struct{}

// helper to safely get addr
func addr(conn net.Conn) string {
	if conn == nil {
		return "<nil>"
	}
	return conn.RemoteAddr().String()
}

//
// Log on each event and use the custom implementation for OnRequest and OnConnect.
//

// OnAccept implements [socks5.ServerHandler].
func (c *customServerHandler) OnAccept(ctx context.Context, conn net.Conn) error {
	log.Printf("[OnAccept] connection from %s", addr(conn))
	return nil
}

// OnAuthGSSAPI implements [socks5.ServerHandler].
func (c *customServerHandler) OnAuthGSSAPI(ctx context.Context, conn net.Conn, token []byte) (resp []byte, done bool, err error) {
	log.Printf("[OnAuthGSSAPI] from %s | token_len=%d", addr(conn), len(token))
	return nil, false, errors.New("GSSAPI authentication not supported")
}

// OnAuthUserPass implements [socks5.ServerHandler].
func (c *customServerHandler) OnAuthUserPass(ctx context.Context, conn net.Conn, username string, password string) error {
	log.Printf("[OnAuthUserPass] from %s | username=%q password_len=%d", addr(conn), username, len(password))
	return errors.New("username/password authentication not supported")
}

// OnBind implements [socks5.ServerHandler].
func (c *customServerHandler) OnBind(ctx context.Context, conn net.Conn, req *socks5.Request) error {
	log.Printf("[OnBind] from %s | req=%+v", addr(conn), req)
	return errors.New("bind not supported")
}

// OnError implements [socks5.ServerHandler].
func (c *customServerHandler) OnError(ctx context.Context, conn net.Conn, err error) {
	log.Printf("[OnError] from %s | error=%v", addr(conn), err)
}

// OnHandshake implements [socks5.ServerHandler].
func (c *customServerHandler) OnHandshake(ctx context.Context, conn net.Conn, req *socks5.HandshakeRequest) (selectedMethod byte, err error) {
	log.Printf("[OnHandshake] from %s | methods=%v", addr(conn), req.Methods)
	return socks5.BaseOnHandshake(ctx, conn, req, []byte{socks5.MethodNoAuth})
}

// OnPanic implements [socks5.ServerHandler].
func (c *customServerHandler) OnPanic(ctx context.Context, conn net.Conn, r any) {
	log.Printf("[OnPanic] from %s | panic=%v", addr(conn), r)
}

// OnResolve implements [socks5.ServerHandler].
func (c *customServerHandler) OnResolve(ctx context.Context, conn net.Conn, req *socks5.Request) error {
	log.Printf("[OnResolve] from %s | target=%s", addr(conn), req.Addr())
	return errors.New("resolve not supported")
}

// OnUDPAssociate implements [socks5.ServerHandler].
func (c *customServerHandler) OnUDPAssociate(ctx context.Context, conn net.Conn, req *socks5.Request) error {
	log.Printf("[OnUDPAssociate] from %s | target=%s", addr(conn), req.Addr())
	return errors.New("UDP associate not supported")
}

// OnConnect implements [socks5.ServerHandler].
func (c *customServerHandler) OnClose(ctx context.Context, conn net.Conn, errCause error) {
	log.Printf("[OnClose] from %s | error=%v", addr(conn), errCause)
}

//
// This custom handler only supports CONNECT command.
//

// OnRequest implements [socks5.ServerHandler].
func (c *customServerHandler) OnRequest(ctx context.Context, conn net.Conn, req *socks5.Request) error {
	log.Printf("[OnRequest] from %s | cmd=%d target=%s", addr(conn), req.Command, req.Addr())

	if req.Command != socks5.CmdConnect {
		return errors.New("only CONNECT command is supported")
	}

	return c.OnConnect(ctx, conn, req) // pass to OnConnect for handling
}

// OnConnect implements [socks5.ServerHandler].
func (c *customServerHandler) OnConnect(ctx context.Context, conn net.Conn, req *socks5.Request) error {
	log.Printf("[OnConnect] from %s | target=%s", addr(conn), req.Addr())

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	connTimeout := 60 * time.Second
	connBufferSize := 1024 * 32

	// use the base implementation for CONNECT command which dials the target and relays data between client and target.
	return socks5.BaseOnConnect(ctx, conn, req, dialer, connTimeout, connBufferSize)
}

func main() {
	handler := &customServerHandler{}

	log.Println("SOCKS5 listening on 127.0.0.1:1080")

	if err := socks5.ListenAndServe(context.Background(), "tcp", "127.0.0.1:1080", handler); err != nil {
		log.Fatal(err)
	}
}
