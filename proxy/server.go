package proxy

import (
	"context"
	"fmt"
	"net"

	"github.com/33TU/socks/socks4"
	"github.com/33TU/socks/socks5"
)

// ServerHandler multiplexes incoming connections to the appropriate SOCKS4 or SOCKS5 handlers based on protocol detection.
type ServerHandler struct {
	Socks4 socks4.ServerHandler
	Socks5 socks5.ServerHandler

	UnknownHandler func(conn net.Conn, peekedByte byte)
}

// Serve accepts incoming connections and dispatches based on protocol.
func Serve(ctx context.Context, listener net.Listener, handler *ServerHandler) error {
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
				continue
			}

			go ServeConn(ctx, handler, conn)
		}
	}
}

// ListenAndServe listens on the network address and serves proxy requests.
func ListenAndServe(ctx context.Context, network, address string, handler *ServerHandler) error {
	ln, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	return Serve(ctx, ln, handler)
}

// ServeConn handles a single client connection, including protocol detection and dispatching to the appropriate handler.
// If no handler is found the connection is closed.
func ServeConn(ctx context.Context, handler *ServerHandler, conn net.Conn) error {
	defer conn.Close()

	if handler == nil {
		return fmt.Errorf("nil handler provided")
	}

	bc, err := newPeekConn(conn)
	if err != nil {
		return fmt.Errorf("unable to determine protocol: %w", err)
	}

	switch bc.initialByte {
	case socks4.SocksVersion:
		if handler.Socks4 != nil {
			if err = socks4.ServeConn(ctx, handler.Socks4, bc); err != nil {
				return fmt.Errorf("socks4 handler error: %w", err)
			}
			return nil
		}

	case socks5.SocksVersion:
		if handler.Socks5 != nil {
			if err = socks5.ServeConn(ctx, handler.Socks5, bc); err != nil {
				return fmt.Errorf("socks5 handler error: %w", err)
			}
			return nil
		}
	}

	if handler.UnknownHandler != nil {
		handler.UnknownHandler(bc, bc.initialByte)
	}

	return fmt.Errorf("unsupported protocol version: %d", bc.initialByte)
}
