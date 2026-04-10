package proxy_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/33TU/socks/proxy"
	"github.com/33TU/socks/socks4"
	"github.com/33TU/socks/socks5"
)

// simple echo server
func startEcho(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(c)
		}
	}()

	return ln
}

// start proxy mux server
func startProxy(t *testing.T, handler *proxy.ServerHandler) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		proxy.Serve(ctx, ln, handler)
	}()

	time.Sleep(10 * time.Millisecond)
	return ln
}

func TestProxyMux_SOCKS4_and_SOCKS5(t *testing.T) {
	echoLn := startEcho(t)
	defer echoLn.Close()

	proxyLn := startProxy(t, &proxy.ServerHandler{
		Socks4: socks4.DefaultServerHandler,
		Socks5: socks5.DefaultServerHandler,
	})
	defer proxyLn.Close()

	target := echoLn.Addr().String()

	// test both protocols
	tests := []struct {
		name string
		dial func(addr string) (net.Conn, error)
	}{
		{
			name: "SOCKS4",
			dial: func(addr string) (net.Conn, error) {
				d := socks4.NewDialer(proxyLn.Addr().String(), "test", nil)
				return d.DialContext(context.Background(), "tcp", addr)
			},
		},
		{
			name: "SOCKS5",
			dial: func(addr string) (net.Conn, error) {
				d := socks5.NewDialer(proxyLn.Addr().String(), nil, nil)
				return d.DialContext(context.Background(), "tcp", addr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := tt.dial(target)
			if err != nil {
				t.Fatalf("dial failed: %v", err)
			}
			defer conn.Close()

			payload := []byte("hello mux")
			resp := make([]byte, len(payload))

			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("write failed: %v", err)
			}

			if _, err := io.ReadFull(conn, resp); err != nil {
				t.Fatalf("read failed: %v", err)
			}

			if !bytes.Equal(payload, resp) {
				t.Fatalf("mismatch: got %q want %q", resp, payload)
			}
		})
	}
}
