package socks4_test

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/33TU/socks/socks4"
)

// startMockSOCKS4Server creates a mock SOCKS4 proxy for tests.
func startMockSOCKS4Server(t *testing.T, handle func(net.Conn)) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestDialer_Connect_Success(t *testing.T) {
	proxyAddr, stop := startMockSOCKS4Server(t, func(c net.Conn) {
		defer c.Close()

		var req socks4.Request
		if _, err := req.ReadFrom(c); err != nil {
			t.Errorf("server: read request: %v", err)
			return
		}
		if req.Command != socks4.CmdConnect {
			t.Errorf("server: expected CONNECT, got %v", req.Command)
			return
		}

		var resp socks4.Reply
		resp.Init(0, socks4.RepGranted, req.Port, req.GetIP())
		resp.WriteTo(c)

		// Echo test
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		c.Write([]byte("pong"))
	})
	defer stop()

	d := &socks4.Dialer{ProxyAddr: proxyAddr, UserID: "tester"}
	conn, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:1234")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("expected pong, got %q", buf)
	}
}

func TestDialer_Connect_Rejected(t *testing.T) {
	proxyAddr, stop := startMockSOCKS4Server(t, func(c net.Conn) {
		defer c.Close()
		var req socks4.Request
		req.ReadFrom(c)
		var resp socks4.Reply
		resp.Init(0, socks4.RepRejected, 0, net.IPv4zero)
		resp.WriteTo(c)
	})
	defer stop()

	d := &socks4.Dialer{ProxyAddr: proxyAddr}
	_, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:9999")
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}

func TestDialer_Bind_Success(t *testing.T) {
	proxyAddr, stop := startMockSOCKS4Server(t, func(c net.Conn) {
		defer c.Close()
		var req socks4.Request
		req.ReadFrom(c)
		if req.Command != socks4.CmdBind {
			t.Errorf("server: expected BIND, got %v", req.Command)
			return
		}

		// Send first reply (bind address)
		var resp1 socks4.Reply
		resp1.Init(0, socks4.RepGranted, 5555, net.IPv4(127, 0, 0, 1))
		resp1.WriteTo(c)

		time.Sleep(100 * time.Millisecond)

		// Send second reply (connection established)
		var resp2 socks4.Reply
		resp2.Init(0, socks4.RepGranted, 5555, net.IPv4(127, 0, 0, 1))
		resp2.WriteTo(c)
	})
	defer stop()

	d := &socks4.Dialer{ProxyAddr: proxyAddr, UserID: "binder"}
	conn, bindAddr, readyCh, err := d.BindContext(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("BindContext failed: %v", err)
	}
	defer conn.Close()

	if bindAddr.Port == 0 {
		t.Errorf("expected nonzero bind port")
	}

	select {
	case err := <-readyCh:
		if err != nil {
			t.Fatalf("bind ready failed: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for BIND ready")
	}
}

func TestDialer_Bind_ContextCancel(t *testing.T) {
	proxyAddr, stop := startMockSOCKS4Server(t, func(c net.Conn) {
		defer c.Close()
		var req socks4.Request
		req.ReadFrom(c)
		var resp1 socks4.Reply
		resp1.Init(0, socks4.RepGranted, 4444, net.IPv4(127, 0, 0, 1))
		resp1.WriteTo(c)
		time.Sleep(2 * time.Second)
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	d := &socks4.Dialer{ProxyAddr: proxyAddr, UserID: "canceltest"}
	conn, _, readyCh, err := d.BindContext(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("BindContext failed: %v", err)
	}
	defer conn.Close()

	select {
	case <-readyCh:
		t.Fatalf("unexpected ready signal before context cancel")
	case <-ctx.Done():
		time.Sleep(50 * time.Millisecond)
	}
}
