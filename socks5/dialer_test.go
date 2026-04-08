package socks5_test

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/33TU/socks/socks5"
)

// startMockSOCKS5Server creates a mock SOCKS5 proxy for tests.
func startMockSOCKS5Server(t *testing.T, handle func(net.Conn)) (string, func()) {
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
	proxyAddr, stop := startMockSOCKS5Server(t, func(c net.Conn) {
		defer c.Close()

		// Read handshake request
		var hsReq socks5.HandshakeRequest
		if _, err := hsReq.ReadFrom(c); err != nil {
			t.Errorf("server: read handshake: %v", err)
			return
		}

		// Send handshake reply (NoAuth)
		hsReply := &socks5.HandshakeReply{
			Version: socks5.SocksVersion,
			Method:  socks5.MethodNoAuth,
		}
		if _, err := hsReply.WriteTo(c); err != nil {
			t.Errorf("server: write handshake reply: %v", err)
			return
		}

		// Read CONNECT request
		var req socks5.Request
		if _, err := req.ReadFrom(c); err != nil {
			t.Errorf("server: read request: %v", err)
			return
		}
		if req.Command != socks5.CmdConnect {
			t.Errorf("server: expected CONNECT, got %v", req.Command)
			return
		}

		// Send success reply
		resp := &socks5.Reply{
			Version:  socks5.SocksVersion,
			Reply:    socks5.RepSuccess,
			AddrType: socks5.AddrTypeIPv4,
			IP:       net.IPv4(127, 0, 0, 1),
			Port:     1234,
		}
		if _, err := resp.WriteTo(c); err != nil {
			t.Errorf("server: write reply: %v", err)
			return
		}

		// Echo test
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		c.Write([]byte("pong"))
	})
	defer stop()

	d := socks5.NewDialer(proxyAddr, nil, nil)
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
	proxyAddr, stop := startMockSOCKS5Server(t, func(c net.Conn) {
		defer c.Close()

		// Handshake
		var hsReq socks5.HandshakeRequest
		hsReq.ReadFrom(c)
		hsReply := &socks5.HandshakeReply{
			Version: socks5.SocksVersion,
			Method:  socks5.MethodNoAuth,
		}
		hsReply.WriteTo(c)

		// Read request and send rejection
		var req socks5.Request
		req.ReadFrom(c)
		resp := &socks5.Reply{
			Version:  socks5.SocksVersion,
			Reply:    socks5.RepConnectionRefused,
			AddrType: socks5.AddrTypeIPv4,
			IP:       net.IPv4zero,
			Port:     0,
		}
		resp.WriteTo(c)
	})
	defer stop()

	d := socks5.NewDialer(proxyAddr, nil, nil)
	_, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:9999")
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}

func TestDialer_Connect_WithAuth(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5Server(t, func(c net.Conn) {
		defer c.Close()

		// Read handshake request
		var hsReq socks5.HandshakeRequest
		hsReq.ReadFrom(c)

		// Send handshake reply (UserPass auth required)
		hsReply := &socks5.HandshakeReply{
			Version: socks5.SocksVersion,
			Method:  socks5.MethodUserPass,
		}
		hsReply.WriteTo(c)

		// Read auth request
		var authReq socks5.UserPassRequest
		if _, err := authReq.ReadFrom(c); err != nil {
			t.Errorf("server: read auth request: %v", err)
			return
		}
		if authReq.Username != "testuser" || authReq.Password != "testpass" {
			t.Errorf("server: invalid credentials")
			return
		}

		// Send auth reply (success)
		authReply := &socks5.UserPassReply{
			Version: 1,
			Status:  0,
		}
		authReply.WriteTo(c)

		// Read CONNECT request
		var req socks5.Request
		req.ReadFrom(c)

		// Send success reply
		resp := &socks5.Reply{
			Version:  socks5.SocksVersion,
			Reply:    socks5.RepSuccess,
			AddrType: socks5.AddrTypeIPv4,
			IP:       net.IPv4(127, 0, 0, 1),
			Port:     1234,
		}
		resp.WriteTo(c)

		// Echo test
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		c.Write([]byte("pong"))
	})
	defer stop()

	auth := &socks5.Auth{
		Username: "testuser",
		Password: "testpass",
	}
	d := socks5.NewDialer(proxyAddr, auth, nil)
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

func TestDialer_Bind_Success(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5Server(t, func(c net.Conn) {
		defer c.Close()

		// Handshake
		var hsReq socks5.HandshakeRequest
		hsReq.ReadFrom(c)
		hsReply := &socks5.HandshakeReply{
			Version: socks5.SocksVersion,
			Method:  socks5.MethodNoAuth,
		}
		hsReply.WriteTo(c)

		// Read BIND request
		var req socks5.Request
		req.ReadFrom(c)
		if req.Command != socks5.CmdBind {
			t.Errorf("server: expected BIND, got %v", req.Command)
			return
		}

		// Send first reply (bind address)
		resp1 := &socks5.Reply{
			Version:  socks5.SocksVersion,
			Reply:    socks5.RepSuccess,
			AddrType: socks5.AddrTypeIPv4,
			IP:       net.IPv4(127, 0, 0, 1),
			Port:     5555,
		}
		resp1.WriteTo(c)

		time.Sleep(100 * time.Millisecond)

		// Send second reply (connection established)
		resp2 := &socks5.Reply{
			Version:  socks5.SocksVersion,
			Reply:    socks5.RepSuccess,
			AddrType: socks5.AddrTypeIPv4,
			IP:       net.IPv4(127, 0, 0, 1),
			Port:     5555,
		}
		resp2.WriteTo(c)
	})
	defer stop()

	d := socks5.NewDialer(proxyAddr, nil, nil)
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
	proxyAddr, stop := startMockSOCKS5Server(t, func(c net.Conn) {
		defer c.Close()

		// Handshake
		var hsReq socks5.HandshakeRequest
		hsReq.ReadFrom(c)
		hsReply := &socks5.HandshakeReply{
			Version: socks5.SocksVersion,
			Method:  socks5.MethodNoAuth,
		}
		hsReply.WriteTo(c)

		// Read BIND request
		var req socks5.Request
		req.ReadFrom(c)

		// Send first reply
		resp1 := &socks5.Reply{
			Version:  socks5.SocksVersion,
			Reply:    socks5.RepSuccess,
			AddrType: socks5.AddrTypeIPv4,
			IP:       net.IPv4(127, 0, 0, 1),
			Port:     4444,
		}
		resp1.WriteTo(c)

		// Wait longer than the context timeout
		time.Sleep(2 * time.Second)
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	d := socks5.NewDialer(proxyAddr, nil, nil)
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

func TestDialer_UDPAssociate_Success(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5Server(t, func(c net.Conn) {
		defer c.Close()

		// Handshake
		var hsReq socks5.HandshakeRequest
		hsReq.ReadFrom(c)
		hsReply := &socks5.HandshakeReply{
			Version: socks5.SocksVersion,
			Method:  socks5.MethodNoAuth,
		}
		hsReply.WriteTo(c)

		// Read UDP ASSOCIATE request
		var req socks5.Request
		req.ReadFrom(c)
		if req.Command != socks5.CmdUDPAssociate {
			t.Errorf("server: expected UDP_ASSOCIATE, got %v", req.Command)
			return
		}

		// Send success reply with UDP relay address
		resp := &socks5.Reply{
			Version:  socks5.SocksVersion,
			Reply:    socks5.RepSuccess,
			AddrType: socks5.AddrTypeIPv4,
			IP:       net.IPv4(127, 0, 0, 1),
			Port:     8888,
		}
		resp.WriteTo(c)

		// Keep connection alive for UDP association
		time.Sleep(200 * time.Millisecond)
	})
	defer stop()

	d := socks5.NewDialer(proxyAddr, nil, nil)
	conn, udpAddr, err := d.UDPAssociateContext(context.Background(), "tcp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	if err != nil {
		t.Fatalf("UDPAssociateContext failed: %v", err)
	}
	defer conn.Close()

	if udpAddr.Port != 8888 {
		t.Errorf("expected UDP port 8888, got %d", udpAddr.Port)
	}
}

func TestDialer_Connect_ContextCancel(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5Server(t, func(c net.Conn) {
		defer c.Close()
		// Handshake
		var hsReq socks5.HandshakeRequest
		hsReq.ReadFrom(c)
		hsReply := &socks5.HandshakeReply{
			Version: socks5.SocksVersion,
			Method:  socks5.MethodNoAuth,
		}
		hsReply.WriteTo(c)

		// Delay to trigger context timeout
		time.Sleep(200 * time.Millisecond)
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	d := socks5.NewDialer(proxyAddr, nil, nil)
	_, err := d.DialContext(ctx, "tcp", "127.0.0.1:1234")
	if err == nil {
		t.Fatal("expected context timeout error")
	}
	if !strings.Contains(err.Error(), "context") &&
		!strings.Contains(err.Error(), "timeout") &&
		!strings.Contains(err.Error(), "closed network connection") {
		t.Fatalf("expected context/timeout/closed connection error, got %v", err)
	}
}
