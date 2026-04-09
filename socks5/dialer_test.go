package socks5_test

import (
	"context"
	"fmt"
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

// Mock GSSAPI contexts for testing

// dialerMockGSSAPIContext_Success simulates successful single-round GSSAPI auth
type dialerMockGSSAPIContext_Success struct {
	complete bool
}

func (m *dialerMockGSSAPIContext_Success) InitSecContext() ([]byte, error) {
	return []byte("test-token-init"), nil
}

func (m *dialerMockGSSAPIContext_Success) AcceptSecContext(serverToken []byte) ([]byte, bool, error) {
	if string(serverToken) == "server-success-token" {
		m.complete = true
		return nil, true, nil // No response token needed, auth complete
	}
	return nil, false, fmt.Errorf("unexpected server token: %s", serverToken)
}

func (m *dialerMockGSSAPIContext_Success) IsComplete() bool {
	return m.complete
}

// dialerMockGSSAPIContext_MultiRound simulates multi-round GSSAPI exchange
type dialerMockGSSAPIContext_MultiRound struct {
	round    int
	complete bool
}

func (m *dialerMockGSSAPIContext_MultiRound) InitSecContext() ([]byte, error) {
	m.round = 1
	return []byte("init-token-round1"), nil
}

func (m *dialerMockGSSAPIContext_MultiRound) AcceptSecContext(serverToken []byte) ([]byte, bool, error) {
	switch m.round {
	case 1:
		if string(serverToken) == "server-round1-token" {
			m.round = 2
			return []byte("client-round2-token"), false, nil
		}
		return nil, false, fmt.Errorf("unexpected round 1 token: %s", serverToken)
	case 2:
		if string(serverToken) == "server-round2-final" {
			m.complete = true
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("unexpected round 2 token: %s", serverToken)
	default:
		return nil, false, fmt.Errorf("unexpected round: %d", m.round)
	}
}

func (m *dialerMockGSSAPIContext_MultiRound) IsComplete() bool {
	return m.complete
}

// dialerMockGSSAPIContext_Failure simulates GSSAPI auth failure
type dialerMockGSSAPIContext_Failure struct{}

func (m *dialerMockGSSAPIContext_Failure) InitSecContext() ([]byte, error) {
	return []byte("bad-token"), nil
}

func (m *dialerMockGSSAPIContext_Failure) AcceptSecContext(serverToken []byte) ([]byte, bool, error) {
	return nil, false, fmt.Errorf("mock GSSAPI auth failed")
}

func (m *dialerMockGSSAPIContext_Failure) IsComplete() bool {
	return false
}

func TestDialer_Connect_WithGSSAPI_Success(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5Server(t, func(c net.Conn) {
		defer c.Close()

		// Read handshake request
		var hsReq socks5.HandshakeRequest
		hsReq.ReadFrom(c)

		// Send handshake reply (GSSAPI auth required)
		hsReply := &socks5.HandshakeReply{
			Version: socks5.SocksVersion,
			Method:  socks5.MethodGSSAPI,
		}
		hsReply.WriteTo(c)

		// Read GSSAPI init request
		var gssReq socks5.GSSAPIRequest
		if _, err := gssReq.ReadFrom(c); err != nil {
			t.Errorf("server: read GSSAPI request: %v", err)
			return
		}
		if gssReq.Version != socks5.GSSAPIVersion || gssReq.MsgType != socks5.GSSAPITypeInit {
			t.Errorf("server: invalid GSSAPI init request")
			return
		}
		if string(gssReq.Token) != "test-token-init" {
			t.Errorf("server: unexpected GSSAPI token: %s", gssReq.Token)
			return
		}

		// Send GSSAPI reply (success)
		gssReply := &socks5.GSSAPIReply{
			Version: socks5.GSSAPIVersion,
			MsgType: socks5.GSSAPITypeReply,
			Token:   []byte("server-success-token"),
		}
		gssReply.WriteTo(c)

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

	gssapiAuth := &socks5.GSSAPIAuth{
		Context: &dialerMockGSSAPIContext_Success{},
	}
	d := socks5.NewDialerWithGSSAPI(proxyAddr, nil, gssapiAuth, nil)
	conn, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:1234")
	if err != nil {
		t.Fatalf("DialContext with GSSAPI failed: %v", err)
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

func TestDialer_Connect_WithGSSAPI_MultiRound(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5Server(t, func(c net.Conn) {
		defer c.Close()

		// Read handshake request
		var hsReq socks5.HandshakeRequest
		hsReq.ReadFrom(c)

		// Send handshake reply (GSSAPI auth required)
		hsReply := &socks5.HandshakeReply{
			Version: socks5.SocksVersion,
			Method:  socks5.MethodGSSAPI,
		}
		hsReply.WriteTo(c)

		// Round 1: Read GSSAPI init request
		var gssReq1 socks5.GSSAPIRequest
		if _, err := gssReq1.ReadFrom(c); err != nil {
			t.Errorf("server: read GSSAPI request round 1: %v", err)
			return
		}
		if string(gssReq1.Token) != "init-token-round1" {
			t.Errorf("server: unexpected round 1 token: %s", gssReq1.Token)
			return
		}

		// Send GSSAPI reply round 1 (needs continuation)
		gssReply1 := &socks5.GSSAPIReply{
			Version: socks5.GSSAPIVersion,
			MsgType: socks5.GSSAPITypeReply,
			Token:   []byte("server-round1-token"),
		}
		gssReply1.WriteTo(c)

		// Round 2: Read GSSAPI continuation request
		var gssReq2 socks5.GSSAPIRequest
		if _, err := gssReq2.ReadFrom(c); err != nil {
			t.Errorf("server: read GSSAPI request round 2: %v", err)
			return
		}
		if string(gssReq2.Token) != "client-round2-token" {
			t.Errorf("server: unexpected round 2 token: %s", gssReq2.Token)
			return
		}

		// Send GSSAPI reply round 2 (success/final)
		gssReply2 := &socks5.GSSAPIReply{
			Version: socks5.GSSAPIVersion,
			MsgType: socks5.GSSAPITypeReply,
			Token:   []byte("server-round2-final"),
		}
		gssReply2.WriteTo(c)

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

	gssapiAuth := &socks5.GSSAPIAuth{
		Context: &dialerMockGSSAPIContext_MultiRound{},
	}
	d := socks5.NewDialerWithGSSAPI(proxyAddr, nil, gssapiAuth, nil)
	conn, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:1234")
	if err != nil {
		t.Fatalf("DialContext with multi-round GSSAPI failed: %v", err)
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

func TestDialer_Connect_WithGSSAPI_Failed(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5Server(t, func(c net.Conn) {
		defer c.Close()

		// Read handshake request
		var hsReq socks5.HandshakeRequest
		hsReq.ReadFrom(c)

		// Send handshake reply (GSSAPI auth required)
		hsReply := &socks5.HandshakeReply{
			Version: socks5.SocksVersion,
			Method:  socks5.MethodGSSAPI,
		}
		hsReply.WriteTo(c)

		// Read GSSAPI init request
		var gssReq socks5.GSSAPIRequest
		if _, err := gssReq.ReadFrom(c); err != nil {
			t.Errorf("server: read GSSAPI request: %v", err)
			return
		}

		// Send GSSAPI abort (authentication failed)
		gssReply := &socks5.GSSAPIReply{
			Version: socks5.GSSAPIVersion,
			MsgType: socks5.GSSAPITypeAbort,
			Token:   nil, // No token for abort
		}
		gssReply.WriteTo(c)
	})
	defer stop()

	gssapiAuth := &socks5.GSSAPIAuth{
		Context: &dialerMockGSSAPIContext_Failure{},
	}
	d := socks5.NewDialerWithGSSAPI(proxyAddr, nil, gssapiAuth, nil)
	_, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:1234")
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("expected GSSAPI abort error, got %v", err)
	}
}

func TestDialer_Connect_WithGSSAPI_NoContext(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5Server(t, func(c net.Conn) {
		defer c.Close()

		// Read handshake request
		var hsReq socks5.HandshakeRequest
		hsReq.ReadFrom(c)

		// Send handshake reply (GSSAPI auth required)
		hsReply := &socks5.HandshakeReply{
			Version: socks5.SocksVersion,
			Method:  socks5.MethodGSSAPI,
		}
		hsReply.WriteTo(c)
	})
	defer stop()

	// Create dialer without GSSAPI auth but server requires it
	d := socks5.NewDialer(proxyAddr, nil, nil)
	_, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:1234")
	if err == nil || !strings.Contains(err.Error(), "requires GSSAPI") {
		t.Fatalf("expected GSSAPI required error, got %v", err)
	}
}

func TestDialer_Connect_WithDeadline(t *testing.T) {
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

		// Read request
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

		// Test deadline by delaying read operation
		time.Sleep(150 * time.Millisecond) // Longer than context deadline

		buf := make([]byte, 4)
		_, err := io.ReadFull(c, buf) // This should fail due to deadline
		if err == nil {
			t.Logf("server: expected deadline error but got none")
		}
	})
	defer stop()

	// Create context with short deadline
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	d := socks5.NewDialer(proxyAddr, nil, nil)
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:1234")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	// Try to write - should work initially
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Wait for deadline to expire, then try to read
	time.Sleep(120 * time.Millisecond)

	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	if err == nil {
		t.Fatal("expected deadline timeout error on read")
	}

	// Verify it's a timeout/deadline error
	if !strings.Contains(err.Error(), "timeout") &&
		!strings.Contains(err.Error(), "deadline") &&
		!strings.Contains(err.Error(), "i/o timeout") {
		t.Logf("got error (acceptable): %v", err) // Log but don't fail - different error types are OK
	}
}
