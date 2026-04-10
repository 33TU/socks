package chain_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/33TU/socks/chain"
	socksnet "github.com/33TU/socks/net"
	"github.com/33TU/socks/socks4"
	"github.com/33TU/socks/socks5"
)

func startEchoServer(t *testing.T) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return ln
}

func startSOCKS5Server(t *testing.T) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = socks5.Serve(ctx, ln, socks5.DefaultServerHandler)
	}()

	return ln.Addr().String(), func() {
		cancel()
		_ = ln.Close()
	}
}

func startSOCKS4Server(t *testing.T) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks4: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = socks4.Serve(ctx, ln, socks4.DefaultServerHandler)
	}()

	return ln.Addr().String(), func() {
		cancel()
		_ = ln.Close()
	}
}

type unsupportedDialer struct{}

func (d *unsupportedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, errors.New("unsupported")
}

func roundTripEcho(t *testing.T, d socksnet.Dialer, target string, payload []byte) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
}

func TestChain_SOCKS5ToSOCKS5(t *testing.T) {
	echoLn := startEchoServer(t)
	defer echoLn.Close()

	s5aAddr, s5aStop := startSOCKS5Server(t)
	defer s5aStop()

	s5bAddr, s5bStop := startSOCKS5Server(t)
	defer s5bStop()

	d1 := socks5.NewDialer(s5aAddr, nil, nil)
	d2 := socks5.NewDialer(s5bAddr, nil, nil)

	chained, err := chain.Chain(d1, d2)
	if err != nil {
		t.Fatalf("Chain failed: %v", err)
	}

	roundTripEcho(t, chained, echoLn.Addr().String(), []byte("ping"))
}

func TestChain_SOCKS4ToSOCKS5(t *testing.T) {
	echoLn := startEchoServer(t)
	defer echoLn.Close()

	s4Addr, s4Stop := startSOCKS4Server(t)
	defer s4Stop()

	s5Addr, s5Stop := startSOCKS5Server(t)
	defer s5Stop()

	d1 := socks4.NewDialer(s4Addr, "", nil)
	d2 := socks5.NewDialer(s5Addr, nil, nil)

	chained, err := chain.Chain(d1, d2)
	if err != nil {
		t.Fatalf("Chain failed: %v", err)
	}

	roundTripEcho(t, chained, echoLn.Addr().String(), []byte("hello"))
}

func TestChain_ThreeHops(t *testing.T) {
	echoLn := startEchoServer(t)
	defer echoLn.Close()

	s1Addr, s1Stop := startSOCKS5Server(t)
	defer s1Stop()

	s2Addr, s2Stop := startSOCKS5Server(t)
	defer s2Stop()

	s3Addr, s3Stop := startSOCKS5Server(t)
	defer s3Stop()

	d1 := socks5.NewDialer(s1Addr, nil, nil)
	d2 := socks5.NewDialer(s2Addr, nil, nil)
	d3 := socks5.NewDialer(s3Addr, nil, nil)

	chained, err := chain.Chain(d1, d2, d3)
	if err != nil {
		t.Fatalf("Chain failed: %v", err)
	}

	roundTripEcho(t, chained, echoLn.Addr().String(), []byte("chain-test"))
}

func TestChain_SOCKS5ToSOCKS4(t *testing.T) {
	echoLn := startEchoServer(t)
	defer echoLn.Close()

	s5Addr, s5Stop := startSOCKS5Server(t)
	defer s5Stop()

	s4Addr, s4Stop := startSOCKS4Server(t)
	defer s4Stop()

	d1 := socks5.NewDialer(s5Addr, nil, nil)
	d2 := socks4.NewDialer(s4Addr, "", nil)

	chained, err := chain.Chain(d1, d2)
	if err != nil {
		t.Fatalf("Chain failed: %v", err)
	}

	roundTripEcho(t, chained, echoLn.Addr().String(), []byte("s5-to-s4"))
}

func TestChain_SingleDialer(t *testing.T) {
	echoLn := startEchoServer(t)
	defer echoLn.Close()

	s5Addr, s5Stop := startSOCKS5Server(t)
	defer s5Stop()

	d1 := socks5.NewDialer(s5Addr, nil, nil)

	chained, err := chain.Chain(d1)
	if err != nil {
		t.Fatalf("Chain failed: %v", err)
	}

	roundTripEcho(t, chained, echoLn.Addr().String(), []byte("single"))
}

func TestChain_OriginalUnmodified(t *testing.T) {
	s5aAddr, s5aStop := startSOCKS5Server(t)
	defer s5aStop()

	s4Addr, s4Stop := startSOCKS4Server(t)
	defer s4Stop()

	d1 := socks5.NewDialer(s5aAddr, nil, nil)
	d2 := socks4.NewDialer(s4Addr, "testuser", nil)

	_, err := chain.Chain(d1, d2)
	if err != nil {
		t.Fatalf("Chain failed: %v", err)
	}
}

func TestChain_MultipleChainsSameDialers(t *testing.T) {
	echoLn := startEchoServer(t)
	defer echoLn.Close()

	s5Addr, s5Stop := startSOCKS5Server(t)
	defer s5Stop()

	s4Addr, s4Stop := startSOCKS4Server(t)
	defer s4Stop()

	d1 := socks5.NewDialer(s5Addr, nil, nil)
	d2 := socks4.NewDialer(s4Addr, "user", nil)

	// Create two different chains with same dialers
	chain1, err := chain.Chain(d1, d2)
	if err != nil {
		t.Fatalf("Chain1 failed: %v", err)
	}

	chain2, err := chain.Chain(d2, d1) // Different order
	if err != nil {
		t.Fatalf("Chain2 failed: %v", err)
	}

	// Both chains should work independently
	roundTripEcho(t, chain1, echoLn.Addr().String(), []byte("chain1"))
	roundTripEcho(t, chain2, echoLn.Addr().String(), []byte("chain2"))
}
