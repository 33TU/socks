package socks4_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/33TU/socks/socks4"
)

// genRandom creates n random bytes.
func genRandom(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

func TestDialerAndServer_Connect_Success(t *testing.T) {
	// Start a simple echo TCP server (acts as destination)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn) // echo back everything
			}(c)
		}
	}()

	// SOCKS4 proxy listener
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxyLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := &socks4.ListenerOptions{
		OnConnect: func(ctx context.Context, opts *socks4.ListenerOptions, conn net.Conn, req *socks4.Request) error {
			t.Logf("proxy received CONNECT to %s:%d", req.GetHost(), req.Port)
			return socks4.OnConnectDefault(ctx, opts, conn, req)
		},
	}

	go func() {
		if err := socks4.ServeContext(ctx, proxyLn, opts); err != nil {
			t.Logf("ServeContext ended: %v", err)
		}
	}()

	// Give proxy a moment to start
	time.Sleep(50 * time.Millisecond)

	// Create SOCKS4 dialer
	dialer := socks4.NewDialer(proxyLn.Addr().String(), "user", nil)

	targetAddr := echoLn.Addr().String()
	conn, err := dialer.DialContext(context.Background(), "tcp", targetAddr)
	if err != nil {
		t.Fatalf("Dialer.Connect failed: %v", err)
	}
	defer conn.Close()

	// Echo test with random 64 KB payload
	message := genRandom(64 * 1024)
	buf := make([]byte, len(message))

	if _, err := conn.Write(message); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if !bytes.Equal(buf, message) {
		t.Fatalf("echo mismatch: data not identical")
	}

	t.Log("SOCKS4 CONNECT test passed successfully with 64KB random payload")
}

func TestDialerAndServer_Bind_Success(t *testing.T) {
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxyLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := &socks4.ListenerOptions{
		OnBind: func(ctx context.Context, opts *socks4.ListenerOptions, conn net.Conn, req *socks4.Request) error {
			t.Logf("proxy received BIND request for port %d", req.Port)

			// Step 1: open a new listener (simulate BIND port)
			bindLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("bind listen: %v", err)
			}
			defer bindLn.Close()

			addr := bindLn.Addr().(*net.TCPAddr)
			resp1 := socks4.Response{}
			resp1.Init(0, socks4.ReqGranted, uint16(addr.Port), net.ParseIP("127.0.0.1"))
			resp1.WriteTo(conn)

			peer, err := bindLn.Accept()
			if err != nil {
				t.Logf("bind accept failed: %v", err)
				return nil
			}
			defer peer.Close()

			resp2 := socks4.Response{}
			resp2.Init(0, socks4.ReqGranted, uint16(addr.Port), net.ParseIP("127.0.0.1"))
			resp2.WriteTo(conn)

			// bridge traffic
			go io.Copy(peer, conn)
			io.Copy(conn, peer)
			return nil
		},
	}

	go func() {
		if err := socks4.ServeContext(ctx, proxyLn, opts); err != nil {
			t.Logf("ServeContext ended: %v", err)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	dialer := socks4.NewDialer(proxyLn.Addr().String(), "user", nil)
	conn, bindAddr, readyCh, err := dialer.BindContext(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("BindContext failed: %v", err)
	}
	defer conn.Close()

	t.Logf("Proxy bound to: %v", bindAddr)

	// Step 3: simulate remote connecting to proxy's bound address
	go func() {
		time.Sleep(100 * time.Millisecond)
		c, err := net.Dial("tcp", bindAddr.String())
		if err != nil {
			t.Logf("peer dial: %v", err)
			return
		}
		defer c.Close()
		io.Copy(c, c) // simple echo
	}()

	// Wait for proxy ready
	if err := <-readyCh; err != nil {
		t.Fatalf("readyCh error: %v", err)
	}

	// Random 64 KB test data
	message := genRandom(64 * 1024)
	buf := make([]byte, len(message))

	if _, err := conn.Write(message); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf, message) {
		t.Fatalf("mismatch: data not identical")
	}

	t.Log("SOCKS4 BIND test passed successfully with 64KB random payload")
}
