package shadowsocks_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/33TU/socks/shadowsocks"
)

// startEchoServer starts a TCP server that echoes everything it receives.
func startEchoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	return ln.Addr().String(), func() {
		ln.Close()
		<-done
	}
}

// startShadowsocksServer starts a Shadowsocks server with the given config.
func startShadowsocksServer(t *testing.T, cfg *shadowsocks.Config, handler *shadowsocks.BaseServerHandler) (addr string, stop func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen shadowsocks: %v", err)
	}

	if handler == nil {
		handler = &shadowsocks.BaseServerHandler{AllowConnect: true}
	}
	handler.Config = cfg

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = shadowsocks.Serve(ctx, ln, handler)
	}()

	return ln.Addr().String(), func() {
		cancel()
		ln.Close()
		<-done
	}
}

func testPSK(t *testing.T, method string) string {
	t.Helper()

	size := 32
	if method == shadowsocks.Method2022Blake3AES128GCM {
		size = 16
	}

	key := make([]byte, size)
	for i := range key {
		key[i] = byte(i * 7)
	}

	return base64.StdEncoding.EncodeToString(key)
}

func TestServer_RoundTrip(t *testing.T) {
	methods := []string{
		shadowsocks.Method2022Blake3AES128GCM,
		shadowsocks.Method2022Blake3AES256GCM,
		shadowsocks.Method2022Blake3ChaCha20Poly1305,
	}

	for _, methodName := range methods {
		t.Run(methodName, func(t *testing.T) {
			echoAddr, stopEcho := startEchoServer(t)
			defer stopEcho()

			cfg := &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)}
			proxyAddr, stopProxy := startShadowsocksServer(t, cfg, nil)
			defer stopProxy()

			d := shadowsocks.NewDialer(proxyAddr, cfg, nil)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			conn, err := d.DialContext(ctx, "tcp", echoAddr)
			if err != nil {
				t.Fatalf("DialContext() error = %v", err)
			}
			defer conn.Close()

			want := []byte("hello shadowsocks 2022")
			if _, err := conn.Write(want); err != nil {
				t.Fatalf("Write() error = %v", err)
			}

			got := make([]byte, len(want))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("ReadFull() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("echo = %q, want %q", got, want)
			}
		})
	}
}

func TestServer_RoundTripLargePayload(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES256GCM
	cfg := &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)}
	proxyAddr, stopProxy := startShadowsocksServer(t, cfg, nil)
	defer stopProxy()

	d := shadowsocks.NewDialer(proxyAddr, cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()

	// Larger than one chunk, so the payload spans multiple length/payload chunks.
	want := make([]byte, 300*1024)
	for i := range want {
		want[i] = byte(i)
	}

	go func() {
		_, _ = conn.Write(want)
	}()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("large echo payload mismatch")
	}
}

func TestServer_RejectsReplayedRequestStart(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	pskB64 := testPSK(t, methodName)
	cfg := &shadowsocks.Config{Method: methodName, PSK: pskB64}

	proxyAddr, stopProxy := startShadowsocksServer(t, cfg, &shadowsocks.BaseServerHandler{
		AllowConnect: true,
		DrainTimeout: time.Second,
	})
	defer stopProxy()

	method, err := shadowsocks.ParseMethod(methodName)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}
	psk, err := shadowsocks.DecodePSKTo(nil, method, pskB64)
	if err != nil {
		t.Fatalf("DecodePSKTo() error = %v", err)
	}

	host, portStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		t.Fatalf("LookupPort() error = %v", err)
	}

	var target shadowsocks.Addr
	target.Init(shadowsocks.AddrTypeIPv4, net.ParseIP(host).To4(), "", uint16(port))

	// Build one request start and send the exact same bytes twice.
	salt := bytes.Repeat([]byte{0x5a}, method.SaltSize)
	var buf bytes.Buffer
	if _, _, err := shadowsocks.WriteTCPRequestStart(
		&buf, method, psk, salt, time.Now(), target,
		bytes.Repeat([]byte{0x00}, 8), []byte("ping"),
	); err != nil {
		t.Fatalf("WriteTCPRequestStart() error = %v", err)
	}
	requestStart := buf.Bytes()

	readResponse := func() error {
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			return err
		}
		defer conn.Close()

		if _, err := conn.Write(requestStart); err != nil {
			return err
		}

		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _, err = shadowsocks.ReadTCPResponseStart(conn, method, psk, salt, time.Now())
		return err
	}

	if err := readResponse(); err != nil {
		t.Fatalf("first request: unexpected error = %v", err)
	}

	err = readResponse()
	if err == nil {
		t.Fatal("replayed request start was accepted, want rejection")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Logf("replayed request rejected with: %v", err)
	}
}

func TestServer_RejectsStaleTimestamp(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	pskB64 := testPSK(t, methodName)
	cfg := &shadowsocks.Config{Method: methodName, PSK: pskB64}

	proxyAddr, stopProxy := startShadowsocksServer(t, cfg, &shadowsocks.BaseServerHandler{
		AllowConnect: true,
		DrainTimeout: time.Second,
	})
	defer stopProxy()

	method, _ := shadowsocks.ParseMethod(methodName)
	psk, _ := shadowsocks.DecodePSKTo(nil, method, pskB64)

	var target shadowsocks.Addr
	target.Init(shadowsocks.AddrTypeDomain, nil, "example.com", 80)

	salt := bytes.Repeat([]byte{0x11}, method.SaltSize)
	var buf bytes.Buffer
	if _, _, err := shadowsocks.WriteTCPRequestStart(
		&buf, method, psk, salt,
		time.Now().Add(-5*time.Minute), // well outside the 30s window
		target, bytes.Repeat([]byte{0x00}, 8), []byte("ping"),
	); err != nil {
		t.Fatalf("WriteTCPRequestStart() error = %v", err)
	}

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(buf.Bytes()); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := shadowsocks.ReadTCPResponseStart(conn, method, psk, salt, time.Now()); err == nil {
		t.Fatal("stale request start was accepted, want rejection")
	}

	_ = echoAddr
}

// TestServer_DrainsProbes checks that a server does not immediately close the
// connection when fed garbage, which would reveal how many bytes it consumed.
func TestServer_DrainsProbes(t *testing.T) {
	methodName := shadowsocks.Method2022Blake3AES128GCM
	cfg := &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)}

	proxyAddr, stopProxy := startShadowsocksServer(t, cfg, &shadowsocks.BaseServerHandler{
		AllowConnect: true,
		DrainTimeout: 3 * time.Second,
		DrainLimit:   4096,
	})
	defer stopProxy()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	// A prober sends far too few bytes to form a header, then keeps writing.
	if _, err := conn.Write([]byte{0x01}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// The server must accept further writes rather than resetting the connection.
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 16; i++ {
		if _, err := conn.Write(bytes.Repeat([]byte{0x02}, 64)); err != nil {
			t.Fatalf("write %d after short header: %v", i, err)
		}
	}

	// The read side sees a clean FIN, never an RST.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("draining server response: %v", err)
	}
}

// failingListener reports a persistent non-terminal error from Accept, standing
// in for a listener that is out of file descriptors.
type failingListener struct {
	accepts atomic.Int64
	closed  chan struct{}
	once    sync.Once
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)

	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}

	return nil, &net.OpError{Op: "accept", Err: syscall.EMFILE}
}

func (l *failingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *failingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero}
}

// TestServer_AcceptErrorDoesNotSpin checks that a listener returning a
// recoverable error is retried with a backoff. Looping without one pegs a core
// and floods the error handler for as long as the condition lasts.
func TestServer_AcceptErrorDoesNotSpin(t *testing.T) {
	methodName := shadowsocks.Method2022Blake3AES128GCM
	handler := &shadowsocks.BaseServerHandler{
		Config: &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)},
	}

	ln := &failingListener{closed: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = shadowsocks.Serve(ctx, ln, handler)
	}()

	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}

	// With a backoff starting at 5ms and doubling, 300ms allows only a handful
	// of attempts. A spinning loop reaches into the millions.
	if got := ln.accepts.Load(); got > 100 {
		t.Fatalf("Accept called %d times in 300ms, want a bounded retry", got)
	}
}
