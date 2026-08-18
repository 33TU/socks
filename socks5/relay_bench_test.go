package socks5_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/33TU/socks/socks5"
)

// benchmarkRelayThroughput pushes bytes through a SOCKS5 CONNECT relay.
//
// The timeout matters more than it looks: CopyConn only reaches io.Copy when
// there is none, and io.Copy between two TCP connections splices in the kernel
// rather than copying through userspace.
func benchmarkRelayThroughput(b *testing.B, timeout time.Duration) {
	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer sink.Close()

	go func() {
		for {
			conn, err := sink.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()

	handler := &socks5.BaseServerHandler{
		AllowConnect:       true,
		ConnectConnTimeout: timeout,
		ConnectBufferSize:  32 * 1024,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go socks5.Serve(ctx, ln, handler)

	d := socks5.NewDialer(ln.Addr().String(), nil, nil)
	conn, err := d.DialContext(context.Background(), "tcp", sink.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	const chunk = 64 * 1024
	payload := make([]byte, chunk)

	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := conn.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRelayNoTimeout(b *testing.B)   { benchmarkRelayThroughput(b, 0) }
func BenchmarkRelayWithTimeout(b *testing.B) { benchmarkRelayThroughput(b, 60*time.Second) }
