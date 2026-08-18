package socks4_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/33TU/socks/socks4"
)

// BenchmarkRelayThroughput pushes bytes through a SOCKS4 CONNECT relay, which
// shares its copy loop with SOCKS5 and so should splice in the kernel too.
func BenchmarkRelayThroughput(b *testing.B) {
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

	handler := &socks4.BaseServerHandler{
		AllowConnect:       true,
		ConnectConnTimeout: 60 * time.Second,
		ConnectBufferSize:  32 * 1024,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go socks4.Serve(ctx, ln, handler)

	d := socks4.NewDialer(ln.Addr().String(), "", nil)
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
