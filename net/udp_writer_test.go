package net_test

import (
	"context"
	"encoding/binary"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	socksnet "github.com/33TU/socks/net"
)

// startFakeDNSForBench is startFakeDNS for a benchmark, which cannot use *testing.T.
func startFakeDNSForBench(b *testing.B) *stdnet.Resolver {
	b.Helper()

	conn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := dnsAnswer(buf[:n]); resp != nil {
				conn.WriteToUDP(resp, from)
			}
		}
	}()

	addr := conn.LocalAddr().String()
	return &stdnet.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (stdnet.Conn, error) {
			var d stdnet.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

// fakeDNS answers every A query with 127.0.0.1 and counts the queries it sees,
// so a test can tell a cache hit from a lookup.
type fakeDNS struct {
	conn    *stdnet.UDPConn
	queries atomic.Int64
	done    chan struct{}
}

func startFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()

	conn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen fake dns: %v", err)
	}

	d := &fakeDNS{conn: conn, done: make(chan struct{})}

	go func() {
		defer close(d.done)
		buf := make([]byte, 1024)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			resp := dnsAnswer(buf[:n])
			if resp == nil {
				continue
			}
			if binary.BigEndian.Uint16(resp[6:8]) == 1 {
				d.queries.Add(1) // an answered A query, i.e. a real lookup
			}
			if _, err := conn.WriteToUDP(resp, from); err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		conn.Close()
		<-d.done
	})

	return d
}

// dnsAnswer builds a response to query, resolving the name to 127.0.0.1.
func dnsAnswer(query []byte) []byte {
	// Only the header and question are echoed. Go sends an EDNS0 record in the
	// additional section, and keeping it would leave it sitting where the
	// parser expects the answer.
	end := 12
	for end < len(query) && query[end] != 0 {
		end += int(query[end]) + 1
	}
	end += 1 + 4 // root label, then qtype and qclass
	if end > len(query) {
		return nil
	}

	qtype := binary.BigEndian.Uint16(query[end-4 : end-2])

	resp := append([]byte(nil), query[:end]...)
	resp[2] |= 0x80                            // QR: this is a response
	resp[3] = 0x80                             // recursion available, no error
	binary.BigEndian.PutUint16(resp[8:10], 0)  // no authority records
	binary.BigEndian.PutUint16(resp[10:12], 0) // no additional records

	// Only A records are served; anything else gets an empty answer.
	if qtype != 1 {
		binary.BigEndian.PutUint16(resp[6:8], 0)
		return resp
	}

	binary.BigEndian.PutUint16(resp[6:8], 1)

	// A pointer back to the question's name, then the A record itself.
	resp = append(resp, 0xc0, 0x0c)
	resp = binary.BigEndian.AppendUint16(resp, 1)  // type A
	resp = binary.BigEndian.AppendUint16(resp, 1)  // class IN
	resp = binary.BigEndian.AppendUint32(resp, 60) // TTL
	resp = binary.BigEndian.AppendUint16(resp, 4)  // RDLENGTH
	return append(resp, 127, 0, 0, 1)
}

// resolver returns a resolver that asks only this server.
func (d *fakeDNS) resolver() *stdnet.Resolver {
	addr := d.conn.LocalAddr().String()
	return &stdnet.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (stdnet.Conn, error) {
			var dialer stdnet.Dialer
			return dialer.DialContext(ctx, "udp", addr)
		},
	}
}

// startUDPSink returns a socket that records the datagrams it receives.
func startUDPSink(t *testing.T) (*stdnet.UDPAddr, func() [][]byte) {
	t.Helper()

	conn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen sink: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	var mu sync.Mutex
	var got [][]byte

	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			got = append(got, append([]byte(nil), buf[:n]...))
			mu.Unlock()
		}
	}()

	return conn.LocalAddr().(*stdnet.UDPAddr), func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return append([][]byte(nil), got...)
	}
}

func TestAsyncUDPWriter_ResolvesAndSends(t *testing.T) {
	dns := startFakeDNS(t)
	sinkAddr, received := startUDPSink(t)

	out, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen out: %v", err)
	}
	defer out.Close()

	w := socksnet.NewAsyncUDPWriter(out, &socksnet.AsyncUDPWriterConfig{Resolver: dns.resolver()})
	defer w.Close()

	for range 4 {
		if !w.WriteToDomain([]byte("payload"), "cached.example", uint16(sinkAddr.Port)) {
			t.Fatal("WriteToDomain() = false, want the datagram accepted")
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for len(received()) < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if got := received(); len(got) != 4 {
		t.Fatalf("sink received %d datagrams, want 4", len(got))
	}

	// The address is cached after the first lookup, so the rest are sent
	// without asking the resolver again.
	if got := dns.queries.Load(); got != 1 {
		t.Errorf("resolver queried %d times, want 1: results are not being cached", got)
	}
}

func TestAsyncUDPWriter_DropsWhenQueueFull(t *testing.T) {
	out, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen out: %v", err)
	}
	defer out.Close()

	// A resolver that never answers, so nothing ever leaves the queue.
	stuck := &stdnet.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (stdnet.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	w := socksnet.NewAsyncUDPWriter(out, &socksnet.AsyncUDPWriterConfig{
		Resolver:  stuck,
		QueueSize: 1,
		Workers:   1,
	})
	defer w.Close()

	var dropped int
	for range 32 {
		if !w.WriteToDomain([]byte("payload"), "stuck.example", 53) {
			dropped++
		}
	}

	if dropped == 0 {
		t.Fatal("no datagrams dropped with a full queue, want the writer to shed load")
	}
}

func TestAsyncUDPWriter_WriteAfterCloseIsRejected(t *testing.T) {
	out, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen out: %v", err)
	}
	defer out.Close()

	w := socksnet.NewAsyncUDPWriter(out, nil)
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}

	if w.WriteToDomain([]byte("payload"), "late.example", 53) {
		t.Error("WriteToDomain() after Close = true, want false")
	}
}

// TestAsyncUDPWriter_ConcurrentWriteAndClose guards the shutdown path: writers
// racing Close must not send on a closed queue.
func TestAsyncUDPWriter_ConcurrentWriteAndClose(t *testing.T) {
	out, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen out: %v", err)
	}
	defer out.Close()

	w := socksnet.NewAsyncUDPWriter(out, &socksnet.AsyncUDPWriterConfig{QueueSize: 4})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				w.WriteToDomain([]byte("payload"), "racing.example", 53)
			}
		}()
	}

	time.Sleep(5 * time.Millisecond)
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	wg.Wait()
}

// TestAsyncUDPWriter_CloseDoesNotWaitForStalledLookups checks that shutdown is
// prompt even while lookups are outstanding, since a relay closes sessions on
// its own read loop.
func TestAsyncUDPWriter_CloseDoesNotWaitForStalledLookups(t *testing.T) {
	out, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen out: %v", err)
	}
	defer out.Close()

	stuck := &stdnet.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (stdnet.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	w := socksnet.NewAsyncUDPWriter(out, &socksnet.AsyncUDPWriterConfig{Resolver: stuck})
	for range 16 {
		w.WriteToDomain([]byte("payload"), "stuck.example", 53)
	}

	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close took %v, want it to abort lookups rather than wait them out", elapsed)
	}
}

// discardPacketConn swallows datagrams so a benchmark measures the writer
// rather than the kernel.
type discardPacketConn struct{ stdnet.PacketConn }

func (discardPacketConn) WriteTo(p []byte, _ stdnet.Addr) (int, error) { return len(p), nil }
func (discardPacketConn) Close() error                                 { return nil }

// benchCachedWriter returns a writer with domain already resolved, so the
// benchmark exercises the cached send path a relay spends its time in.
func benchCachedWriter(b *testing.B, domain string) *socksnet.AsyncUDPWriter {
	b.Helper()

	dns := startFakeDNSForBench(b)
	w := socksnet.NewAsyncUDPWriter(discardPacketConn{}, &socksnet.AsyncUDPWriterConfig{
		Resolver: dns,
	})

	// Prime the cache and wait for the lookup to land.
	for range 100 {
		w.WriteToDomain([]byte("warm"), domain, 53)
		time.Sleep(time.Millisecond)
	}

	return w
}

func BenchmarkAsyncUDPWriterCachedSerial(b *testing.B) {
	w := benchCachedWriter(b, "cached.example")
	defer w.Close()

	payload := make([]byte, 1400)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		w.WriteToDomain(payload, "cached.example", 53)
	}
}

func BenchmarkAsyncUDPWriterCachedParallel(b *testing.B) {
	w := benchCachedWriter(b, "cached.example")
	defer w.Close()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		payload := make([]byte, 1400)
		for pb.Next() {
			w.WriteToDomain(payload, "cached.example", 53)
		}
	})
}
