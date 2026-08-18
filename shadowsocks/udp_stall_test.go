package shadowsocks_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/33TU/socks/shadowsocks"
)

// hangingResolver blocks every lookup until its context expires, standing in
// for a DNS server that has stopped answering.
func hangingResolver(started chan<- struct{}) *net.Resolver {
	// The resolver calls Dial from several goroutines at once.
	var once sync.Once
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			once.Do(func() { close(started) })
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
}

// TestUDPRelay_DomainStallDoesNotBlockOtherTraffic checks that packets to an
// unresolvable domain do not hold up the relay. Every session's packets arrive
// on one socket, so resolving on that loop stalls all of them at once.
func TestUDPRelay_DomainStallDoesNotBlockOtherTraffic(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	cfg := &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)}

	started := make(chan struct{})
	handler := &shadowsocks.BaseUDPServerHandler{
		Config:     cfg,
		AllowRelay: true,
		Resolver:   hangingResolver(started),
	}

	relayAddr, stopRelay := startUDPRelayWithHandler(t, handler)
	defer stopRelay()

	d := shadowsocks.NewDialer(relayAddr, cfg, nil)
	conn, err := d.ListenPacket(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	// Packets aimed at a domain nothing can resolve.
	var target shadowsocks.Addr
	target.Init(shadowsocks.AddrTypeDomain, nil, "stalled.invalid", 53)
	stalled := &shadowsocks.UDPAddr{Target: target}

	for range 8 {
		if _, err := conn.WriteTo([]byte("stalled"), stalled); err != nil {
			t.Fatalf("WriteTo(domain) error = %v", err)
		}
	}

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("resolver was never consulted; the test is not exercising the stall")
	}

	// A packet to a numeric target must still get through promptly.
	want := []byte("not stalled")
	if _, err := conn.WriteTo(want, echoAddr); err != nil {
		t.Fatalf("WriteTo(ip) error = %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)

	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("relay stalled behind domain resolution: %v", err)
		}
		if string(buf[:n]) == string(want) {
			return
		}
	}
}
