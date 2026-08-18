package socks5_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/33TU/socks/socks5"
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

// startUDPEcho starts a UDP server that echoes every datagram back.
func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], from); err != nil {
				return
			}
		}
	}()

	return pc.LocalAddr().(*net.UDPAddr)
}

// associate performs a SOCKS5 UDP ASSOCIATE by hand and returns the relay
// address, so that the test can send packets the client API cannot express.
func associate(t *testing.T, serverAddr string) *net.UDPAddr {
	t.Helper()

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	var hs socks5.HandshakeRequest
	hs.Init(socks5.SocksVersion, socks5.MethodNoAuth)
	if _, err := hs.WriteTo(conn); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	var hsReply socks5.HandshakeReply
	if _, err := hsReply.ReadFrom(conn); err != nil {
		t.Fatalf("read handshake reply: %v", err)
	}

	var req socks5.Request
	req.Init(socks5.SocksVersion, socks5.CmdUDPAssociate, 0, socks5.AddrTypeIPv4, net.IPv4zero, "", 0)
	if _, err := req.WriteTo(conn); err != nil {
		t.Fatalf("write associate request: %v", err)
	}

	var reply socks5.Reply
	if _, err := reply.ReadFrom(conn); err != nil {
		t.Fatalf("read associate reply: %v", err)
	}
	if reply.Reply != socks5.RepSuccess {
		t.Fatalf("associate rejected: %d", reply.Reply)
	}

	relay, err := net.ResolveUDPAddr("udp", reply.Addr())
	if err != nil {
		t.Fatalf("resolve relay address: %v", err)
	}
	if relay.IP.IsUnspecified() {
		relay.IP = net.ParseIP("127.0.0.1")
	}

	return relay
}

func marshalUDPPacket(t *testing.T, addrType byte, ip net.IP, domain string, port uint16, payload []byte) []byte {
	t.Helper()

	var pkt socks5.UDPPacket
	pkt.Init([2]byte{}, 0, addrType, ip, domain, port, payload)

	buf := make([]byte, pkt.Size())
	n, err := pkt.MarshalTo(buf)
	if err != nil {
		t.Fatalf("marshal udp packet: %v", err)
	}

	return buf[:n]
}

// TestUDPAssociate_DomainStallDoesNotBlockOtherTraffic checks that datagrams to
// an unresolvable domain do not hold up the association's other traffic.
// Resolving on the relay's read loop stalls every datagram behind the lookup.
func TestUDPAssociate_DomainStallDoesNotBlockOtherTraffic(t *testing.T) {
	echoAddr := startUDPEcho(t)

	started := make(chan struct{})
	handler := &socks5.BaseServerHandler{
		AllowConnect:           true,
		AllowUDPAssociate:      true,
		UDPAssociateTimeout:    30 * time.Second,
		UDPAssociateBufferSize: 64 * 1024,
		ResolveResolver:        hangingResolver(started),
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go socks5.Serve(ctx, ln, handler)

	relayAddr := associate(t, ln.Addr().String())

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer client.Close()

	// Datagrams aimed at a domain nothing can resolve.
	stalled := marshalUDPPacket(t, socks5.AddrTypeDomain, nil, "stalled.invalid", 53, []byte("stalled"))
	for range 8 {
		if _, err := client.WriteToUDP(stalled, relayAddr); err != nil {
			t.Fatalf("write domain packet: %v", err)
		}
	}

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("resolver was never consulted; the test is not exercising the stall")
	}

	// A datagram to a numeric target must still get through promptly.
	want := []byte("not stalled")
	direct := marshalUDPPacket(t, socks5.AddrTypeIPv4, echoAddr.IP.To4(), "", uint16(echoAddr.Port), want)
	if _, err := client.WriteToUDP(direct, relayAddr); err != nil {
		t.Fatalf("write ip packet: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)

	for {
		n, _, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("relay stalled behind domain resolution: %v", err)
		}

		var pkt socks5.UDPPacket
		if _, err := pkt.UnmarshalFrom(buf[:n]); err != nil {
			continue
		}
		if string(pkt.Data) == string(want) {
			return
		}
	}
}
