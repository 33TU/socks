package shadowsocks_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/33TU/socks/shadowsocks"
	"github.com/33TU/socks/socks5"
)

// startLocalSOCKS5 starts a SOCKS5 front end whose traffic leaves through a
// Shadowsocks proxy, which is how a Shadowsocks client is normally deployed.
func startLocalSOCKS5(t *testing.T, dialer *shadowsocks.Dialer) (addr string, stop func()) {
	t.Helper()

	handler := &socks5.BaseServerHandler{
		Dialer:                 dialer,
		AllowConnect:           true,
		AllowUDPAssociate:      true,
		UDPAssociateTimeout:    30 * time.Second,
		UDPAssociateBufferSize: 64 * 1024,
		UDPListenPacket: func(ctx context.Context, _ net.Conn, _ *socks5.Request) (net.PacketConn, error) {
			return dialer.ListenPacket(ctx, nil)
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = socks5.Serve(ctx, ln, handler)
	}()

	return ln.Addr().String(), func() {
		cancel()
		ln.Close()
		<-done
	}
}

// TestSOCKS5UDPOverShadowsocks relays UDP from a SOCKS5 client through a
// Shadowsocks proxy, the full local-front-end deployment.
func TestSOCKS5UDPOverShadowsocks(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	cfg := &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)}

	relayAddr, stopRelay := startUDPRelay(t, cfg)
	defer stopRelay()

	ssDialer := shadowsocks.NewDialer(relayAddr, cfg, nil)

	localAddr, stopLocal := startLocalSOCKS5(t, ssDialer)
	defer stopLocal()

	socksDialer := socks5.NewDialer(localAddr, nil, nil)
	pc, err := socksDialer.ListenPacket(context.Background(), "tcp", nil)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	_ = pc.SetDeadline(time.Now().Add(10 * time.Second))

	for i := range 3 {
		want := []byte{byte(i), 'u', 'd', 'p'}
		if _, err := pc.WriteTo(want, echoAddr); err != nil {
			t.Fatalf("WriteTo() error = %v", err)
		}

		buf := make([]byte, 2048)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom() error = %v", err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("echo = %q, want %q", buf[:n], want)
		}

		udpFrom, ok := from.(*net.UDPAddr)
		if !ok {
			t.Fatalf("source address type = %T, want *net.UDPAddr", from)
		}
		if udpFrom.Port != echoAddr.Port {
			t.Errorf("source port = %d, want %d", udpFrom.Port, echoAddr.Port)
		}
	}
}

// TestSOCKS5UDPOverShadowsocks_DomainTargetResolvesRemotely checks that a
// domain target is carried to the Shadowsocks server by name. Resolving it in
// the front end would leak the lookup and defeat the point of the tunnel.
func TestSOCKS5UDPOverShadowsocks_DomainTargetResolvesRemotely(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	cfg := &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)}

	// The relay resolves any name to the echo server, and records what it saw.
	resolved := make(chan string, 4)
	handler := &shadowsocks.BaseUDPServerHandler{
		Config:     cfg,
		AllowRelay: true,
		Resolver:   fixedResolver(t, echoAddr.IP),
		TargetAuthorizer: func(_ context.Context, _ *shadowsocks.UDPSession, target shadowsocks.Addr, _ []byte) error {
			if target.AddrType == shadowsocks.AddrTypeDomain {
				select {
				case resolved <- target.Domain:
				default:
				}
			}
			return nil
		},
	}

	relayAddr, stopRelay := startUDPRelayWithHandler(t, handler)
	defer stopRelay()

	ssDialer := shadowsocks.NewDialer(relayAddr, cfg, nil)

	localAddr, stopLocal := startLocalSOCKS5(t, ssDialer)
	defer stopLocal()

	// The SOCKS5 client names a domain the front end cannot resolve.
	conn, err := net.Dial("tcp", localAddr)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	defer conn.Close()

	relay := socks5Associate(t, conn)

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer client.Close()

	want := []byte("through the tunnel")
	packet := socks5DomainPacket(t, "only-the-server-knows.invalid", uint16(echoAddr.Port), want)
	if _, err := client.WriteToUDP(packet, relay); err != nil {
		t.Fatalf("write domain packet: %v", err)
	}

	select {
	case got := <-resolved:
		if got != "only-the-server-knows.invalid" {
			t.Errorf("server saw target %q, want the name sent by the client", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the Shadowsocks server never saw a domain target: the name was resolved locally")
	}

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)

	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no reply for the domain target: %v", err)
	}

	var reply socks5.UDPPacket
	if _, err := reply.UnmarshalFrom(buf[:n]); err != nil {
		t.Fatalf("UnmarshalFrom() error = %v", err)
	}
	if !bytes.Equal(reply.Data, want) {
		t.Errorf("echo = %q, want %q", reply.Data, want)
	}
}

// fixedResolver resolves every name to ip.
func fixedResolver(t *testing.T, ip net.IP) *net.Resolver {
	t.Helper()

	dns := startFixedDNS(t, ip)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", dns)
		},
	}
}
