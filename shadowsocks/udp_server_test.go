package shadowsocks_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/33TU/socks/shadowsocks"
)

// startUDPEchoServer starts a UDP server that echoes every datagram back.
func startUDPEchoServer(t *testing.T) (addr *net.UDPAddr, stop func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64*1024)
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

	return pc.LocalAddr().(*net.UDPAddr), func() {
		pc.Close()
		<-done
	}
}

// startUDPRelay starts a Shadowsocks UDP relay server.
func startUDPRelay(t *testing.T, cfg *shadowsocks.Config) (addr string, stop func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp relay: %v", err)
	}

	server := &shadowsocks.UDPServer{Config: cfg}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ctx, pc)
	}()

	return pc.LocalAddr().String(), func() {
		cancel()
		pc.Close()
		<-done
	}
}

func TestUDPRelay_RoundTrip(t *testing.T) {
	for _, methodName := range udpTestMethods() {
		t.Run(methodName, func(t *testing.T) {
			echoAddr, stopEcho := startUDPEchoServer(t)
			defer stopEcho()

			cfg := &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)}
			relayAddr, stopRelay := startUDPRelay(t, cfg)
			defer stopRelay()

			d := shadowsocks.NewDialer(relayAddr, cfg, nil)

			conn, err := d.ListenPacket(context.Background(), nil)
			if err != nil {
				t.Fatalf("ListenPacket() error = %v", err)
			}
			defer conn.Close()

			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

			// Several datagrams over one relay session, each with its own packet ID.
			for i := range 5 {
				want := []byte{byte(i), 'p', 'i', 'n', 'g'}
				if _, err := conn.WriteTo(want, echoAddr); err != nil {
					t.Fatalf("WriteTo() error = %v", err)
				}

				buf := make([]byte, 1024)
				n, from, err := conn.ReadFrom(buf)
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
		})
	}
}

func TestUDPRelay_LargeDatagram(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES256GCM
	cfg := &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)}
	relayAddr, stopRelay := startUDPRelay(t, cfg)
	defer stopRelay()

	d := shadowsocks.NewDialer(relayAddr, cfg, nil)
	conn, err := d.ListenPacket(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	want := make([]byte, 8192)
	for i := range want {
		want[i] = byte(i)
	}

	if _, err := conn.WriteTo(want, echoAddr); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	buf := make([]byte, 64*1024)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatal("large datagram mismatch")
	}
}

// craftedClientPacket builds a raw client packet, bypassing UDPConn so tests can
// control the session ID, packet ID and timestamp.
func craftedClientPacket(
	t *testing.T,
	session *shadowsocks.UDPSessionCipher,
	packetID uint64,
	timestamp time.Time,
	target *net.UDPAddr,
	payload []byte,
) []byte {
	t.Helper()

	var addr shadowsocks.Addr
	addr.Init(shadowsocks.AddrTypeIPv4, target.IP.To4(), "", uint16(target.Port))

	var header shadowsocks.UDPClientHeader
	header.Init(shadowsocks.UDPHeaderTypeClientPacket, uint64(timestamp.Unix()), nil, addr)

	body, err := header.EncodeTo(nil)
	if err != nil {
		t.Fatalf("EncodeTo() error = %v", err)
	}
	body = append(body, payload...)

	packet, err := session.SealTo(nil, packetID, body)
	if err != nil {
		t.Fatalf("SealTo() error = %v", err)
	}

	return packet
}

// newRawRelayClient returns a plain UDP socket aimed at the relay, plus the
// session cipher used to build packets for it.
func newRawRelayClient(t *testing.T, relayAddr, methodName, pskB64 string, sessionID uint64) (*net.UDPConn, *net.UDPAddr, *shadowsocks.UDPSessionCipher) {
	t.Helper()

	method, err := shadowsocks.ParseMethod(methodName)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}
	psk, err := shadowsocks.DecodePSKTo(nil, method, pskB64)
	if err != nil {
		t.Fatalf("DecodePSKTo() error = %v", err)
	}

	cipher, err := shadowsocks.NewUDPCipher(method, psk)
	if err != nil {
		t.Fatalf("NewUDPCipher() error = %v", err)
	}
	session, err := cipher.NewSession(sessionID)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	serverAddr, err := net.ResolveUDPAddr("udp", relayAddr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr() error = %v", err)
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}

	return conn, serverAddr, session
}

func TestUDPRelay_DropsReplayedPacket(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	pskB64 := testPSK(t, methodName)
	cfg := &shadowsocks.Config{Method: methodName, PSK: pskB64}
	relayAddr, stopRelay := startUDPRelay(t, cfg)
	defer stopRelay()

	conn, serverAddr, session := newRawRelayClient(t, relayAddr, methodName, pskB64, 0x1122334455667788)
	defer conn.Close()

	packet := craftedClientPacket(t, session, 0, time.Now(), echoAddr, []byte("replay me"))

	// The same ciphertext twice: the relay must forward it exactly once.
	for range 2 {
		if _, err := conn.WriteToUDP(packet, serverAddr); err != nil {
			t.Fatalf("WriteToUDP() error = %v", err)
		}
	}

	buf := make([]byte, 64*1024)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := conn.ReadFromUDP(buf); err != nil {
		t.Fatalf("first reply not received: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, _, err := conn.ReadFromUDP(buf); err == nil {
		t.Fatalf("replayed packet produced a second reply of %d bytes, want none", n)
	}
}

func TestUDPRelay_DropsStaleTimestamp(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	pskB64 := testPSK(t, methodName)
	cfg := &shadowsocks.Config{Method: methodName, PSK: pskB64}
	relayAddr, stopRelay := startUDPRelay(t, cfg)
	defer stopRelay()

	conn, serverAddr, session := newRawRelayClient(t, relayAddr, methodName, pskB64, 0x99)
	defer conn.Close()

	stale := craftedClientPacket(t, session, 0, time.Now().Add(-5*time.Minute), echoAddr, []byte("stale"))
	if _, err := conn.WriteToUDP(stale, serverAddr); err != nil {
		t.Fatalf("WriteToUDP() error = %v", err)
	}

	buf := make([]byte, 64*1024)
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, _, err := conn.ReadFromUDP(buf); err == nil {
		t.Fatalf("stale packet produced a reply of %d bytes, want none", n)
	}

	// A fresh packet on the same session still works, so the session itself was
	// never established by the stale one.
	fresh := craftedClientPacket(t, session, 1, time.Now(), echoAddr, []byte("fresh"))
	if _, err := conn.WriteToUDP(fresh, serverAddr); err != nil {
		t.Fatalf("WriteToUDP() error = %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := conn.ReadFromUDP(buf); err != nil {
		t.Fatalf("fresh packet after stale one: %v", err)
	}
}

// TestUDPRelay_SurvivesClientAddressChange checks that a relay session is routed
// by client session ID, not source address, and that replies follow the client
// to its new address.
func TestUDPRelay_SurvivesClientAddressChange(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	pskB64 := testPSK(t, methodName)
	cfg := &shadowsocks.Config{Method: methodName, PSK: pskB64}
	relayAddr, stopRelay := startUDPRelay(t, cfg)
	defer stopRelay()

	const sessionID = 0xabcdef

	first, serverAddr, session := newRawRelayClient(t, relayAddr, methodName, pskB64, sessionID)
	defer first.Close()

	buf := make([]byte, 64*1024)

	packet := craftedClientPacket(t, session, 0, time.Now(), echoAddr, []byte("from first socket"))
	if _, err := first.WriteToUDP(packet, serverAddr); err != nil {
		t.Fatalf("WriteToUDP() error = %v", err)
	}

	_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := first.ReadFromUDP(buf); err != nil {
		t.Fatalf("first socket reply: %v", err)
	}

	// The client moves to a new address, keeping its session.
	second, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer second.Close()

	packet = craftedClientPacket(t, session, 1, time.Now(), echoAddr, []byte("from second socket"))
	if _, err := second.WriteToUDP(packet, serverAddr); err != nil {
		t.Fatalf("WriteToUDP() error = %v", err)
	}

	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := second.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("second socket reply: %v", err)
	}
	if n == 0 {
		t.Fatal("empty reply on new client address")
	}
}

// TestUDPConn_IgnoresForeignPackets checks that datagrams a client cannot
// authenticate never surface from ReadFrom.
func TestUDPConn_IgnoresForeignPackets(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	pskB64 := testPSK(t, methodName)
	cfg := &shadowsocks.Config{Method: methodName, PSK: pskB64}
	relayAddr, stopRelay := startUDPRelay(t, cfg)
	defer stopRelay()

	d := shadowsocks.NewDialer(relayAddr, cfg, nil)
	conn, err := d.ListenPacket(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	// Garbage aimed straight at the client's socket.
	attacker, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer attacker.Close()

	clientAddr := conn.LocalAddr().(*net.UDPAddr)
	for range 4 {
		if _, err := attacker.WriteToUDP(bytes.Repeat([]byte{0xff}, 128), clientAddr); err != nil {
			t.Fatalf("WriteToUDP() error = %v", err)
		}
	}

	// A real exchange still comes through, and only that.
	want := []byte("legit")
	if _, err := conn.WriteTo(want, echoAddr); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("read = %q, want %q", buf[:n], want)
	}
}
