package shadowsocks_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	"github.com/33TU/socks/shadowsocks"
	"github.com/zeebo/blake3"
)

func identityTestKey(method shadowsocks.Method, seed byte) []byte {
	psk := make([]byte, method.KeySize)
	for i := range psk {
		psk[i] = seed + byte(i)
	}
	return psk
}

func TestPSKHash(t *testing.T) {
	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	psk := identityTestKey(method, 1)

	// The spec names a key by the first 16 bytes of its BLAKE3 hash.
	want := blake3.Sum256(psk)
	got := shadowsocks.PSKHash(psk)

	if !bytes.Equal(got[:], want[:shadowsocks.IdentityHeaderLen]) {
		t.Errorf("PSKHash = %x, want %x", got, want[:shadowsocks.IdentityHeaderLen])
	}
}

func TestTCPIdentityHeaders_RoundTrip(t *testing.T) {
	for _, methodName := range []string{
		shadowsocks.Method2022Blake3AES128GCM,
		shadowsocks.Method2022Blake3AES256GCM,
	} {
		t.Run(methodName, func(t *testing.T) {
			method, err := shadowsocks.ParseMethod(methodName)
			if err != nil {
				t.Fatalf("ParseMethod() error = %v", err)
			}

			ipsk0 := identityTestKey(method, 1)
			ipsk1 := identityTestKey(method, 2)
			upsk := identityTestKey(method, 3)
			salt := bytes.Repeat([]byte{0x42}, method.SaltSize)

			headers, err := shadowsocks.EncodeTCPIdentityHeadersTo(nil, method, [][]byte{ipsk0, ipsk1}, upsk, salt)
			if err != nil {
				t.Fatalf("EncodeTCPIdentityHeadersTo() error = %v", err)
			}
			if len(headers) != 2*shadowsocks.IdentityHeaderLen {
				t.Fatalf("headers length = %d, want %d", len(headers), 2*shadowsocks.IdentityHeaderLen)
			}

			// Each layer names the key that follows it: the first names iPSK1,
			// and the last names the user PSK.
			first, err := shadowsocks.DecodeTCPIdentityHeader(headers[:shadowsocks.IdentityHeaderLen], method, ipsk0, salt)
			if err != nil {
				t.Fatalf("DecodeTCPIdentityHeader() error = %v", err)
			}
			if want := shadowsocks.PSKHash(ipsk1); first != want {
				t.Errorf("first header names %x, want %x", first, want)
			}

			second, err := shadowsocks.DecodeTCPIdentityHeader(headers[shadowsocks.IdentityHeaderLen:], method, ipsk1, salt)
			if err != nil {
				t.Fatalf("DecodeTCPIdentityHeader() error = %v", err)
			}
			if want := shadowsocks.PSKHash(upsk); second != want {
				t.Errorf("second header names %x, want %x", second, want)
			}
		})
	}
}

// TestTCPIdentityHeaders_BoundToSalt checks that a header cannot be lifted from
// one session and replayed into another: the subkey is derived from the salt.
func TestTCPIdentityHeaders_BoundToSalt(t *testing.T) {
	method, _ := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)

	ipsk := identityTestKey(method, 1)
	upsk := identityTestKey(method, 2)

	first, err := shadowsocks.EncodeTCPIdentityHeadersTo(nil, method, [][]byte{ipsk}, upsk, bytes.Repeat([]byte{0x01}, method.SaltSize))
	if err != nil {
		t.Fatalf("EncodeTCPIdentityHeadersTo() error = %v", err)
	}

	second, err := shadowsocks.EncodeTCPIdentityHeadersTo(nil, method, [][]byte{ipsk}, upsk, bytes.Repeat([]byte{0x02}, method.SaltSize))
	if err != nil {
		t.Fatalf("EncodeTCPIdentityHeadersTo() error = %v", err)
	}

	if bytes.Equal(first, second) {
		t.Error("identity header is identical across salts, want it bound to the session")
	}
}

func TestUserTable(t *testing.T) {
	method, _ := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)

	table := shadowsocks.NewUserTable()
	alice := identityTestKey(method, 10)

	if err := table.Add("alice", method, alice); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := table.AddBase64("bob", method, base64.StdEncoding.EncodeToString(identityTestKey(method, 20))); err != nil {
		t.Fatalf("AddBase64() error = %v", err)
	}
	if got := table.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}

	user, ok := table.Lookup(shadowsocks.PSKHash(alice))
	if !ok || user.Name != "alice" {
		t.Fatalf("Lookup() = (%q, %v), want alice", user.Name, ok)
	}

	if _, ok := table.Lookup(shadowsocks.PSKHash(identityTestKey(method, 99))); ok {
		t.Error("Lookup() of an unregistered PSK succeeded, want a miss")
	}

	table.Remove("alice")
	if _, ok := table.Lookup(shadowsocks.PSKHash(alice)); ok {
		t.Error("Lookup() after Remove succeeded, want a miss")
	}

	// A PSK of the wrong size is rejected rather than stored unusable.
	if err := table.Add("short", method, []byte{1, 2, 3}); err == nil {
		t.Error("Add() with a short PSK succeeded, want an error")
	}
}

// TestServer_MultiUser runs the whole path: a client presenting iPSK:uPSK is
// identified by the server, which then protects the session with that user's key.
func TestServer_MultiUser(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	method, _ := shadowsocks.ParseMethod(methodName)

	identityPSK := identityTestKey(method, 1)
	alicePSK := identityTestKey(method, 40)
	bobPSK := identityTestKey(method, 60)

	users := shadowsocks.NewUserTable()
	if err := users.Add("alice", method, alicePSK); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := users.Add("bob", method, bobPSK); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	identified := make(chan string, 4)
	handler := &shadowsocks.BaseServerHandler{
		AllowConnect: true,
		Users:        users,
		DrainTimeout: time.Second,
	}

	serverCfg := &shadowsocks.Config{
		Method: methodName,
		PSK:    base64.StdEncoding.EncodeToString(identityPSK),
	}

	proxyAddr, stopProxy := startShadowsocksServerWithUsers(t, serverCfg, handler, identified)
	defer stopProxy()

	for _, tt := range []struct {
		name string
		psk  []byte
	}{
		{"alice", alicePSK},
		{"bob", bobPSK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// The client presents the server's identity key, then its own.
			clientCfg := &shadowsocks.Config{
				Method: methodName,
				PSK: base64.StdEncoding.EncodeToString(identityPSK) + ":" +
					base64.StdEncoding.EncodeToString(tt.psk),
			}

			d := shadowsocks.NewDialer(proxyAddr, clientCfg, nil)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			conn, err := d.DialContext(ctx, "tcp", echoAddr)
			if err != nil {
				t.Fatalf("DialContext() error = %v", err)
			}
			defer conn.Close()

			want := []byte("hello from " + tt.name)
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

			select {
			case name := <-identified:
				if name != tt.name {
					t.Errorf("server identified %q, want %q", name, tt.name)
				}
			case <-time.After(time.Second):
				t.Error("server did not identify the user")
			}
		})
	}
}

// TestServer_MultiUser_RejectsUnknownUser checks that a client whose user PSK
// the server does not know is turned away.
func TestServer_MultiUser_RejectsUnknownUser(t *testing.T) {
	methodName := shadowsocks.Method2022Blake3AES128GCM
	method, _ := shadowsocks.ParseMethod(methodName)

	identityPSK := identityTestKey(method, 1)

	users := shadowsocks.NewUserTable()
	if err := users.Add("alice", method, identityTestKey(method, 40)); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	handler := &shadowsocks.BaseServerHandler{
		AllowConnect: true,
		Users:        users,
		DrainTimeout: time.Second,
	}

	serverCfg := &shadowsocks.Config{
		Method: methodName,
		PSK:    base64.StdEncoding.EncodeToString(identityPSK),
	}

	proxyAddr, stopProxy := startShadowsocksServerWithUsers(t, serverCfg, handler, nil)
	defer stopProxy()

	// A stranger holding the identity key but no registered user PSK.
	clientCfg := &shadowsocks.Config{
		Method: methodName,
		PSK: base64.StdEncoding.EncodeToString(identityPSK) + ":" +
			base64.StdEncoding.EncodeToString(identityTestKey(method, 99)),
	}

	d := shadowsocks.NewDialer(proxyAddr, clientCfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:9")
	if err != nil {
		return // rejected during the handshake, which is fine
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("let me in")); err != nil {
		return
	}

	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("unknown user was served, want rejection")
	}
}

// startShadowsocksServerWithUsers serves a multi-user handler, reporting which
// user each request was attributed to.
func startShadowsocksServerWithUsers(
	t *testing.T,
	cfg *shadowsocks.Config,
	handler *shadowsocks.BaseServerHandler,
	identified chan<- string,
) (addr string, stop func()) {
	t.Helper()

	handler.Config = cfg

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen shadowsocks: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = shadowsocks.Serve(ctx, ln, &identifyingHandler{
			ServerHandler: handler,
			identified:    identified,
		})
	}()

	return ln.Addr().String(), func() {
		cancel()
		ln.Close()
		<-done
	}
}

// identifyingHandler reports the user each request was attributed to.
type identifyingHandler struct {
	shadowsocks.ServerHandler
	identified chan<- string
}

func (h *identifyingHandler) OnRequest(ctx context.Context, conn *shadowsocks.TCPConn, req *shadowsocks.ParsedTCPRequestStart) error {
	if h.identified != nil {
		select {
		case h.identified <- req.User.Name:
		default:
		}
	}
	return h.ServerHandler.OnRequest(ctx, conn, req)
}

// TestUDPIdentityHeaders_RoundTrip checks the UDP construction, which masks the
// named hash with the packet's session and packet ID rather than binding it to
// a salt as TCP does.
func TestUDPIdentityHeaders_RoundTrip(t *testing.T) {
	method, _ := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)

	ipsk := identityTestKey(method, 1)
	upsk := identityTestKey(method, 2)

	separate := make([]byte, shadowsocks.UDPSeparateHeaderLen)
	for i := range separate {
		separate[i] = byte(i)
	}

	headers, err := shadowsocks.EncodeUDPIdentityHeadersTo(nil, [][]byte{ipsk}, upsk, separate)
	if err != nil {
		t.Fatalf("EncodeUDPIdentityHeadersTo() error = %v", err)
	}

	named, err := shadowsocks.DecodeUDPIdentityHeader(headers, ipsk, separate)
	if err != nil {
		t.Fatalf("DecodeUDPIdentityHeader() error = %v", err)
	}
	if want := shadowsocks.PSKHash(upsk); named != want {
		t.Errorf("header names %x, want %x", named, want)
	}

	// A different packet must produce a different header.
	other := append([]byte(nil), separate...)
	other[0] ^= 0xff

	otherHeaders, err := shadowsocks.EncodeUDPIdentityHeadersTo(nil, [][]byte{ipsk}, upsk, other)
	if err != nil {
		t.Fatalf("EncodeUDPIdentityHeadersTo() error = %v", err)
	}
	if bytes.Equal(headers, otherHeaders) {
		t.Error("identity header is identical across packets, want it masked per packet")
	}
}

// TestUDPRelay_MultiUser runs a multi-user UDP relay end to end.
func TestUDPRelay_MultiUser(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	method, _ := shadowsocks.ParseMethod(methodName)

	identityPSK := identityTestKey(method, 1)
	alicePSK := identityTestKey(method, 40)

	users := shadowsocks.NewUserTable()
	if err := users.Add("alice", method, alicePSK); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	serverCfg := &shadowsocks.Config{
		Method: methodName,
		PSK:    base64.StdEncoding.EncodeToString(identityPSK),
	}

	seen := make(chan string, 4)
	handler := &shadowsocks.BaseUDPServerHandler{
		Config:     serverCfg,
		AllowRelay: true,
		Users:      users,
		TargetAuthorizer: func(_ context.Context, session *shadowsocks.UDPSession, _ shadowsocks.Addr, _ []byte) error {
			select {
			case seen <- session.User().Name:
			default:
			}
			return nil
		},
	}

	relayAddr, stopRelay := startUDPRelayWithHandler(t, handler)
	defer stopRelay()

	clientCfg := &shadowsocks.Config{
		Method: methodName,
		PSK: base64.StdEncoding.EncodeToString(identityPSK) + ":" +
			base64.StdEncoding.EncodeToString(alicePSK),
	}

	d := shadowsocks.NewDialer(relayAddr, clientCfg, nil)
	conn, err := d.ListenPacket(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	want := []byte("multi-user udp")
	if _, err := conn.WriteTo(want, echoAddr); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	buf := make([]byte, 2048)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("echo = %q, want %q", buf[:n], want)
	}

	select {
	case name := <-seen:
		if name != "alice" {
			t.Errorf("relay attributed the packet to %q, want alice", name)
		}
	case <-time.After(time.Second):
		t.Error("relay never reported which user sent the packet")
	}
}

// TestUDPRelay_MultiUser_RejectsUnknownUser checks that a packet naming a user
// the relay does not know is dropped.
func TestUDPRelay_MultiUser_RejectsUnknownUser(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	method, _ := shadowsocks.ParseMethod(methodName)

	identityPSK := identityTestKey(method, 1)

	users := shadowsocks.NewUserTable()
	if err := users.Add("alice", method, identityTestKey(method, 40)); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	handler := &shadowsocks.BaseUDPServerHandler{
		Config: &shadowsocks.Config{
			Method: methodName,
			PSK:    base64.StdEncoding.EncodeToString(identityPSK),
		},
		AllowRelay: true,
		Users:      users,
	}

	relayAddr, stopRelay := startUDPRelayWithHandler(t, handler)
	defer stopRelay()

	clientCfg := &shadowsocks.Config{
		Method: methodName,
		PSK: base64.StdEncoding.EncodeToString(identityPSK) + ":" +
			base64.StdEncoding.EncodeToString(identityTestKey(method, 99)),
	}

	d := shadowsocks.NewDialer(relayAddr, clientCfg, nil)
	conn, err := d.ListenPacket(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	if _, err := conn.WriteTo([]byte("let me in"), echoAddr); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 2048)
	if n, _, err := conn.ReadFrom(buf); err == nil {
		t.Fatalf("unknown user got a %d byte reply, want the packet dropped", n)
	}
}
