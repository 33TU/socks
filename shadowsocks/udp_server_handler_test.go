package shadowsocks_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/33TU/socks/shadowsocks"
)

// recordingUDPHandler records the relay events it receives, and lets a test
// override individual hooks.
type recordingUDPHandler struct {
	shadowsocks.BaseUDPServerHandler

	mu            sync.Mutex
	sessions      []uint64
	targets       []string
	closed        []uint64
	panics        []any
	listenCalls   atomic.Int64
	onPacketHook  func(target shadowsocks.Addr) error
	outboundAddr  *net.UDPAddr
	panicOnPacket atomic.Bool
}

func (h *recordingUDPHandler) OnSession(ctx context.Context, session *shadowsocks.UDPSession) error {
	if err := h.BaseUDPServerHandler.OnSession(ctx, session); err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessions = append(h.sessions, session.ClientSessionID())
	return nil
}

func (h *recordingUDPHandler) ListenPacket(ctx context.Context, session *shadowsocks.UDPSession) (*net.UDPConn, error) {
	h.listenCalls.Add(1)
	return net.ListenUDP("udp", h.outboundAddr)
}

func (h *recordingUDPHandler) OnPacket(ctx context.Context, session *shadowsocks.UDPSession, target shadowsocks.Addr, payload []byte) error {
	if h.panicOnPacket.CompareAndSwap(true, false) {
		panic("handler panic for test")
	}

	if err := h.BaseUDPServerHandler.OnPacket(ctx, session, target, payload); err != nil {
		return err
	}

	h.mu.Lock()
	h.targets = append(h.targets, target.Addr())
	h.mu.Unlock()

	if h.onPacketHook != nil {
		return h.onPacketHook(target)
	}
	return nil
}

func (h *recordingUDPHandler) OnSessionClose(ctx context.Context, session *shadowsocks.UDPSession, errCause error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = append(h.closed, session.ClientSessionID())
}

func (h *recordingUDPHandler) OnPanic(ctx context.Context, r any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.panics = append(h.panics, r)
}

func (h *recordingUDPHandler) snapshot() (sessions, closed []uint64, targets []string, panics []any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]uint64(nil), h.sessions...),
		append([]uint64(nil), h.closed...),
		append([]string(nil), h.targets...),
		append([]any(nil), h.panics...)
}

// startUDPRelayWithHandler serves a relay with the given handler.
func startUDPRelayWithHandler(t *testing.T, handler shadowsocks.UDPServerHandler) (addr string, stop func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp relay: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Surfacing this matters: a relay that fails to start looks exactly
		// like one that drops every packet.
		if err := shadowsocks.ServePacket(ctx, pc, handler); err != nil && ctx.Err() == nil {
			t.Errorf("ServePacket() error = %v", err)
		}
	}()

	return pc.LocalAddr().String(), func() {
		cancel()
		pc.Close()
		<-done
	}
}

func newRecordingHandler(cfg *shadowsocks.Config) *recordingUDPHandler {
	h := &recordingUDPHandler{}
	h.Config = cfg
	h.AllowRelay = true
	return h
}

func TestUDPServerHandler_HooksFire(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	cfg := &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)}

	handler := newRecordingHandler(cfg)
	relayAddr, stopRelay := startUDPRelayWithHandler(t, handler)

	d := shadowsocks.NewDialer(relayAddr, cfg, nil)
	conn, err := d.ListenPacket(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.WriteTo([]byte("ping"), echoAddr); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	buf := make([]byte, 1024)
	if _, _, err := conn.ReadFrom(buf); err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}

	sessions, _, targets, _ := handler.snapshot()
	if len(sessions) != 1 {
		t.Errorf("OnSession called %d times, want 1", len(sessions))
	}
	if sessions[0] != conn.SessionID() {
		t.Errorf("OnSession session = %#x, want %#x", sessions[0], conn.SessionID())
	}
	if len(targets) != 1 || targets[0] != echoAddr.String() {
		t.Errorf("OnPacket targets = %v, want [%s]", targets, echoAddr)
	}
	if got := handler.listenCalls.Load(); got != 1 {
		t.Errorf("ListenPacket called %d times, want 1", got)
	}

	// Shutting the relay down must report the session as closed.
	stopRelay()

	_, closed, _, _ := handler.snapshot()
	if len(closed) == 0 {
		t.Error("OnSessionClose was never called")
	}
}

func TestUDPServerHandler_TargetAuthorizerDropsPacket(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	cfg := &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)}

	handler := newRecordingHandler(cfg)
	handler.onPacketHook = func(target shadowsocks.Addr) error {
		return fmt.Errorf("target %s not allowed", target.Addr())
	}

	relayAddr, stopRelay := startUDPRelayWithHandler(t, handler)
	defer stopRelay()

	d := shadowsocks.NewDialer(relayAddr, cfg, nil)
	conn, err := d.ListenPacket(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	if _, err := conn.WriteTo([]byte("blocked"), echoAddr); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	if n, _, err := conn.ReadFrom(buf); err == nil {
		t.Fatalf("rejected target produced a %d byte reply, want none", n)
	}
}

func TestUDPServerHandler_DisallowedRelayRejectsSession(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	cfg := &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)}

	handler := newRecordingHandler(cfg)
	handler.AllowRelay = false

	relayAddr, stopRelay := startUDPRelayWithHandler(t, handler)
	defer stopRelay()

	d := shadowsocks.NewDialer(relayAddr, cfg, nil)
	conn, err := d.ListenPacket(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	if _, err := conn.WriteTo([]byte("nope"), echoAddr); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	if n, _, err := conn.ReadFrom(buf); err == nil {
		t.Fatalf("disallowed relay produced a %d byte reply, want none", n)
	}

	// No outbound socket should have been opened for a rejected session.
	if got := handler.listenCalls.Load(); got != 0 {
		t.Errorf("ListenPacket called %d times for a rejected session, want 0", got)
	}
}

// TestUDPServerHandler_PanicIsContained checks that a panicking handler takes
// down neither the relay nor the other sessions sharing its read loop.
func TestUDPServerHandler_PanicIsContained(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	cfg := &shadowsocks.Config{Method: methodName, PSK: testPSK(t, methodName)}

	handler := newRecordingHandler(cfg)
	handler.panicOnPacket.Store(true)

	relayAddr, stopRelay := startUDPRelayWithHandler(t, handler)
	defer stopRelay()

	d := shadowsocks.NewDialer(relayAddr, cfg, nil)
	conn, err := d.ListenPacket(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	// This packet makes the handler panic and is therefore never relayed.
	if _, err := conn.WriteTo([]byte("boom"), echoAddr); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	if _, _, err := conn.ReadFrom(buf); err == nil {
		t.Fatal("panicking packet was relayed, want it dropped")
	}

	// The relay must still be serving afterwards.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	want := []byte("still alive")
	if _, err := conn.WriteTo(want, echoAddr); err != nil {
		t.Fatalf("WriteTo() after panic error = %v", err)
	}

	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("relay stopped serving after a handler panic: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Errorf("echo = %q, want %q", buf[:n], want)
	}

	_, _, _, panics := handler.snapshot()
	if len(panics) != 1 {
		t.Errorf("OnPanic called %d times, want 1", len(panics))
	}
}
