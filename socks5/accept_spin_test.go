package socks5_test

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/33TU/socks/socks5"
)

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

// TestServe_AcceptErrorDoesNotSpin checks that a listener returning a
// recoverable error is retried with a backoff. Looping without one pegs a core
// and floods the error handler for as long as the condition lasts.
func TestServe_AcceptErrorDoesNotSpin(t *testing.T) {
	ln := &failingListener{closed: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = socks5.Serve(ctx, ln, nil)
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
