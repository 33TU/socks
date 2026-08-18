package net_test

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	socksnet "github.com/33TU/socks/net"
)

// TestCopyConnIdleTimeout checks that a connection carrying nothing is still
// given up on. The copy runs inside io.CopyBuffer to keep the kernel splicing,
// so the timeout is enforced around it rather than per read.
func TestCopyConnIdleTimeout(t *testing.T) {
	src, dst := net.Pipe()
	defer src.Close()
	defer dst.Close()

	done := make(chan error, 1)
	go func() {
		done <- socksnet.CopyConn(dst, src, 200*time.Millisecond, 4096)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("CopyConn() error = %v, want a deadline error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("an idle connection was never given up on")
	}
}

// TestCopyConnStaysOpenWhileBusy checks that traffic keeps a connection alive
// past the timeout, which the round-based deadline has to get right.
func TestCopyConnStaysOpenWhileBusy(t *testing.T) {
	srcIn, srcOut := net.Pipe()
	dstIn, dstOut := net.Pipe()

	defer srcIn.Close()
	defer dstIn.Close()

	copied := make(chan error, 1)
	go func() {
		copied <- socksnet.CopyConn(dstOut, srcOut, 100*time.Millisecond, 4096)
	}()

	// Drain whatever arrives.
	go io.Copy(io.Discard, dstIn)

	// Keep writing for well past the timeout.
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := srcIn.Write([]byte("still here")); err != nil {
			t.Fatalf("write during copy: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	select {
	case err := <-copied:
		t.Fatalf("CopyConn() returned %v while data was still flowing", err)
	default:
	}

	srcIn.Close()

	select {
	case <-copied:
	case <-time.After(3 * time.Second):
		t.Fatal("CopyConn did not return after the source closed")
	}
}
