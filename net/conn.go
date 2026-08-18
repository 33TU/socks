package net

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/33TU/socks/internal"
)

// CloseWriter is an interface that wraps the CloseWrite method, which is used to close the write side of a connection.
type CloseWriter interface {
	net.Conn
	CloseWrite() error
}

// DomainPacketConn is a net.PacketConn that can send to a target named by
// domain rather than by address.
//
// A relay whose outbound connection is itself a tunnel should not resolve
// names locally: the tunnel's far end is where the target has to be reached
// from, and resolving here both leaks the lookup and can resolve to an address
// that is only meaningful on this side. Such a connection implements this
// interface so callers can hand the name over instead.
type DomainPacketConn interface {
	net.PacketConn

	// WriteToDomain sends p to domain:port.
	WriteToDomain(p []byte, domain string, port uint16) (int, error)
}

// CopyConn copies data between src and dst with a timeout and buffer size.
func CopyConn(dst, src net.Conn, timeout time.Duration, bufSize int) error {
	defer func() {
		if c, ok := dst.(CloseWriter); ok {
			c.CloseWrite()
		} else {
			dst.Close()
		}
	}()

	if bufSize <= 0 {
		bufSize = 1024 * 32 // default buffer size for io.CopyBuffer
	}

	buf := internal.GetBuffer(bufSize)
	defer internal.PutBuffer(buf)

	// The deadline outlives this call otherwise, and src belongs to the caller.
	defer src.SetDeadline(time.Time{})

	if timeout == 0 {
		_, err := io.CopyBuffer(dst, src, buf.B)
		return err
	}

	// The copy stays inside io.CopyBuffer even with a timeout, because that is
	// what lets the kernel splice one connection into the other: reading and
	// writing here instead costs more than half the throughput.
	//
	// Idleness is enforced around the copy rather than inside it. Each round
	// runs until the deadline, and a round that moved nothing at all is the
	// idle one. A round that moved something starts another, so a connection
	// can sit idle for up to twice the timeout before it is given up on.
	for {
		if err := src.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}

		n, err := io.CopyBuffer(dst, src, buf.B)
		if err == nil || errors.Is(err, io.EOF) {
			return nil
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return err
		}
		if n == 0 {
			return err
		}
	}
}
