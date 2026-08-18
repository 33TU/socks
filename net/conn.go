package net

import (
	"io"
	"net"
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

	if timeout == 0 {
		_, err := io.Copy(dst, src)
		return err
	}

	if bufSize <= 0 {
		bufSize = 1024 * 32 // default buffer size for io.CopyBuffer
	}

	buf := internal.GetBuffer(bufSize)
	defer internal.PutBuffer(buf)

	for {
		if err := src.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}

		n, err := src.Read(buf.B)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if _, err := dst.Write(buf.B[:n]); err != nil {
			return err
		}
	}
}
