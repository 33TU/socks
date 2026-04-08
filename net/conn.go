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
	CloseRead() error
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

	buf := internal.GetBytes(bufSize)
	defer internal.PutBytes(buf)

	for {
		if err := src.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}

		n, err := src.Read(buf)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if _, err := dst.Write(buf[:n]); err != nil {
			return err
		}
	}
}
