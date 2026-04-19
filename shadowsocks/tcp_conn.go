package shadowsocks

import "net"

// TcpConn wraps a proxy TCP connection and exposes plain application reads/writes
// while handling Shadowsocks 2022 TCP chunk framing internally.
type TcpConn struct {
	net.Conn
	Reader  TCPChunkReader
	Writer  TCPChunkWriter
	readBuf []byte
}

func (c *TcpConn) Read(p []byte) (int, error) {
	if len(c.readBuf) == 0 {
		buf, _, err := c.Reader.ReadChunkTo(nil, c.Conn)
		if err != nil {
			return 0, err
		}
		c.readBuf = buf
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *TcpConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	written := 0
	for len(p) > 0 {
		nn := len(p)
		if nn > 0xFFFF {
			nn = 0xFFFF
		}

		if _, err := c.Writer.WriteChunk(c.Conn, p[:nn]); err != nil {
			return written, err
		}

		written += nn
		p = p[nn:]
	}

	return written, nil
}

var _ net.Conn = (*TcpConn)(nil)
