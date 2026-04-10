package proxy

import "net"

type peekConn struct {
	net.Conn

	initialByte    byte
	hasInitialByte bool
}

// newPeekConn reads the first byte immediately
func newPeekConn(conn net.Conn) (*peekConn, error) {
	var b [1]byte
	if _, err := conn.Read(b[:]); err != nil {
		return nil, err
	}

	return &peekConn{
		Conn:           conn,
		initialByte:    b[0],
		hasInitialByte: true,
	}, nil
}

func (c *peekConn) Read(p []byte) (int, error) {
	if c.hasInitialByte && len(p) > 0 {
		p[0] = c.initialByte
		c.hasInitialByte = false

		n, err := c.Conn.Read(p[1:])
		return n + 1, err
	}

	return c.Conn.Read(p)
}
