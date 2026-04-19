package shadowsocks

import (
	"fmt"
	"net"
	"sync"
)

type TcpConn struct {
	net.Conn

	Reader TCPChunkReader
	Writer TCPChunkWriter

	readBuf []byte

	requestMethod Method
	requestPSK    []byte
	requestSalt   []byte
	requestCipher *TCPStreamCipher

	responseStart *ParsedTCPResponseStart

	readInitMu  sync.Mutex
	writeInitMu sync.Mutex
}

func (c *TcpConn) ensureReadReady() error {
	c.readInitMu.Lock()
	defer c.readInitMu.Unlock()

	if c.Reader.Cipher != nil {
		return nil
	}

	if c.responseStart != nil {
		if c.responseStart.Cipher == nil {
			return fmt.Errorf("missing TCP response cipher")
		}
		if err := c.Reader.Init(c.responseStart.Cipher); err != nil {
			return err
		}
		c.readBuf = append(c.readBuf[:0], c.responseStart.InitialPayload...)
		return nil
	}

	if err := c.requestMethod.Validate(); err != nil {
		return err
	}
	if len(c.requestPSK) != c.requestMethod.KeySize {
		return fmt.Errorf("invalid request PSK length: got %d, want %d", len(c.requestPSK), c.requestMethod.KeySize)
	}
	if len(c.requestSalt) != c.requestMethod.SaltSize {
		return fmt.Errorf("invalid request salt length: got %d, want %d", len(c.requestSalt), c.requestMethod.SaltSize)
	}

	respStart, _, err := ReadTCPResponseStart(c.Conn, c.requestMethod, c.requestPSK, c.requestSalt)
	if err != nil {
		return err
	}
	if err := c.Reader.Init(respStart.Cipher); err != nil {
		return err
	}
	c.responseStart = respStart
	c.readBuf = append(c.readBuf[:0], respStart.InitialPayload...)
	return nil
}

func (c *TcpConn) ensureWriteReady() error {
	c.writeInitMu.Lock()
	defer c.writeInitMu.Unlock()

	if c.Writer.Cipher != nil {
		return nil
	}
	if c.requestCipher == nil {
		return fmt.Errorf("missing TCP request cipher")
	}
	return c.Writer.Init(c.requestCipher)
}

func (c *TcpConn) Read(p []byte) (int, error) {
	if err := c.ensureReadReady(); err != nil {
		return 0, err
	}

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
	if err := c.ensureWriteReady(); err != nil {
		return 0, err
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
