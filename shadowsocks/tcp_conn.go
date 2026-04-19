package shadowsocks

import (
	"fmt"
	"net"
	"time"
)

type TCPConn struct {
	net.Conn

	Reader   TCPChunkReader
	Writer   TCPChunkWriter
	readBuf  []byte
	chunkBuf []byte

	responseMethod Method
	responsePSK    []byte
	requestSalt    []byte
}

func NewClientTCPConn(
	conn net.Conn,
	method Method,
	psk []byte,
	target Addr,
	padding []byte,
	initialPayload []byte,
) (*TCPConn, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil net.Conn")
	}
	if err := method.Validate(); err != nil {
		return nil, err
	}
	if len(psk) != method.KeySize {
		return nil, fmt.Errorf("invalid PSK length: got %d, want %d", len(psk), method.KeySize)
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}

	requestSalt := make([]byte, method.SaltSize)
	if err := FillSaltTo(requestSalt, method); err != nil {
		return nil, err
	}

	requestCipher, _, err := WriteTCPRequestStart(
		conn,
		method,
		psk,
		requestSalt,
		time.Now(),
		target,
		padding,
		initialPayload,
	)
	if err != nil {
		return nil, err
	}

	var writer TCPChunkWriter
	if err := writer.Init(requestCipher); err != nil {
		return nil, err
	}

	return &TCPConn{
		Conn:           conn,
		Writer:         writer,
		responseMethod: method,
		responsePSK:    append([]byte(nil), psk...),
		requestSalt:    append([]byte(nil), requestSalt...),
	}, nil
}

func NewServerTCPConn(conn net.Conn, method Method, psk []byte) (*TCPConn, *ParsedTCPRequestStart, error) {
	if conn == nil {
		return nil, nil, fmt.Errorf("nil net.Conn")
	}
	if err := method.Validate(); err != nil {
		return nil, nil, err
	}
	if len(psk) != method.KeySize {
		return nil, nil, fmt.Errorf("invalid PSK length: got %d, want %d", len(psk), method.KeySize)
	}

	reqStart, _, err := ReadTCPRequestStart(conn, method, psk)
	if err != nil {
		return nil, nil, err
	}

	var reader TCPChunkReader
	if err := reader.Init(reqStart.Cipher); err != nil {
		return nil, nil, err
	}

	c := &TCPConn{
		Conn:   conn,
		Reader: reader,
	}

	if len(reqStart.Header.InitialData) > 0 {
		c.chunkBuf = append(c.chunkBuf[:0], reqStart.Header.InitialData...)
		c.readBuf = c.chunkBuf
	}

	return c, reqStart, nil
}

func (c *TCPConn) InitResponse(method Method, psk []byte, requestSalt []byte, initialPayload []byte) error {
	if c == nil {
		return fmt.Errorf("nil TCPConn")
	}
	if c.Conn == nil {
		return fmt.Errorf("nil net.Conn")
	}
	if err := method.Validate(); err != nil {
		return err
	}
	if len(psk) != method.KeySize {
		return fmt.Errorf("invalid PSK length: got %d, want %d", len(psk), method.KeySize)
	}
	if len(requestSalt) != method.SaltSize {
		return fmt.Errorf("invalid request salt length: got %d, want %d", len(requestSalt), method.SaltSize)
	}

	responseSalt := make([]byte, method.SaltSize)
	if err := FillSaltTo(responseSalt, method); err != nil {
		return err
	}

	responseCipher, _, err := WriteTCPResponseStart(
		c.Conn,
		method,
		psk,
		responseSalt,
		time.Now(),
		requestSalt,
		initialPayload,
	)
	if err != nil {
		return err
	}

	return c.Writer.Init(responseCipher)
}

func (c *TCPConn) ensureClientResponseReady() error {
	if c == nil {
		return fmt.Errorf("nil TCPConn")
	}
	if c.Conn == nil {
		return fmt.Errorf("nil net.Conn")
	}
	if c.Reader.Cipher != nil {
		return nil
	}
	if err := c.responseMethod.Validate(); err != nil {
		return err
	}
	if len(c.responsePSK) != c.responseMethod.KeySize {
		return fmt.Errorf("invalid response PSK length: got %d, want %d", len(c.responsePSK), c.responseMethod.KeySize)
	}
	if len(c.requestSalt) != c.responseMethod.SaltSize {
		return fmt.Errorf("invalid request salt length: got %d, want %d", len(c.requestSalt), c.responseMethod.SaltSize)
	}

	respStart, _, err := ReadTCPResponseStart(c.Conn, c.responseMethod, c.responsePSK, c.requestSalt)
	if err != nil {
		return err
	}

	if err := c.Reader.Init(respStart.Cipher); err != nil {
		return err
	}

	if len(respStart.InitialPayload) > 0 {
		c.chunkBuf = append(c.chunkBuf[:0], respStart.InitialPayload...)
		c.readBuf = c.chunkBuf
	}

	return nil
}

func (c *TCPConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c == nil {
		return 0, fmt.Errorf("nil TCPConn")
	}
	if c.Reader.Cipher == nil {
		if err := c.ensureClientResponseReady(); err != nil {
			return 0, err
		}
	}
	if c.Reader.Cipher == nil {
		return 0, fmt.Errorf("TCP reader not initialized")
	}

	if len(c.readBuf) == 0 {
		buf, _, err := c.Reader.ReadChunkTo(c.chunkBuf[:0], c.Conn)
		if err != nil {
			return 0, err
		}
		c.chunkBuf = buf
		c.readBuf = buf
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *TCPConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c == nil {
		return 0, fmt.Errorf("nil TCPConn")
	}
	if c.Writer.Cipher == nil {
		return 0, fmt.Errorf("TCP writer not initialized")
	}

	written := 0
	for len(p) > 0 {
		nn := min(len(p), 0xFFFF)
		if _, err := c.Writer.WriteChunk(c.Conn, p[:nn]); err != nil {
			return written, err
		}
		written += nn
		p = p[nn:]
	}
	return written, nil
}

var _ net.Conn = (*TCPConn)(nil)
