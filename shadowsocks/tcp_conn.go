package shadowsocks

import (
	"fmt"
	"net"
	"time"

	socksnet "github.com/33TU/socks/net"
)

// TCPConn is a net.Conn carrying one Shadowsocks 2022 proxy connection.
//
// A proxy connection consists of two independent streams. The client writes the
// request stream and reads the response stream; the server does the opposite.
// Both streams start lazily in the reading direction: a client reads the
// response start on its first Read, and a server writes the response start on
// its first Write, so that the response header always travels with payload.
type TCPConn struct {
	net.Conn

	Reader TCPChunkReader
	Writer TCPChunkWriter

	method      Method
	psk         []byte
	requestSalt []byte

	// responsePending marks a server connection whose response stream has not
	// been started yet.
	responsePending bool
}

// NewClientTCPConn starts a request stream on conn and returns the proxy connection.
//
// Either padding or initialPayload must be non-empty. The salt and both header
// chunks are written to conn in a single write call.
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

	c := &TCPConn{
		Conn:        conn,
		method:      method,
		psk:         append([]byte(nil), psk...),
		requestSalt: requestSalt,
	}
	if err := c.Writer.Init(requestCipher, conn); err != nil {
		return nil, err
	}

	return c, nil
}

// NewServerTCPConn reads a request stream start from conn and returns the proxy
// connection along with the parsed request.
//
// The request timestamp is checked against now and its salt against replay,
// which may be nil to skip the replay check. The response stream is started on
// the first Write.
func NewServerTCPConn(conn net.Conn, method Method, psk []byte, now time.Time, replay *ReplayCache) (*TCPConn, *ParsedTCPRequestStart, error) {
	if conn == nil {
		return nil, nil, fmt.Errorf("nil net.Conn")
	}
	if err := method.Validate(); err != nil {
		return nil, nil, err
	}
	if len(psk) != method.KeySize {
		return nil, nil, fmt.Errorf("invalid PSK length: got %d, want %d", len(psk), method.KeySize)
	}

	reqStart, _, err := ReadTCPRequestStart(conn, method, psk, now, replay)
	if err != nil {
		return nil, nil, err
	}

	c := &TCPConn{
		Conn:            conn,
		method:          method,
		psk:             append([]byte(nil), psk...),
		requestSalt:     reqStart.Salt,
		responsePending: true,
	}
	if err := c.Reader.Init(reqStart.Cipher, conn); err != nil {
		return nil, nil, err
	}

	// The initial payload arrived inside the header chunk, ahead of the stream.
	if len(reqStart.Header.InitialData) > 0 {
		c.Reader.pushFront(reqStart.Header.InitialData)
	}

	return c, reqStart, nil
}

// RequestSalt returns the salt of the request stream.
func (c *TCPConn) RequestSalt() []byte {
	return c.requestSalt
}

// InitResponse starts the response stream, writing the response salt, header and
// first payload chunk in a single write call.
//
// Servers normally let the first Write start the response stream instead.
func (c *TCPConn) InitResponse(initialPayload []byte) error {
	if c == nil {
		return fmt.Errorf("nil TCPConn")
	}
	if c.Conn == nil {
		return fmt.Errorf("nil net.Conn")
	}
	if len(initialPayload) > MaxTCPChunkPayloadLength {
		return fmt.Errorf("initial payload too large: got %d, max %d", len(initialPayload), MaxTCPChunkPayloadLength)
	}
	if err := c.method.Validate(); err != nil {
		return err
	}
	if len(c.psk) != c.method.KeySize {
		return fmt.Errorf("invalid PSK length: got %d, want %d", len(c.psk), c.method.KeySize)
	}
	if len(c.requestSalt) != c.method.SaltSize {
		return fmt.Errorf("invalid request salt length: got %d, want %d", len(c.requestSalt), c.method.SaltSize)
	}

	responseSalt := make([]byte, c.method.SaltSize)
	if err := FillSaltTo(responseSalt, c.method); err != nil {
		return err
	}

	responseCipher, _, err := WriteTCPResponseStart(
		c.Conn,
		c.method,
		c.psk,
		responseSalt,
		time.Now(),
		c.requestSalt,
		initialPayload,
	)
	if err != nil {
		return err
	}

	c.responsePending = false
	return c.Writer.Init(responseCipher, c.Conn)
}

// ensureClientResponseReady reads the response stream start on a client connection.
func (c *TCPConn) ensureClientResponseReady() error {
	if c.Conn == nil {
		return fmt.Errorf("nil net.Conn")
	}
	if err := c.method.Validate(); err != nil {
		return err
	}
	if len(c.psk) != c.method.KeySize {
		return fmt.Errorf("invalid response PSK length: got %d, want %d", len(c.psk), c.method.KeySize)
	}
	if len(c.requestSalt) != c.method.SaltSize {
		return fmt.Errorf("invalid request salt length: got %d, want %d", len(c.requestSalt), c.method.SaltSize)
	}

	respStart, _, err := ReadTCPResponseStart(c.Conn, c.method, c.psk, c.requestSalt, time.Now())
	if err != nil {
		return err
	}

	if err := c.Reader.Init(respStart.Cipher, c.Conn); err != nil {
		return err
	}

	// The first payload chunk follows the header immediately, ahead of the stream.
	if len(respStart.InitialPayload) > 0 {
		c.Reader.pushFront(respStart.InitialPayload)
	}

	return nil
}

func (c *TCPConn) Read(p []byte) (int, error) {
	if c == nil {
		return 0, fmt.Errorf("nil TCPConn")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.Reader.Cipher == nil {
		if err := c.ensureClientResponseReady(); err != nil {
			return 0, err
		}
	}
	return c.Reader.Read(p)
}

func (c *TCPConn) Write(p []byte) (int, error) {
	if c == nil {
		return 0, fmt.Errorf("nil TCPConn")
	}
	if len(p) == 0 {
		return 0, nil
	}

	if c.responsePending {
		// The response header must be sent along with payload, so the first
		// chunk rides inside the response start.
		initial := p
		if len(initial) > MaxTCPChunkPayloadLength {
			initial = initial[:MaxTCPChunkPayloadLength]
		}
		if err := c.InitResponse(initial); err != nil {
			return 0, err
		}

		rest := p[len(initial):]
		if len(rest) == 0 {
			return len(initial), nil
		}

		n, err := c.Writer.Write(rest)
		return len(initial) + n, err
	}

	return c.Writer.Write(p)
}

// CloseWrite shuts down the writing half of the underlying connection.
//
// Shadowsocks streams carry no end-of-stream marker, so a half close is how the
// end of a stream is signalled to the peer.
func (c *TCPConn) CloseWrite() error {
	if c == nil || c.Conn == nil {
		return fmt.Errorf("nil TCPConn")
	}
	if cw, ok := c.Conn.(socksnet.CloseWriter); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

var (
	_ net.Conn             = (*TCPConn)(nil)
	_ socksnet.CloseWriter = (*TCPConn)(nil)
)
