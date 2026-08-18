package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/33TU/socks/internal"
)

// UDPAddr adapts a Shadowsocks address to net.Addr, so datagrams can be sent to
// a domain name, which net.UDPAddr cannot express.
type UDPAddr struct {
	Target Addr
}

// Network implements net.Addr.
func (a *UDPAddr) Network() string { return "udp" }

// String implements net.Addr.
func (a *UDPAddr) String() string { return a.Target.Addr() }

var _ net.Addr = (*UDPAddr)(nil)

// UDPConnConfig configures a client UDP relay session.
type UDPConnConfig struct {
	// Padding decides the padding added to packet headers.
	// A nil policy means PadPlainDNS(MaxPaddingLength).
	Padding PaddingPolicy

	// BufferSize is the read buffer size. Zero means DefaultUDPBufferSize.
	BufferSize int

	// FilterSize is the sliding window size used to reject replayed packets.
	// Zero means DefaultSlidingWindowFilterSize.
	FilterSize uint64
}

// udpServerSession is the client's view of one server relay session.
type udpServerSession struct {
	sessionID uint64
	cipher    *UDPSessionCipher
	filter    *SlidingWindowFilter
	lastSeen  time.Time
}

// UDPConn is a net.PacketConn that tunnels datagrams through a Shadowsocks 2022
// proxy as a single relay session.
//
// Outgoing packets carry the client session ID and an incrementing packet ID.
// Incoming packets are matched to a server session; because a server may restart
// and start a new session, the current and the previous server session are both
// accepted, and a further new session is refused while the previous one is still
// fresh, as the protocol requires.
type UDPConn struct {
	conn       net.PacketConn
	serverAddr net.Addr

	cipher     *UDPCipher
	padding    PaddingPolicy
	bufferSize int
	filterSize uint64

	sessionID uint64
	session   *UDPSessionCipher
	packetID  atomic.Uint64

	// mu guards the server session state, and is held from routing an incoming
	// packet to a session through recording it in that session's filter.
	mu       sync.Mutex
	current  *udpServerSession
	previous *udpServerSession
}

// NewUDPConn creates a relay session over conn towards the proxy at serverAddr.
func NewUDPConn(conn net.PacketConn, serverAddr net.Addr, method Method, psk []byte, cfg *UDPConnConfig) (*UDPConn, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil net.PacketConn")
	}
	if serverAddr == nil {
		return nil, fmt.Errorf("nil server address")
	}

	cipher, err := NewUDPCipher(method, psk)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = &UDPConnConfig{}
	}

	c := &UDPConn{
		conn:       conn,
		serverAddr: serverAddr,
		cipher:     cipher,
		padding:    cfg.Padding,
		bufferSize: cfg.BufferSize,
		filterSize: cfg.FilterSize,
	}

	if c.padding == nil {
		c.padding = PadPlainDNS(MaxPaddingLength)
	}
	if c.bufferSize <= 0 {
		c.bufferSize = DefaultUDPBufferSize
	}

	// The client session ID is random and fixed for the life of the connection.
	var sessionID [UDPSessionIDLen]byte
	if err := FillRandomBytes(sessionID[:]); err != nil {
		return nil, err
	}
	c.sessionID = binary.BigEndian.Uint64(sessionID[:])

	if c.session, err = cipher.NewSession(c.sessionID); err != nil {
		return nil, err
	}

	return c, nil
}

// SessionID returns the client session ID used for outgoing packets.
func (c *UDPConn) SessionID() uint64 {
	return c.sessionID
}

// WriteTo implements net.PacketConn.
func (c *UDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	target, err := targetFromNetAddr(addr)
	if err != nil {
		return 0, err
	}

	paddingLen, err := c.padding(target, len(p))
	if err != nil {
		return 0, err
	}

	padding := internal.GetBytes(paddingLen)
	defer internal.PutBytes(padding)
	if err := FillRandomBytes(padding); err != nil {
		return 0, err
	}

	var header UDPClientHeader
	header.Init(UDPHeaderTypeClientPacket, uint64(time.Now().Unix()), padding, target)

	body := internal.GetBytes(header.EncodedLen() + len(p))[:0]
	defer internal.PutBytes(body)

	if body, err = header.EncodeTo(body); err != nil {
		return 0, err
	}
	body = append(body, p...)

	packet := internal.GetBytes(c.cipher.PacketOverhead() + len(body))[:0]
	defer internal.PutBytes(packet)

	if packet, err = c.session.SealTo(packet, c.packetID.Add(1)-1, body); err != nil {
		return 0, err
	}

	if _, err := c.conn.WriteTo(packet, c.serverAddr); err != nil {
		return 0, err
	}

	return len(p), nil
}

// ReadFrom implements net.PacketConn.
//
// Packets that fail to decrypt or validate are dropped, and reading continues,
// since anyone can send a datagram to an open socket.
func (c *UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := internal.GetBytes(c.bufferSize)
	defer internal.PutBytes(buf)

	plain := internal.GetBytes(c.bufferSize)
	defer internal.PutBytes(plain)

	for {
		n, _, err := c.conn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}

		payload, source, ok := c.unpack(plain[:0], buf[:n], time.Now())
		if !ok {
			continue
		}

		return copy(p, payload), source, nil
	}
}

// unpack decrypts and validates one incoming packet, reporting whether it was
// accepted, and commits it to the session state when it was.
func (c *UDPConn) unpack(dst, packet []byte, now time.Time) ([]byte, net.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var (
		session *udpServerSession
		isNew   bool
	)

	unpacked, err := c.cipher.OpenPacketTo(dst, packet, func(sessionID, packetID uint64) (*UDPSessionCipher, error) {
		s, created, err := c.resolveServerSessionLocked(sessionID, now)
		if err != nil {
			return nil, err
		}
		if !s.filter.IsOk(packetID) {
			return nil, ErrUDPReplay
		}

		session, isNew = s, created
		return s.cipher, nil
	})
	if err != nil || session == nil {
		return nil, nil, false
	}

	var header UDPServerHeader
	headerLen, err := header.Decode(unpacked.Body)
	if err != nil {
		return nil, nil, false
	}
	if err := ValidateTimestamp(header.Timestamp, now); err != nil {
		return nil, nil, false
	}
	if header.ClientSessionID != c.sessionID {
		return nil, nil, false
	}

	// The packet is authentic and fresh, so it may now update session state.
	session.filter.Add(unpacked.PacketID)
	session.lastSeen = now
	if isNew {
		c.previous = c.current
		c.current = session
	}

	return unpacked.Body[headerLen:], netAddrFromTarget(header.Source), true
}

// resolveServerSessionLocked returns the session an incoming packet belongs to,
// creating it when the server has started a new session.
//
// A new session is only created when the session it would displace has gone
// quiet for a full replay window. Otherwise an attacker could push out a live
// session by forging packets with fresh session IDs.
func (c *UDPConn) resolveServerSessionLocked(sessionID uint64, now time.Time) (*udpServerSession, bool, error) {
	if c.current != nil && c.current.sessionID == sessionID {
		return c.current, false, nil
	}
	if c.previous != nil && c.previous.sessionID == sessionID {
		return c.previous, false, nil
	}

	if c.current != nil && c.previous != nil && now.Sub(c.previous.lastSeen) < ReplayWindowDuration {
		return nil, false, ErrTooManyUDPServerSessions
	}

	cipher, err := c.cipher.NewSession(sessionID)
	if err != nil {
		return nil, false, err
	}

	return &udpServerSession{
		sessionID: sessionID,
		cipher:    cipher,
		filter:    NewSlidingWindowFilter(c.filterSize),
		lastSeen:  now,
	}, true, nil
}

// LocalAddr implements net.PacketConn.
func (c *UDPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// SetDeadline implements net.PacketConn.
func (c *UDPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements net.PacketConn.
func (c *UDPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn.
func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// Close implements net.PacketConn.
func (c *UDPConn) Close() error {
	return c.conn.Close()
}

var _ net.PacketConn = (*UDPConn)(nil)

// targetFromNetAddr converts a net.Addr into a Shadowsocks address.
func targetFromNetAddr(addr net.Addr) (Addr, error) {
	switch a := addr.(type) {
	case nil:
		return Addr{}, fmt.Errorf("nil target address")

	case *UDPAddr:
		return a.Target, a.Target.Validate()

	case *net.UDPAddr:
		var target Addr
		if ip4 := a.IP.To4(); ip4 != nil {
			target.Init(AddrTypeIPv4, ip4, "", uint16(a.Port))
		} else {
			target.Init(AddrTypeIPv6, a.IP.To16(), "", uint16(a.Port))
		}
		return target, target.Validate()

	default:
		return parseTargetAddr(a.String())
	}
}

// netAddrFromTarget converts a Shadowsocks address into a net.Addr.
func netAddrFromTarget(target Addr) net.Addr {
	if target.AddrType == AddrTypeDomain {
		return &UDPAddr{Target: target}
	}
	return &net.UDPAddr{IP: target.IP, Port: int(target.Port)}
}
