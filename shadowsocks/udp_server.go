package shadowsocks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/33TU/socks/internal"
)

// UDPServer relays Shadowsocks 2022 UDP packets between clients and their targets.
//
// Packets are routed by client session ID rather than by source address, so a
// relay session survives a client changing network. Each client session owns one
// outbound socket, and is remembered for at least a full replay window so that
// replayed packets from a forgotten session cannot be accepted again.
type UDPServer struct {
	// Config is the server's method and PSK. It is required.
	Config *Config

	// SessionTimeout is how long an idle relay session is kept.
	// Values below ReplayWindowDuration are raised to it.
	SessionTimeout time.Duration

	// BufferSize is the read buffer size. Zero means DefaultUDPBufferSize.
	BufferSize int

	// FilterSize is the sliding window size used to reject replayed packets.
	// Zero means DefaultSlidingWindowFilterSize.
	FilterSize uint64

	// Padding decides the padding added to packet headers sent to clients.
	// A nil policy means PadPlainDNS(MaxPaddingLength).
	Padding PaddingPolicy

	// Resolver resolves domain targets. Nil means net.DefaultResolver.
	Resolver *net.Resolver

	// OnError is called for packets that could not be relayed. Nil logs at debug level.
	OnError func(ctx context.Context, err error)

	cipher  *UDPCipher
	serving atomic.Bool

	mu       sync.Mutex
	sessions map[uint64]*udpRelaySession
}

// ListenAndServe listens for UDP packets on address and relays them.
func (s *UDPServer) ListenAndServe(ctx context.Context, address string) error {
	pc, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}

	return s.Serve(ctx, pc)
}

// Serve relays UDP packets received on pc until ctx is done or pc fails.
func (s *UDPServer) Serve(ctx context.Context, pc net.PacketConn) error {
	if pc == nil {
		return fmt.Errorf("nil net.PacketConn")
	}

	// Relay sessions belong to the socket they were created on, so one server
	// serves one connection at a time.
	if !s.serving.CompareAndSwap(false, true) {
		return fmt.Errorf("UDP server is already serving")
	}
	defer s.serving.Store(false)

	cipher, err := NewServerCipher(s.Config, nil)
	if err != nil {
		return err
	}
	if s.cipher, err = NewUDPCipher(cipher.Method, cipher.PSK); err != nil {
		return err
	}

	s.mu.Lock()
	s.sessions = make(map[uint64]*udpRelaySession)
	s.mu.Unlock()

	defer s.closeSessions()

	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	go s.purgeSessions(ctx)

	buf := internal.GetBytes(s.bufferSize())
	defer internal.PutBytes(buf)

	plain := internal.GetBytes(s.bufferSize())
	defer internal.PutBytes(plain)

	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}

		if err := s.handlePacket(ctx, pc, plain[:0], buf[:n], from); err != nil {
			s.onError(ctx, err)
		}
	}
}

// handlePacket decrypts one client packet and forwards its payload to the target.
func (s *UDPServer) handlePacket(ctx context.Context, pc net.PacketConn, dst, packet []byte, from net.Addr) error {
	now := time.Now()

	clientAddr, ok := from.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("unexpected UDP remote addr type %T", from)
	}

	var (
		session *udpRelaySession
		isNew   bool
	)

	unpacked, err := s.cipher.OpenPacketTo(dst, packet, func(sessionID, packetID uint64) (*UDPSessionCipher, error) {
		sess, created, err := s.resolveSession(sessionID)
		if err != nil {
			return nil, err
		}
		if !sess.filterIsOk(packetID) {
			return nil, ErrUDPReplay
		}

		session, isNew = sess, created
		return sess.clientCipher, nil
	})
	if err != nil {
		return fmt.Errorf("dropping packet from %s: %w", from, err)
	}
	if session == nil {
		return fmt.Errorf("dropping packet from %s: %w", from, ErrUDPUnknownSession)
	}

	var header UDPClientHeader
	headerLen, err := header.Decode(unpacked.Body)
	if err != nil {
		return fmt.Errorf("dropping packet from %s: %w", from, err)
	}
	if err := ValidateTimestamp(header.Timestamp, now); err != nil {
		return fmt.Errorf("dropping packet from %s: %w", from, err)
	}

	// The packet is authentic and fresh, so it may now update session state.
	session.filterAdd(unpacked.PacketID)
	session.touch(now, clientAddr)

	if isNew {
		// Registered before the relay goroutine starts: the goroutine removes
		// itself on exit, and would otherwise race ahead of its own entry.
		s.addSession(session)

		if err := session.start(ctx, s, pc); err != nil {
			s.removeSession(session)
			return fmt.Errorf("starting session %d: %w", session.clientSessionID, err)
		}
	}

	target, err := s.resolveTarget(ctx, header.Target)
	if err != nil {
		return fmt.Errorf("resolving target %s: %w", header.Target.Addr(), err)
	}

	if _, err := session.out.WriteToUDP(unpacked.Body[headerLen:], target); err != nil {
		return fmt.Errorf("forwarding to %s: %w", target, err)
	}

	return nil
}

// resolveSession returns the relay session for a client session ID, building a
// new one when the ID is unknown.
//
// A new session is only registered once its first packet has been validated, so
// forged session IDs cannot make the server allocate sockets.
func (s *UDPServer) resolveSession(sessionID uint64) (*udpRelaySession, bool, error) {
	s.mu.Lock()
	session, ok := s.sessions[sessionID]
	s.mu.Unlock()

	if ok {
		return session, false, nil
	}

	clientCipher, err := s.cipher.NewSession(sessionID)
	if err != nil {
		return nil, false, err
	}

	var serverSessionID [UDPSessionIDLen]byte
	if err := FillRandomBytes(serverSessionID[:]); err != nil {
		return nil, false, err
	}

	serverID := binary.BigEndian.Uint64(serverSessionID[:])
	serverCipher, err := s.cipher.NewSession(serverID)
	if err != nil {
		return nil, false, err
	}

	return &udpRelaySession{
		clientSessionID: sessionID,
		clientCipher:    clientCipher,
		filter:          NewSlidingWindowFilter(s.FilterSize),
		serverSessionID: serverID,
		serverCipher:    serverCipher,
		done:            make(chan struct{}),
	}, true, nil
}

// addSession registers a started session, replacing any session that raced with it.
func (s *UDPServer) addSession(session *udpRelaySession) {
	s.mu.Lock()
	previous, ok := s.sessions[session.clientSessionID]
	s.sessions[session.clientSessionID] = session
	s.mu.Unlock()

	if ok && previous != session {
		previous.close()
	}
}

// purgeSessions closes relay sessions that have been idle past the NAT timeout.
func (s *UDPServer) purgeSessions(ctx context.Context) {
	timeout := s.sessionTimeout()
	ticker := time.NewTicker(timeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.mu.Lock()
			for id, session := range s.sessions {
				if now.Sub(session.lastSeenTime()) > timeout {
					delete(s.sessions, id)
					session.close()
				}
			}
			s.mu.Unlock()
		}
	}
}

// closeSessions tears down every relay session.
func (s *UDPServer) closeSessions() {
	s.mu.Lock()
	sessions := s.sessions
	s.sessions = nil
	s.mu.Unlock()

	for _, session := range sessions {
		session.close()
	}
}

// removeSession drops a session that has ended on its own.
func (s *UDPServer) removeSession(session *udpRelaySession) {
	s.mu.Lock()
	if current, ok := s.sessions[session.clientSessionID]; ok && current == session {
		delete(s.sessions, session.clientSessionID)
	}
	s.mu.Unlock()
}

// resolveTarget converts a target address from a packet header into a UDP address.
func (s *UDPServer) resolveTarget(ctx context.Context, target Addr) (*net.UDPAddr, error) {
	switch target.AddrType {
	case AddrTypeIPv4, AddrTypeIPv6:
		return &net.UDPAddr{IP: target.IP, Port: int(target.Port)}, nil

	case AddrTypeDomain:
		resolver := s.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}

		ips, err := resolver.LookupIP(ctx, "ip", target.Domain)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses for %s", target.Domain)
		}

		return &net.UDPAddr{IP: ips[0], Port: int(target.Port)}, nil

	default:
		return nil, ErrInvalidAddrType
	}
}

func (s *UDPServer) bufferSize() int {
	if s.BufferSize <= 0 {
		return DefaultUDPBufferSize
	}
	return s.BufferSize
}

func (s *UDPServer) sessionTimeout() time.Duration {
	if s.SessionTimeout < ReplayWindowDuration {
		return ReplayWindowDuration
	}
	return s.SessionTimeout
}

func (s *UDPServer) padding() PaddingPolicy {
	if s.Padding == nil {
		return PadPlainDNS(MaxPaddingLength)
	}
	return s.Padding
}

func (s *UDPServer) onError(ctx context.Context, err error) {
	if s.OnError != nil {
		s.OnError(ctx, err)
		return
	}
	slog.DebugContext(ctx, "udp relay", "error", err)
}

// udpRelaySession is one client session and the outbound socket serving it.
type udpRelaySession struct {
	clientSessionID uint64
	clientCipher    *UDPSessionCipher

	serverSessionID uint64
	serverCipher    *UDPSessionCipher
	serverPacketID  atomic.Uint64

	out *net.UDPConn

	// clientAddr is the address the last valid packet came from, and where
	// replies are sent. It lets a session survive a client changing network.
	clientAddr atomic.Pointer[net.UDPAddr]
	lastSeen   atomic.Int64

	mu     sync.Mutex
	filter *SlidingWindowFilter

	closeOnce sync.Once
	done      chan struct{}
}

// start opens the outbound socket and begins relaying replies to the client.
func (s *udpRelaySession) start(ctx context.Context, server *UDPServer, pc net.PacketConn) error {
	out, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	s.out = out

	go s.relayFromTarget(ctx, server, pc)
	return nil
}

// relayFromTarget forwards datagrams from the outbound socket back to the client.
func (s *udpRelaySession) relayFromTarget(ctx context.Context, server *UDPServer, pc net.PacketConn) {
	defer server.removeSession(s)
	defer s.close()

	timeout := server.sessionTimeout()
	padding := server.padding()

	buf := internal.GetBytes(server.bufferSize())
	defer internal.PutBytes(buf)

	for {
		select {
		case <-s.done:
			return
		case <-ctx.Done():
			return
		default:
		}

		// The session lives as long as either side is active, so the deadline
		// follows the last client packet. Deriving it from this loop alone would
		// tear down a session whose client is still sending to a silent target.
		deadline := s.lastSeenTime().Add(timeout)
		if !deadline.After(time.Now()) {
			return
		}

		if err := s.out.SetReadDeadline(deadline); err != nil {
			return
		}

		n, src, err := s.out.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				// The target has gone quiet; the client may not have.
				continue
			}
			return
		}

		clientAddr := s.clientAddr.Load()
		if clientAddr == nil {
			continue
		}

		if err := s.writeToClient(pc, clientAddr, padding, src, buf[:n]); err != nil {
			server.onError(ctx, fmt.Errorf("replying to %s: %w", clientAddr, err))
			continue
		}
	}
}

// writeToClient packs one reply and sends it to the client.
func (s *udpRelaySession) writeToClient(
	pc net.PacketConn,
	clientAddr *net.UDPAddr,
	padding PaddingPolicy,
	src *net.UDPAddr,
	payload []byte,
) error {
	var source Addr
	if ip4 := src.IP.To4(); ip4 != nil {
		source.Init(AddrTypeIPv4, ip4, "", uint16(src.Port))
	} else {
		source.Init(AddrTypeIPv6, src.IP.To16(), "", uint16(src.Port))
	}

	paddingLen, err := padding(source, len(payload))
	if err != nil {
		return err
	}

	paddingBuf := internal.GetBytes(paddingLen)
	defer internal.PutBytes(paddingBuf)
	if err := FillRandomBytes(paddingBuf); err != nil {
		return err
	}

	var header UDPServerHeader
	header.Init(UDPHeaderTypeServerPacket, uint64(time.Now().Unix()), s.clientSessionID, paddingBuf, source)

	body := internal.GetBytes(header.EncodedLen() + len(payload))[:0]
	defer internal.PutBytes(body)

	if body, err = header.EncodeTo(body); err != nil {
		return err
	}
	body = append(body, payload...)

	packet := internal.GetBytes(s.serverCipher.cipher.PacketOverhead() + len(body))[:0]
	defer internal.PutBytes(packet)

	if packet, err = s.serverCipher.SealTo(packet, s.serverPacketID.Add(1)-1, body); err != nil {
		return err
	}

	_, err = pc.WriteTo(packet, clientAddr)
	return err
}

// filterIsOk reports whether a packet ID would be accepted by the session window.
func (s *udpRelaySession) filterIsOk(packetID uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.filter.IsOk(packetID)
}

// filterAdd records a validated packet ID in the session window.
func (s *udpRelaySession) filterAdd(packetID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filter.Add(packetID)
}

// touch records the time and source address of the last valid client packet.
func (s *udpRelaySession) touch(now time.Time, clientAddr *net.UDPAddr) {
	s.lastSeen.Store(now.UnixNano())
	s.clientAddr.Store(clientAddr)
}

func (s *udpRelaySession) lastSeenTime() time.Time {
	return time.Unix(0, s.lastSeen.Load())
}

func (s *udpRelaySession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.out != nil {
			s.out.Close()
		}
	})
}
