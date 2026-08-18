package shadowsocks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/33TU/socks/internal"
	socksnet "github.com/33TU/socks/net"
)

// UDPServerOptions are the relay parameters a UDP server handler supplies.
// The zero value selects the defaults documented on each field.
type UDPServerOptions struct {
	// SessionTimeout is how long an idle relay session is kept.
	// Values below ReplayWindowDuration are raised to it, since a shorter NAT
	// timeout would let an attacker replay packets from a forgotten session.
	SessionTimeout time.Duration

	// BufferSize is the packet buffer size. Zero means DefaultUDPBufferSize.
	BufferSize int

	// FilterSize is the sliding window size used to reject replayed packets.
	// Zero means DefaultSlidingWindowFilterSize.
	FilterSize uint64

	// Padding decides the padding added to packet headers sent to clients.
	// A nil policy means PadPlainDNS(MaxPaddingLength).
	Padding PaddingPolicy

	// Resolver resolves domain targets. Nil means net.DefaultResolver.
	Resolver *net.Resolver
}

// normalize returns the options with defaults filled in.
func (o UDPServerOptions) normalize() UDPServerOptions {
	if o.SessionTimeout < ReplayWindowDuration {
		o.SessionTimeout = ReplayWindowDuration
	}
	if o.BufferSize <= 0 {
		o.BufferSize = DefaultUDPBufferSize
	}
	if o.Padding == nil {
		o.Padding = PadPlainDNS(MaxPaddingLength)
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	return o
}

// UDPServerHandler handles Shadowsocks UDP relay events.
type UDPServerHandler interface {
	// Cipher returns the crypto state used to accept packets.
	Cipher(ctx context.Context) (*ServerCipher, error)

	// Options returns the relay parameters.
	Options() UDPServerOptions

	// OnSession is called once a new client session has been established, which
	// happens only after its first packet decrypts and validates. Returning an
	// error rejects the session and drops the packet.
	OnSession(ctx context.Context, session *UDPSession) error

	// ListenPacket opens the outbound socket a session relays through. It is
	// the hook for binding a particular source address or interface.
	ListenPacket(ctx context.Context, session *UDPSession) (*net.UDPConn, error)

	// OnPacket is called for every validated packet before it is relayed, with
	// the target as named in the packet header, before any name resolution.
	// Returning an error drops the packet.
	OnPacket(ctx context.Context, session *UDPSession, target Addr, payload []byte) error

	// OnSessionClose is called when a relay session ends.
	OnSessionClose(ctx context.Context, session *UDPSession, errCause error)

	// OnError is called for packets that could not be relayed.
	OnError(ctx context.Context, err error)

	// OnPanic is called when a panic occurs while relaying.
	OnPanic(ctx context.Context, r any)
}

// ListenAndServePacket listens for UDP packets on address and relays them.
func ListenAndServePacket(ctx context.Context, address string, handler UDPServerHandler) error {
	pc, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}

	return ServePacket(ctx, pc, handler)
}

// ServePacket relays Shadowsocks UDP packets received on pc until ctx is done
// or pc fails.
//
// Packets are routed by client session ID rather than by source address, so a
// relay session survives a client changing network. Each client session owns one
// outbound socket, and is remembered for at least a full replay window so that
// replayed packets from a forgotten session cannot be accepted again.
func ServePacket(ctx context.Context, pc net.PacketConn, handler UDPServerHandler) error {
	if handler == nil {
		return fmt.Errorf("nil handler provided")
	}
	if pc == nil {
		return fmt.Errorf("nil net.PacketConn")
	}

	serverCipher, err := handler.Cipher(ctx)
	if err != nil {
		return err
	}
	if err := serverCipher.Validate(); err != nil {
		return err
	}

	// A multi-user server is known by its identity key; the keys protecting
	// bodies belong to its users and are only known once a packet names one.
	basePSK := serverCipher.PSK
	if serverCipher.MultiUser() {
		basePSK = serverCipher.IdentityPSK
	}

	cipher, err := NewUDPCipher(serverCipher.Method, basePSK)
	if err != nil {
		return err
	}

	relay := &udpRelay{
		cipher:   cipher,
		server:   serverCipher,
		handler:  handler,
		options:  handler.Options().normalize(),
		sessions: make(map[uint64]*UDPSession),
	}

	// The same cipher reads the separate and identity headers, which the
	// identity key protects; bodies use the user's key instead.
	if serverCipher.MultiUser() {
		relay.identity = cipher
	}
	defer relay.closeSessions(ctx)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	go relay.purgeSessions(ctx)

	buf := internal.GetBuffer(relay.options.BufferSize)
	defer internal.PutBuffer(buf)

	plain := internal.GetBuffer(relay.options.BufferSize)
	defer internal.PutBuffer(plain)

	for {
		n, from, err := pc.ReadFrom(buf.B)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}

		if err := relay.handlePacket(ctx, pc, plain.B[:0], buf.B[:n], from); err != nil {
			handler.OnError(ctx, err)
		}
	}
}

// udpRelay is the state of one ServePacket call.
type udpRelay struct {
	cipher   *UDPCipher
	identity *UDPCipher
	server   *ServerCipher
	handler  UDPServerHandler
	options  UDPServerOptions

	mu       sync.Mutex
	sessions map[uint64]*UDPSession
}

// handlePacket decrypts one client packet and forwards its payload to the target.
func (r *udpRelay) handlePacket(ctx context.Context, pc net.PacketConn, dst, packet []byte, from net.Addr) (err error) {
	// A panic here would otherwise take down the whole relay, since every
	// session shares this read loop.
	defer func() {
		if rec := recover(); rec != nil {
			r.handler.OnPanic(ctx, rec)
			err = fmt.Errorf("panic while handling packet from %s", from)
		}
	}()

	now := time.Now()

	clientAddr, ok := from.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("unexpected UDP remote addr type %T", from)
	}

	var (
		session *UDPSession
		isNew   bool
	)

	if r.identity != nil {
		return r.handleMultiUserPacket(ctx, pc, dst, packet, clientAddr, now)
	}

	unpacked, err := r.cipher.OpenPacketTo(dst, packet, func(sessionID, packetID uint64) (*UDPSessionCipher, error) {
		sess, created, err := r.resolveSession(sessionID)
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
		if err := r.startSession(ctx, pc, session); err != nil {
			return fmt.Errorf("session %#x: %w", session.clientSessionID, err)
		}
	}

	payload := unpacked.Body[headerLen:]
	if err := r.handler.OnPacket(ctx, session, header.Target, payload); err != nil {
		return fmt.Errorf("dropping packet from %s to %s: %w", from, header.Target.Addr(), err)
	}

	// Domains are resolved off this loop, which every session's packets share.
	if header.Target.AddrType == AddrTypeDomain {
		if !session.domainWriter.WriteToDomain(payload, header.Target.Domain, header.Target.Port) {
			return fmt.Errorf("dropping packet from %s to %s: resolver queue full", from, header.Target.Addr())
		}
		return nil
	}

	target, err := r.resolveTarget(header.Target)
	if err != nil {
		return fmt.Errorf("resolving target %s: %w", header.Target.Addr(), err)
	}

	if _, err := session.out.WriteToUDP(payload, target); err != nil {
		return fmt.Errorf("forwarding to %s: %w", target, err)
	}

	return nil
}

// handleMultiUserPacket decrypts a packet naming its user in an identity header.
func (r *udpRelay) handleMultiUserPacket(
	ctx context.Context,
	pc net.PacketConn,
	dst, packet []byte,
	clientAddr *net.UDPAddr,
	now time.Time,
) error {
	const headersLen = UDPSeparateHeaderLen + IdentityHeaderLen

	if len(packet) < headersLen {
		return fmt.Errorf("dropping packet from %s: %w", clientAddr, ErrShortUDPPacket)
	}

	sessionID, packetID, _, err := r.identity.PeekSeparateHeader(packet)
	if err != nil {
		return fmt.Errorf("dropping packet from %s: %w", clientAddr, err)
	}

	// The identity header masks its hash with the plaintext separate header.
	var separate [UDPSeparateHeaderLen]byte
	binary.BigEndian.PutUint64(separate[:UDPSessionIDLen], sessionID)
	binary.BigEndian.PutUint64(separate[UDPSessionIDLen:], packetID)

	named, err := DecodeUDPIdentityHeader(packet[UDPSeparateHeaderLen:headersLen], r.server.IdentityPSK, separate[:])
	if err != nil {
		return fmt.Errorf("dropping packet from %s: %w", clientAddr, err)
	}

	user, ok := r.server.Users.Lookup(named)
	if !ok {
		return fmt.Errorf("dropping packet from %s: %w", clientAddr, ErrUnknownUser)
	}

	session, isNew, err := r.resolveUserSession(user, sessionID)
	if err != nil {
		return fmt.Errorf("dropping packet from %s: %w", clientAddr, err)
	}
	if !session.filterIsOk(packetID) {
		return fmt.Errorf("dropping packet from %s: %w", clientAddr, ErrUDPReplay)
	}

	body, err := session.clientCipher.OpenBodyTo(dst, packet[headersLen:], separate[:])
	if err != nil {
		return fmt.Errorf("dropping packet from %s: %w", clientAddr, err)
	}

	var header UDPClientHeader
	headerLen, err := header.Decode(body)
	if err != nil {
		return fmt.Errorf("dropping packet from %s: %w", clientAddr, err)
	}
	if err := ValidateTimestamp(header.Timestamp, now); err != nil {
		return fmt.Errorf("dropping packet from %s: %w", clientAddr, err)
	}

	session.filterAdd(packetID)
	session.touch(now, clientAddr)

	if isNew {
		if err := r.startSession(ctx, pc, session); err != nil {
			return fmt.Errorf("session %#x: %w", session.clientSessionID, err)
		}
	}

	payload := body[headerLen:]
	if err := r.handler.OnPacket(ctx, session, header.Target, payload); err != nil {
		return fmt.Errorf("dropping packet from %s to %s: %w", clientAddr, header.Target.Addr(), err)
	}

	if header.Target.AddrType == AddrTypeDomain {
		if !session.domainWriter.WriteToDomain(payload, header.Target.Domain, header.Target.Port) {
			return fmt.Errorf("dropping packet from %s to %s: resolver queue full", clientAddr, header.Target.Addr())
		}
		return nil
	}

	target, err := r.resolveTarget(header.Target)
	if err != nil {
		return fmt.Errorf("resolving target %s: %w", header.Target.Addr(), err)
	}

	if _, err := session.out.WriteToUDP(payload, target); err != nil {
		return fmt.Errorf("forwarding to %s: %w", target, err)
	}

	return nil
}

// resolveUserSession returns the relay session for a user's client session ID.
func (r *udpRelay) resolveUserSession(user User, sessionID uint64) (*UDPSession, bool, error) {
	r.mu.Lock()
	session, ok := r.sessions[sessionID]
	r.mu.Unlock()

	if ok {
		return session, false, nil
	}

	// The body, and the replies to it, are protected by the user's own key.
	userCipher, err := NewUDPCipher(r.server.Method, user.PSK)
	if err != nil {
		return nil, false, err
	}

	clientCipher, err := userCipher.NewSession(sessionID)
	if err != nil {
		return nil, false, err
	}

	var serverSessionID [UDPSessionIDLen]byte
	if err := FillRandomBytes(serverSessionID[:]); err != nil {
		return nil, false, err
	}

	serverID := binary.BigEndian.Uint64(serverSessionID[:])
	serverCipher, err := userCipher.NewSession(serverID)
	if err != nil {
		return nil, false, err
	}

	return &UDPSession{
		clientSessionID: sessionID,
		clientCipher:    clientCipher,
		filter:          NewSlidingWindowFilter(r.options.FilterSize),
		serverSessionID: serverID,
		serverCipher:    serverCipher,
		user:            user,
		done:            make(chan struct{}),
	}, true, nil
}

// startSession admits a new session, opens its outbound socket and begins
// relaying replies. The session is only published once it is ready to use.
func (r *udpRelay) startSession(ctx context.Context, pc net.PacketConn, session *UDPSession) error {
	if err := r.handler.OnSession(ctx, session); err != nil {
		return err
	}

	out, err := r.handler.ListenPacket(ctx, session)
	if err != nil {
		return err
	}
	if out == nil {
		return fmt.Errorf("handler returned a nil outbound socket")
	}
	session.out = out
	session.domainWriter = socksnet.NewAsyncUDPWriter(out, &socksnet.AsyncUDPWriterConfig{
		Resolver: r.options.Resolver,
		OnError:  func(err error) { r.handler.OnError(ctx, err) },
	})

	// Registered before the relay goroutine starts: the goroutine removes
	// itself on exit, and would otherwise race ahead of its own entry.
	r.addSession(ctx, session)

	go r.relayFromTarget(ctx, pc, session)
	return nil
}

// resolveSession returns the relay session for a client session ID, building a
// new one when the ID is unknown.
//
// A new session is only admitted once its first packet has been validated, so
// forged session IDs cannot make the server allocate sockets.
func (r *udpRelay) resolveSession(sessionID uint64) (*UDPSession, bool, error) {
	r.mu.Lock()
	session, ok := r.sessions[sessionID]
	r.mu.Unlock()

	if ok {
		return session, false, nil
	}

	clientCipher, err := r.cipher.NewSession(sessionID)
	if err != nil {
		return nil, false, err
	}

	var serverSessionID [UDPSessionIDLen]byte
	if err := FillRandomBytes(serverSessionID[:]); err != nil {
		return nil, false, err
	}

	serverID := binary.BigEndian.Uint64(serverSessionID[:])
	serverCipher, err := r.cipher.NewSession(serverID)
	if err != nil {
		return nil, false, err
	}

	return &UDPSession{
		clientSessionID: sessionID,
		clientCipher:    clientCipher,
		filter:          NewSlidingWindowFilter(r.options.FilterSize),
		serverSessionID: serverID,
		serverCipher:    serverCipher,
		done:            make(chan struct{}),
	}, true, nil
}

// addSession publishes a started session, replacing any session that raced with it.
func (r *udpRelay) addSession(ctx context.Context, session *UDPSession) {
	r.mu.Lock()
	previous, ok := r.sessions[session.clientSessionID]
	r.sessions[session.clientSessionID] = session
	r.mu.Unlock()

	if ok && previous != session {
		previous.close()
		r.handler.OnSessionClose(ctx, previous, nil)
	}
}

// removeSession drops a session that has ended on its own.
func (r *udpRelay) removeSession(session *UDPSession) {
	r.mu.Lock()
	if current, ok := r.sessions[session.clientSessionID]; ok && current == session {
		delete(r.sessions, session.clientSessionID)
	}
	r.mu.Unlock()
}

// purgeSessions closes relay sessions that have been idle past the NAT timeout.
func (r *udpRelay) purgeSessions(ctx context.Context) {
	timeout := r.options.SessionTimeout
	ticker := time.NewTicker(timeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			var expired []*UDPSession

			r.mu.Lock()
			for id, session := range r.sessions {
				if now.Sub(session.LastSeen()) > timeout {
					delete(r.sessions, id)
					expired = append(expired, session)
				}
			}
			r.mu.Unlock()

			for _, session := range expired {
				session.close()
				r.handler.OnSessionClose(ctx, session, nil)
			}
		}
	}
}

// closeSessions tears down every relay session.
func (r *udpRelay) closeSessions(ctx context.Context) {
	r.mu.Lock()
	sessions := r.sessions
	r.sessions = nil
	r.mu.Unlock()

	for _, session := range sessions {
		session.close()
		r.handler.OnSessionClose(ctx, session, nil)
	}
}

// relayFromTarget forwards datagrams from a session's outbound socket back to
// the client.
func (r *udpRelay) relayFromTarget(ctx context.Context, pc net.PacketConn, session *UDPSession) {
	var cause error

	defer func() {
		if rec := recover(); rec != nil {
			r.handler.OnPanic(ctx, rec)
			cause = fmt.Errorf("panic while relaying session %#x", session.clientSessionID)
		}

		r.removeSession(session)
		session.close()
		r.handler.OnSessionClose(ctx, session, cause)
	}()

	timeout := r.options.SessionTimeout

	buf := internal.GetBuffer(r.options.BufferSize)
	defer internal.PutBuffer(buf)

	for {
		select {
		case <-session.done:
			return
		case <-ctx.Done():
			return
		default:
		}

		// The session lives as long as either side is active, so the deadline
		// follows the last client packet. Deriving it from this loop alone would
		// tear down a session whose client is still sending to a silent target.
		deadline := session.LastSeen().Add(timeout)
		if !deadline.After(time.Now()) {
			return
		}

		if err := session.out.SetReadDeadline(deadline); err != nil {
			cause = err
			return
		}

		n, src, err := session.out.ReadFromUDP(buf.B)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				// The target has gone quiet; the client may not have.
				continue
			}
			if !errors.Is(err, net.ErrClosed) {
				cause = err
			}
			return
		}

		clientAddr := session.ClientAddr()
		if clientAddr == nil {
			continue
		}

		if err := session.writeToClient(pc, clientAddr, r.options.Padding, src, buf.B[:n]); err != nil {
			r.handler.OnError(ctx, fmt.Errorf("replying to %s: %w", clientAddr, err))
			continue
		}
	}
}

// resolveTarget converts a numeric target address into a UDP address.
//
// Domain targets go through the session's AsyncUDPWriter instead, so that
// resolution never happens on the relay's read loop.
func (r *udpRelay) resolveTarget(target Addr) (*net.UDPAddr, error) {
	switch target.AddrType {
	case AddrTypeIPv4, AddrTypeIPv6:
		return &net.UDPAddr{IP: target.IP, Port: int(target.Port)}, nil

	default:
		return nil, ErrInvalidAddrType
	}
}

// UDPSession is one client relay session and the outbound socket serving it.
type UDPSession struct {
	clientSessionID uint64
	clientCipher    *UDPSessionCipher

	serverSessionID uint64
	serverCipher    *UDPSessionCipher
	serverPacketID  atomic.Uint64

	out *net.UDPConn

	// domainWriter resolves and sends to domain targets away from the relay's
	// read loop.
	domainWriter *socksnet.AsyncUDPWriter

	// clientAddr is the address the last valid packet came from, and where
	// replies are sent. It lets a session survive a client changing network.
	clientAddr atomic.Pointer[net.UDPAddr]
	lastSeen   atomic.Int64

	mu     sync.Mutex
	filter *SlidingWindowFilter

	// user is set when an identity header named one.
	user User

	closeOnce sync.Once
	done      chan struct{}
}

// User returns the user this session belongs to, empty on a single-user server.
func (s *UDPSession) User() User {
	return s.user
}

// ClientSessionID returns the session ID the client chose.
func (s *UDPSession) ClientSessionID() uint64 {
	return s.clientSessionID
}

// ServerSessionID returns the session ID the server uses for its replies.
func (s *UDPSession) ServerSessionID() uint64 {
	return s.serverSessionID
}

// ClientAddr returns the address the last valid packet came from, which is
// where replies are sent. It is nil before the first packet is accepted.
func (s *UDPSession) ClientAddr() *net.UDPAddr {
	return s.clientAddr.Load()
}

// LastSeen returns when the last valid client packet arrived.
func (s *UDPSession) LastSeen() time.Time {
	return time.Unix(0, s.lastSeen.Load())
}

// LocalAddr returns the local address of the session's outbound socket, or nil
// before the session has been started.
func (s *UDPSession) LocalAddr() net.Addr {
	if s.out == nil {
		return nil
	}
	return s.out.LocalAddr()
}

// writeToClient packs one reply and sends it to the client.
func (s *UDPSession) writeToClient(
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

	paddingBuf := internal.GetBuffer(paddingLen)
	defer internal.PutBuffer(paddingBuf)
	if err := FillRandomBytes(paddingBuf.B); err != nil {
		return err
	}

	var header UDPServerHeader
	header.Init(UDPHeaderTypeServerPacket, uint64(time.Now().Unix()), s.clientSessionID, paddingBuf.B, source)

	bodyBuf := internal.GetBuffer(header.EncodedLen() + len(payload))
	defer internal.PutBuffer(bodyBuf)

	body, err := header.EncodeTo(bodyBuf.B[:0])
	if err != nil {
		return err
	}
	body = append(body, payload...)

	packetBuf := internal.GetBuffer(s.serverCipher.cipher.PacketOverhead() + len(body))
	defer internal.PutBuffer(packetBuf)

	packet, err := s.serverCipher.SealTo(packetBuf.B[:0], s.serverPacketID.Add(1)-1, body)
	if err != nil {
		return err
	}

	_, err = pc.WriteTo(packet, clientAddr)
	return err
}

// filterIsOk reports whether a packet ID would be accepted by the session window.
func (s *UDPSession) filterIsOk(packetID uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.filter.IsOk(packetID)
}

// filterAdd records a validated packet ID in the session window.
func (s *UDPSession) filterAdd(packetID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filter.Add(packetID)
}

// touch records the time and source address of the last valid client packet.
func (s *UDPSession) touch(now time.Time, clientAddr *net.UDPAddr) {
	s.lastSeen.Store(now.UnixNano())
	s.clientAddr.Store(clientAddr)
}

func (s *UDPSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.domainWriter != nil {
			s.domainWriter.Close()
		}
		if s.out != nil {
			s.out.Close()
		}
	})
}
