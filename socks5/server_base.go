package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/33TU/socks/internal"
	socksnet "github.com/33TU/socks/net"
	"golang.org/x/sync/errgroup"
)

// BaseServerHandler provides a basic implementation of ServerHandler with configurable options.
type BaseServerHandler struct {
	Dialer socksnet.Dialer

	RequestTimeout         time.Duration
	BindAcceptTimeout      time.Duration
	BindConnTimeout        time.Duration
	ConnectConnTimeout     time.Duration
	UDPAssociateTimeout    time.Duration
	ConnectBufferSize      int
	UDPAssociateBufferSize int
	AllowConnect           bool
	AllowBind              bool
	AllowUDPAssociate      bool
	AllowResolve           bool
	ResolveResolver        *net.Resolver // also resolves UDP ASSOCIATE domain targets
	ResolvePreferIPv4      bool          // When true, prefer IPv4 addresses over IPv6 for DNS resolution

	SupportedMethods []byte

	// UserPassAuthenticator validates username/password credentials for
	// username/password authentication. It should return nil on success
	// and a non-nil error when authentication fails or cannot be completed.
	UserPassAuthenticator func(ctx context.Context, username, password string) error

	// GSSAPIAuthenticator processes a single GSSAPI token exchange step.
	// It returns the response token to send back to the client, whether the
	// authentication exchange is complete, and any error encountered.
	GSSAPIAuthenticator func(ctx context.Context, token []byte) (resp []byte, done bool, err error)

	// UDPListenPacket opens the connection a UDP ASSOCIATE relays over. Nil
	// binds a local UDP socket, which sends datagrams straight out.
	//
	// Returning a socksnet.DomainPacketConn tunnels the association: a
	// Shadowsocks UDP connection here turns this server into a local front end
	// whose UDP traffic leaves through the Shadowsocks proxy, with domain
	// targets resolved there rather than locally.
	UDPListenPacket func(ctx context.Context, conn net.Conn, req *Request) (net.PacketConn, error)

	// UDPAssociateAddrs returns the addresses used for a SOCKS5 UDP ASSOCIATE.
	//
	// relayAddr is the local UDP bind address exposed to the SOCKS client.
	// outAddr is the local UDP bind/source address used for remote targets.
	// advertiseAddr is the address returned to the client in the SOCKS5
	UDPAssociateAddrs func(ctx context.Context, conn net.Conn, req *Request) (relayAddr, outAddr, advertiseAddr *net.UDPAddr, err error)
}

func (d *BaseServerHandler) OnAccept(ctx context.Context, conn net.Conn) error {
	slog.InfoContext(ctx, "accepted connection", "from", conn.RemoteAddr())

	if d.RequestTimeout != 0 {
		conn.SetDeadline(time.Now().Add(d.RequestTimeout))
	}
	return nil
}

func (d *BaseServerHandler) OnHandshake(ctx context.Context, conn net.Conn, req *HandshakeRequest) (byte, error) {
	slog.InfoContext(ctx, "handshake request", "from", conn.RemoteAddr(), "methods", req.Methods)

	selectedMethod, err := BaseOnHandshake(ctx, conn, req, d.GetSupportedMethods())
	if err != nil {
		slog.ErrorContext(ctx, "handshake failed", "error", err)
		return MethodNoAcceptable, err
	}

	slog.InfoContext(ctx, "handshake completed", "from", conn.RemoteAddr(), "selected_method", selectedMethod)
	return selectedMethod, nil
}

func (d *BaseServerHandler) OnAuthUserPass(ctx context.Context, conn net.Conn, username, password string) error {
	slog.InfoContext(ctx, "validating username/password", "from", conn.RemoteAddr(), "username", username)

	if d.UserPassAuthenticator != nil {
		return d.UserPassAuthenticator(ctx, username, password)
	}
	return nil // Allow all by default
}

func (d *BaseServerHandler) OnAuthGSSAPI(ctx context.Context, conn net.Conn, token []byte) ([]byte, bool, error) {
	slog.InfoContext(ctx, "validating GSSAPI token", "from", conn.RemoteAddr())

	if d.GSSAPIAuthenticator != nil {
		return d.GSSAPIAuthenticator(ctx, token)
	}
	return nil, true, nil // Allow all by default, and mark as complete
}

func (d *BaseServerHandler) OnRequest(ctx context.Context, conn net.Conn, req *Request) error {
	err := BaseOnRequest(ctx, d, conn, req)
	if err != nil {
		slog.ErrorContext(ctx, "request handling failed", "error", err, "from", conn.RemoteAddr(), "request", req)
	}
	return err
}

func (d *BaseServerHandler) OnConnect(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowConnect {
		_ = WriteRejectReply(conn, RepConnectionNotAllowed)
		return fmt.Errorf("CONNECT command not allowed")
	}

	addr := req.Addr()
	slog.InfoContext(ctx, "CONNECT request", "from", conn.RemoteAddr(), "target", addr)

	if err := BaseOnConnect(ctx, conn, req, d.Dialer, d.ConnectConnTimeout, d.ConnectBufferSize); isUnexpectedNetErr(err) {
		return fmt.Errorf("CONNECT failed to %s: %w", addr, err)
	}

	slog.InfoContext(ctx, "CONNECT completed", "from", conn.RemoteAddr(), "target", addr)
	return nil
}

func (d *BaseServerHandler) OnClose(ctx context.Context, conn net.Conn, errCause error) {
	slog.InfoContext(ctx, "connection closed", "from", conn.RemoteAddr(), "error", errCause)
}

func (d *BaseServerHandler) OnBind(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowBind {
		_ = WriteRejectReply(conn, RepConnectionNotAllowed)
		return fmt.Errorf("BIND command not allowed")
	}

	slog.InfoContext(ctx, "BIND request", "from", conn.RemoteAddr(), "target", req.Addr())

	if err := BaseOnBind(ctx, conn, req, d.BindAcceptTimeout, d.BindConnTimeout, d.ConnectBufferSize); isUnexpectedNetErr(err) {
		return fmt.Errorf("BIND failed: %w", err)
	}

	slog.InfoContext(ctx, "BIND completed", "from", conn.RemoteAddr())
	return nil
}

func (d *BaseServerHandler) OnUDPAssociate(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowUDPAssociate {
		_ = WriteRejectReply(conn, RepConnectionNotAllowed)
		return fmt.Errorf("UDP ASSOCIATE command not allowed")
	}

	addr := req.Addr()
	slog.InfoContext(ctx, "UDP ASSOCIATE request", "from", conn.RemoteAddr(), "target", addr)

	var (
		relayAddr     *net.UDPAddr
		outAddr       *net.UDPAddr
		advertiseAddr *net.UDPAddr
		err           error
	)

	if d.UDPAssociateAddrs != nil {
		if relayAddr, outAddr, advertiseAddr, err = d.UDPAssociateAddrs(ctx, conn, req); err != nil {
			_ = WriteRejectReply(conn, RepGeneralFailure)
			return fmt.Errorf("failed to determine local address for UDP associate: %w", err)
		}
	}

	if err = BaseOnUDPAssociate(ctx, conn, req, UDPAssociateOptions{
		Timeout:       d.UDPAssociateTimeout,
		BufferSize:    d.UDPAssociateBufferSize,
		RelayAddr:     relayAddr,
		OutAddr:       outAddr,
		AdvertiseAddr: advertiseAddr,
		Resolver:      d.ResolveResolver,
		ListenPacket:  d.udpListenPacket(conn, req),
	}); isUnexpectedNetErr(err) {
		return fmt.Errorf("UDP ASSOCIATE failed to %s: %w", addr, err)
	}

	slog.InfoContext(ctx, "UDP ASSOCIATE completed", "from", conn.RemoteAddr(), "target", addr)
	return nil
}

func (d *BaseServerHandler) OnResolve(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowResolve {
		_ = WriteRejectReply(conn, RepConnectionNotAllowed)
		return fmt.Errorf("RESOLVE command not allowed")
	}

	addr := req.Addr()
	slog.InfoContext(ctx, "RESOLVE request", "from", conn.RemoteAddr(), "target", addr)

	if err := BaseOnResolve(ctx, conn, req, d.Dialer, d.ResolveResolver, d.ResolvePreferIPv4, d.ConnectConnTimeout, d.ConnectBufferSize); isUnexpectedNetErr(err) {
		return fmt.Errorf("RESOLVE failed for %s: %w", addr, err)
	}

	slog.InfoContext(ctx, "RESOLVE completed", "from", conn.RemoteAddr(), "target", addr)
	return nil
}

func (d *BaseServerHandler) OnError(ctx context.Context, conn net.Conn, err error) {
	slog.ErrorContext(ctx, "error occurred", "error", err)
}

func (d *BaseServerHandler) OnPanic(ctx context.Context, conn net.Conn, r any) {
	slog.WarnContext(ctx, "panic occurred", "error", r)
}

// udpListenPacket adapts UDPListenPacket to what BaseOnUDPAssociate expects.
func (d *BaseServerHandler) udpListenPacket(conn net.Conn, req *Request) func(context.Context) (net.PacketConn, error) {
	if d.UDPListenPacket == nil {
		return nil
	}

	return func(ctx context.Context) (net.PacketConn, error) {
		return d.UDPListenPacket(ctx, conn, req)
	}
}

// GetSupportedMethods returns the supported authentication methods.
func (d *BaseServerHandler) GetSupportedMethods() []byte {
	if d.SupportedMethods == nil {
		return []byte{MethodNoAuth}
	}
	return d.SupportedMethods
}

// BaseOnHandshake provides a default handshake implementation that selects the first matching authentication method.
func BaseOnHandshake(ctx context.Context, conn net.Conn, req *HandshakeRequest, supportedMethods []byte) (byte, error) {
	for _, clientMethod := range req.Methods {
		if slices.Contains(supportedMethods, clientMethod) {
			return clientMethod, nil
		}
	}

	return MethodNoAcceptable, fmt.Errorf(
		"no acceptable authentication methods: client=%v server=%v",
		req.Methods,
		supportedMethods,
	)
}

// BaseOnRequest provides request handling logic for CONNECT, BIND, UDP ASSOCIATE, and RESOLVE commands.
func BaseOnRequest(ctx context.Context, handler ServerHandler, conn net.Conn, req *Request) error {
	switch req.Command {
	case CmdConnect:
		return handler.OnConnect(ctx, conn, req)
	case CmdBind:
		return handler.OnBind(ctx, conn, req)
	case CmdUDPAssociate:
		return handler.OnUDPAssociate(ctx, conn, req)
	case CmdResolve:
		return handler.OnResolve(ctx, conn, req)
	default:
		_ = WriteRejectReply(conn, RepCommandNotSupported)
		return fmt.Errorf("unsupported command: %d", req.Command)
	}
}

// BaseOnConnect provides CONNECT implementation
func BaseOnConnect(ctx context.Context, conn net.Conn, req *Request, dialer socksnet.Dialer, connTimeout time.Duration, bufferSize int) error {
	if dialer == nil {
		dialer = socksnet.DefaultDialer
	}

	targetAddr := req.Addr()
	remote, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		// Determine appropriate SOCKS5 error code
		var code byte = RepGeneralFailure
		if ne, ok := err.(net.Error); ok {
			if ne.Timeout() {
				code = RepTTLExpired
			} else {
				code = RepConnectionRefused
			}
		}
		_ = WriteRejectReply(conn, code)
		return fmt.Errorf("failed to connect to target %s: %w", targetAddr, err)
	}
	defer remote.Close()

	// Send success reply with bound address
	if err := WriteSuccessReply(conn, remote.LocalAddr()); err != nil {
		return fmt.Errorf("failed to write connect response: %w", err)
	}

	// Start bidirectional copying with coordinated error handling
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return socksnet.CopyConn(remote, conn, connTimeout, bufferSize)
	})

	g.Go(func() error {
		return socksnet.CopyConn(conn, remote, connTimeout, bufferSize)
	})

	return g.Wait()
}

// BaseOnBind provides BIND implementation
func BaseOnBind(ctx context.Context, conn net.Conn, req *Request, acceptTimeout, connTimeout time.Duration, bufferSize int) error {
	// Bind to any available port on all interfaces
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		_ = WriteRejectReply(conn, RepGeneralFailure)
		return fmt.Errorf("failed to bind listening port: %w", err)
	}
	defer listener.Close()

	// Send first reply with bound address/port
	if err := WriteSuccessReply(conn, listener.Addr()); err != nil {
		return fmt.Errorf("failed to write bind response: %w", err)
	}

	// Set bind timeout for accepting incoming connection
	if acceptTimeout > 0 {
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(acceptTimeout))
	}

	// Wait for incoming connection
	incomingConn, err := listener.Accept()
	if err != nil {
		_ = WriteRejectReply(conn, RepGeneralFailure)
		return fmt.Errorf("failed to accept incoming connection: %w", err)
	}
	defer incomingConn.Close()

	// Validate source address (if not 0.0.0.0/::)
	incomingAddr := incomingConn.RemoteAddr().(*net.TCPAddr)
	expectedIP := req.IP
	if expectedIP != nil && !expectedIP.IsUnspecified() && !expectedIP.Equal(incomingAddr.IP) {
		_ = WriteRejectReply(conn, RepConnectionNotAllowed)
		return fmt.Errorf("incoming connection from %s, expected %s", incomingAddr.IP, expectedIP)
	}

	// Send second reply indicating successful connection
	if err := WriteSuccessReply(conn, incomingConn.RemoteAddr()); err != nil {
		return fmt.Errorf("failed to write connection response: %w", err)
	}

	// Start bidirectional copying with coordinated error handling
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return socksnet.CopyConn(incomingConn, conn, connTimeout, bufferSize)
	})

	g.Go(func() error {
		return socksnet.CopyConn(conn, incomingConn, connTimeout, bufferSize)
	})

	return g.Wait()
}

// BaseOnUDPAssociate provides UDP ASSOCIATE implementation.
// UDPAssociateOptions configures a UDP ASSOCIATE relay.
type UDPAssociateOptions struct {
	// Timeout is how long a relay waits on an idle socket.
	Timeout time.Duration

	// BufferSize is the datagram buffer size. Zero means 64 KiB.
	BufferSize int

	// RelayAddr is the local UDP bind address exposed to the SOCKS client.
	RelayAddr *net.UDPAddr

	// OutAddr is the local UDP bind address used for remote targets.
	// It is ignored when ListenPacket is set.
	OutAddr *net.UDPAddr

	// AdvertiseAddr is the address returned to the SOCKS client.
	// Nil advertises the relay socket's own address.
	AdvertiseAddr *net.UDPAddr

	// Resolver resolves domain targets. Nil means net.DefaultResolver.
	// It is unused when the outbound connection resolves names itself.
	Resolver *net.Resolver

	// ListenPacket opens the connection datagrams are relayed over.
	// Nil binds a local UDP socket to OutAddr.
	//
	// Returning a socksnet.DomainPacketConn, as a Shadowsocks UDP connection
	// does, tunnels domain targets by name so they are resolved at the far end
	// rather than here.
	ListenPacket func(ctx context.Context) (net.PacketConn, error)
}

// BaseOnUDPAssociate provides UDP ASSOCIATE implementation.
func BaseOnUDPAssociate(ctx context.Context, conn net.Conn, req *Request, opts UDPAssociateOptions) error {
	var clientUDPAddr atomic.Pointer[net.UDPAddr]

	timeout := opts.Timeout
	bufferSize := opts.BufferSize
	if bufferSize <= 0 {
		bufferSize = 64 * 1024
	}

	clientTCPAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		_ = WriteRejectReply(conn, RepGeneralFailure)
		return fmt.Errorf("unexpected TCP remote addr type %T", conn.RemoteAddr())
	}

	relayConn, err := net.ListenUDP("udp", opts.RelayAddr)
	if err != nil {
		_ = WriteRejectReply(conn, RepGeneralFailure)
		return fmt.Errorf("failed to listen on relay UDP socket: %w", err)
	}
	defer relayConn.Close()

	outConn, err := openOutboundPacketConn(ctx, opts)
	if err != nil {
		_ = WriteRejectReply(conn, RepGeneralFailure)
		return fmt.Errorf("failed to open outbound UDP connection: %w", err)
	}
	defer outConn.Close()

	// An outbound connection that addresses targets by name does its own
	// resolution, at the far end of whatever it tunnels through. Otherwise
	// names are resolved here, off this handler's read loop: a slow lookup
	// there would stall every other datagram the association is carrying.
	domainConn, tunnelsDomains := outConn.(socksnet.DomainPacketConn)

	var domainWriter *socksnet.AsyncUDPWriter
	if !tunnelsDomains {
		domainWriter = socksnet.NewAsyncUDPWriter(outConn, &socksnet.AsyncUDPWriterConfig{
			Resolver: opts.Resolver,
		})
		defer domainWriter.Close()
	}

	advertiseAddr := opts.AdvertiseAddr
	if advertiseAddr == nil {
		advertiseAddr = relayConn.LocalAddr().(*net.UDPAddr)
	}
	if err := WriteSuccessReply(conn, advertiseAddr); err != nil {
		return fmt.Errorf("failed to write UDP associate response: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	// Close UDP sockets when the TCP control connection ends.
	g.Go(func() error {
		defer relayConn.Close()
		defer outConn.Close()

		if _, err := io.Copy(io.Discard, conn); isUnexpectedNetErr(err) {
			return err
		}
		return nil
	})

	// Client -> remote
	g.Go(func() error {
		buf := internal.GetBuffer(bufferSize)
		defer internal.PutBuffer(buf)

		for {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			if timeout > 0 {
				if err := relayConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
					return err
				}
			}

			n, srcAddr, err := relayConn.ReadFromUDP(buf.B)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			}

			var pkt UDPPacket
			if _, err := pkt.UnmarshalFrom(buf.B[:n]); err != nil {
				continue
			}

			locked := clientUDPAddr.Load()
			if locked == nil {
				if !srcAddr.IP.Equal(clientTCPAddr.IP) {
					continue
				}

				addr := cloneUDPAddr(srcAddr)
				if clientUDPAddr.CompareAndSwap(nil, addr) {
					locked = addr
				} else {
					locked = clientUDPAddr.Load()
					if locked == nil {
						continue
					}
				}
			}

			if !srcAddr.IP.Equal(locked.IP) || srcAddr.Port != locked.Port {
				continue
			}

			// Fragmentation unsupported; silently drop.
			if pkt.Frag != 0x00 {
				continue
			}

			// Addresses already in numeric form are sent straight out; only
			// domains need resolving, wherever that happens.
			if pkt.AddrType == AddrTypeDomain {
				if tunnelsDomains {
					_, _ = domainConn.WriteToDomain(pkt.Data, pkt.Domain, pkt.Port)
				} else {
					domainWriter.WriteToDomain(pkt.Data, pkt.Domain, pkt.Port)
				}
				continue
			}

			targetAddr, err := resolveUDPPacketTarget(&pkt)
			if err != nil {
				continue
			}

			if _, err := outConn.WriteTo(pkt.Data, targetAddr); err != nil {
				continue
			}
		}
	})

	// Remote -> client
	g.Go(func() error {
		inBuf := internal.GetBuffer(bufferSize)
		defer internal.PutBuffer(inBuf)

		outBuf := internal.GetBuffer(bufferSize)
		defer internal.PutBuffer(outBuf)

		for {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			if timeout > 0 {
				if err := outConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
					return err
				}
			}

			n, srcAddr, err := outConn.ReadFrom(inBuf.B)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			}

			locked := clientUDPAddr.Load()
			if locked == nil {
				continue
			}

			addrType, ip, domain, port, err := splitPacketSource(srcAddr)
			if err != nil {
				continue
			}

			var resp UDPPacket
			resp.Init(
				[2]byte{0x00, 0x00},
				0x00,
				addrType,
				ip,
				domain,
				port,
				inBuf.B[:n],
			)

			nOut, err := resp.MarshalTo(outBuf.B)
			if err != nil {
				continue
			}

			if _, err := relayConn.WriteToUDP(outBuf.B[:nOut], locked); err != nil {
				continue
			}
		}
	})

	return g.Wait()
}

// cloneUDPAddr creates a deep copy of a net.UDPAddr.
func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), a.IP...),
		Port: a.Port,
		Zone: a.Zone,
	}
}

// openOutboundPacketConn opens the connection datagrams are relayed over.
func openOutboundPacketConn(ctx context.Context, opts UDPAssociateOptions) (net.PacketConn, error) {
	if opts.ListenPacket != nil {
		conn, err := opts.ListenPacket(ctx)
		if err != nil {
			return nil, err
		}
		if conn == nil {
			return nil, fmt.Errorf("ListenPacket returned a nil connection")
		}
		return conn, nil
	}

	return net.ListenUDP("udp", opts.OutAddr)
}

// splitPacketSource describes where a relayed reply came from, in the terms a
// SOCKS5 reply packet needs. A tunnelled connection may report a name.
func splitPacketSource(addr net.Addr) (addrType byte, ip net.IP, domain string, port uint16, err error) {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if ip4 := udpAddr.IP.To4(); ip4 != nil {
			return AddrTypeIPv4, ip4, "", uint16(udpAddr.Port), nil
		}
		return AddrTypeIPv6, udpAddr.IP, "", uint16(udpAddr.Port), nil
	}

	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0, nil, "", 0, err
	}

	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, nil, "", 0, err
	}

	if parsed := net.ParseIP(host); parsed != nil {
		if ip4 := parsed.To4(); ip4 != nil {
			return AddrTypeIPv4, ip4, "", uint16(portNum), nil
		}
		return AddrTypeIPv6, parsed, "", uint16(portNum), nil
	}

	return AddrTypeDomain, nil, host, uint16(portNum), nil
}

// resolveUDPPacketTarget resolves the target address from a UDPPacket.
//
// Domain targets are handled by the association's AsyncUDPWriter instead, so
// that resolution never happens on a relay's read loop.
func resolveUDPPacketTarget(pkt *UDPPacket) (*net.UDPAddr, error) {
	switch pkt.AddrType {
	case AddrTypeIPv4, AddrTypeIPv6:
		return &net.UDPAddr{
			IP:   append(net.IP(nil), pkt.IP...),
			Port: int(pkt.Port),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported UDP address type: %d", pkt.AddrType)
	}
}

// BaseOnResolve provides RESOLVE implementation
func BaseOnResolve(
	ctx context.Context,
	conn net.Conn,
	req *Request,
	dialer socksnet.Dialer, resolver *net.Resolver, preferIPv4 bool,
	connTimeout time.Duration,
	bufferSize int,
) error {
	host := req.GetHost()

	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		_ = WriteRejectReply(conn, RepHostUnreachable)
		return fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}

	if len(ips) == 0 {
		_ = WriteRejectReply(conn, RepHostUnreachable)
		return fmt.Errorf("no IP addresses found for host: %s", host)
	}

	// Select the best IP address based on preference
	ip := ResolveSelectBestIP(ips, preferIPv4)

	var addrType byte
	if ip4 := ip.To4(); ip4 != nil {
		addrType = AddrTypeIPv4
		ip = ip4
	} else {
		addrType = AddrTypeIPv6
	}

	// Send success reply
	var resp Reply
	resp.Init(
		SocksVersion,
		RepSuccess,
		0,
		addrType,
		ip,
		"",
		req.Port, // or 0
	)

	if _, err := resp.WriteTo(conn); err != nil {
		return fmt.Errorf("failed to write resolve response: %w", err)
	}

	return nil
}

// ResolveSelectBestIP selects the most appropriate IP address from a list based on preferences
func ResolveSelectBestIP(ips []net.IP, preferIPv4 bool) net.IP {
	if len(ips) == 0 {
		return nil
	}

	// If we have only one IP, return it
	if len(ips) == 1 {
		return ips[0]
	}

	var ipv4s, ipv6s []net.IP

	// Separate IPv4 and IPv6 addresses
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			ipv4s = append(ipv4s, ip)
		} else {
			ipv6s = append(ipv6s, ip)
		}
	}

	// Apply preference
	if preferIPv4 {
		// Prefer IPv4: return first IPv4 if available, otherwise first IPv6
		if len(ipv4s) > 0 {
			return ipv4s[0]
		}
		if len(ipv6s) > 0 {
			return ipv6s[0]
		}
	} else {
		// Prefer IPv6: return first IPv6 if available, otherwise first IPv4
		if len(ipv6s) > 0 {
			return ipv6s[0]
		}
		if len(ipv4s) > 0 {
			return ipv4s[0]
		}
	}

	// Fallback: return first IP (shouldn't reach here given the checks above)
	return ips[0]
}

// isUnexpectedNetErr checks if an error is a network error that is not EOF or ErrClosed
func isUnexpectedNetErr(err error) bool {
	return err != nil &&
		!errors.Is(err, io.EOF) &&
		!errors.Is(err, net.ErrClosed)
}
