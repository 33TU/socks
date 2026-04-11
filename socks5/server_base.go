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
	ResolveResolver        *net.Resolver
	ResolvePreferIPv4      bool // When true, prefer IPv4 addresses over IPv6 for DNS resolution

	SupportedMethods []byte

	UserPassAuthenticator func(ctx context.Context, username, password string) error
	GSSAPIAuthenticator   func(ctx context.Context, token []byte) (resp []byte, done bool, err error)
	UDPAssociateLocalAddr func(ctx context.Context, conn net.Conn, req *Request) (*net.UDPAddr, error)
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
		WriteRejectReply(conn, RepConnectionNotAllowed)
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

func (d *BaseServerHandler) OnBind(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowBind {
		WriteRejectReply(conn, RepConnectionNotAllowed)
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
		WriteRejectReply(conn, RepConnectionNotAllowed)
		return fmt.Errorf("UDP ASSOCIATE command not allowed")
	}

	addr := req.Addr()
	slog.InfoContext(ctx, "UDP ASSOCIATE request", "from", conn.RemoteAddr(), "target", addr)

	var (
		laddr *net.UDPAddr
		err   error
	)

	if d.UDPAssociateLocalAddr != nil {
		if laddr, err = d.UDPAssociateLocalAddr(ctx, conn, req); err != nil {
			WriteRejectReply(conn, RepGeneralFailure)
			return fmt.Errorf("failed to determine local address for UDP associate: %w", err)
		}
	}

	if err = BaseOnUDPAssociate(ctx, conn, req, d.UDPAssociateTimeout, d.UDPAssociateBufferSize, laddr); isUnexpectedNetErr(err) {
		return fmt.Errorf("UDP ASSOCIATE failed to %s: %w", addr, err)
	}

	slog.InfoContext(ctx, "UDP ASSOCIATE completed", "from", conn.RemoteAddr(), "target", addr)
	return nil
}

func (d *BaseServerHandler) OnResolve(ctx context.Context, conn net.Conn, req *Request) error {
	if !d.AllowResolve {
		WriteRejectReply(conn, RepConnectionNotAllowed)
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
		WriteRejectReply(conn, RepCommandNotSupported)
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
		WriteRejectReply(conn, code)
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
		WriteRejectReply(conn, RepGeneralFailure)
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
		WriteRejectReply(conn, RepGeneralFailure)
		return fmt.Errorf("failed to accept incoming connection: %w", err)
	}
	defer incomingConn.Close()

	// Validate source address (if not 0.0.0.0/::)
	incomingAddr := incomingConn.RemoteAddr().(*net.TCPAddr)
	expectedIP := req.IP
	if expectedIP != nil && !expectedIP.IsUnspecified() && !expectedIP.Equal(incomingAddr.IP) {
		WriteRejectReply(conn, RepConnectionNotAllowed)
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

// BaseOnUDPAssociate provides UDP ASSOCIATE implementation
func BaseOnUDPAssociate(
	ctx context.Context,
	conn net.Conn,
	req *Request,
	timeout time.Duration,
	bufferSize int,
	laddr *net.UDPAddr,
) error {
	// Create UDP listener
	udpConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		WriteRejectReply(conn, RepGeneralFailure)
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}
	defer udpConn.Close()

	// Send success reply with UDP relay address
	if err := WriteSuccessReply(conn, udpConn.LocalAddr()); err != nil {
		return fmt.Errorf("failed to write UDP associate reply: %w", err)
	}

	clientTCPAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("unexpected TCP remote addr type %T", conn.RemoteAddr())
	}

	g, ctx := errgroup.WithContext(ctx)

	// Close UDP relay when TCP association ends
	g.Go(func() error {
		defer udpConn.Close()

		if _, err := io.Copy(io.Discard, conn); isUnexpectedNetErr(err) {
			return err
		}
		return nil
	})

	// UDP relay loop
	g.Go(func() error {
		defer conn.Close()

		if bufferSize <= 0 {
			bufferSize = 64 * 1024
		}

		inBuf := internal.GetBytes(bufferSize)
		defer internal.PutBytes(inBuf)

		outBuf := internal.GetBytes(bufferSize)
		defer internal.PutBytes(outBuf)

		// Lock onto the actual UDP client after first valid packet.
		var clientUDPAddr *net.UDPAddr

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if timeout > 0 {
				if err := udpConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
					return err
				}
			}

			n, srcAddr, err := udpConn.ReadFromUDP(inBuf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					return err
				}
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			}

			// First valid client packet must come from same IP as TCP peer.
			if clientUDPAddr == nil {
				var pkt UDPPacket
				if _, err := pkt.UnmarshalFrom(inBuf[:n]); err == nil && srcAddr.IP.Equal(clientTCPAddr.IP) {
					clientUDPAddr = cloneUDPAddr(srcAddr)
				}
			}

			// Client -> target
			if clientUDPAddr != nil &&
				srcAddr.IP.Equal(clientUDPAddr.IP) &&
				srcAddr.Port == clientUDPAddr.Port {

				var pkt UDPPacket
				if _, err := pkt.UnmarshalFrom(inBuf[:n]); err != nil {
					continue
				}

				// Fragmentation not supported; RFC says drop if unsupported.
				if pkt.Frag != 0x00 {
					continue
				}

				targetAddr, err := resolveUDPPacketTarget(&pkt)
				if err != nil {
					continue
				}

				if _, err := udpConn.WriteToUDP(pkt.Data, targetAddr); err != nil {
					continue
				}

				continue
			}

			// Target -> client
			if clientUDPAddr == nil {
				continue
			}

			var resp UDPPacket

			addrType := AddrTypeIPv6
			ip := srcAddr.IP
			if ip4 := ip.To4(); ip4 != nil {
				addrType = AddrTypeIPv4
				ip = ip4
			}

			resp.Init(
				[2]byte{0x00, 0x00},
				0x00,
				byte(addrType),
				ip,
				"",
				uint16(srcAddr.Port),
				inBuf[:n],
			)

			nOut, err := resp.MarshalTo(outBuf)
			if err != nil {
				continue
			}

			if _, err := udpConn.WriteToUDP(outBuf[:nOut], clientUDPAddr); err != nil {
				continue
			}
		}
	})

	return g.Wait()
}

// resolveUDPPacketTarget resolves the target address from a UDPPacket, handling different address types.
func resolveUDPPacketTarget(pkt *UDPPacket) (*net.UDPAddr, error) {
	switch pkt.AddrType {
	case AddrTypeIPv4, AddrTypeIPv6:
		return &net.UDPAddr{
			IP:   pkt.IP,
			Port: int(pkt.Port),
		}, nil

	case AddrTypeDomain:
		return net.ResolveUDPAddr("udp", net.JoinHostPort(pkt.Domain, strconv.Itoa(int(pkt.Port))))

	default:
		return nil, fmt.Errorf("unsupported UDP address type: %d", pkt.AddrType)
	}
}

// cloneUDPAddr creates a deep copy of a net.UDPAddr
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
		WriteRejectReply(conn, RepHostUnreachable)
		return fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}

	if len(ips) == 0 {
		WriteRejectReply(conn, RepHostUnreachable)
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
