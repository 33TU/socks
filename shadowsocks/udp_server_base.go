package shadowsocks

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// BaseUDPServerHandler provides a basic implementation of UDPServerHandler with
// configurable options.
type BaseUDPServerHandler struct {
	// Config is the server's method and PSK. It is required.
	Config *Config

	// SessionTimeout is how long an idle relay session is kept.
	// Values below ReplayWindowDuration are raised to it.
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

	// AllowRelay reports whether packets may be relayed at all.
	AllowRelay bool

	// Users, when set, serves many users on one port through identity headers,
	// as on the TCP side.
	Users *UserTable

	// OutboundAddr is the local address outbound sockets bind to.
	// Nil lets the system choose, which is the usual setting.
	OutboundAddr *net.UDPAddr

	// TargetAuthorizer decides whether a validated packet may be relayed to its
	// target, which is the packet's target address before any name resolution.
	// It should return nil to allow the packet and an error to drop it.
	// Nil allows every target.
	TargetAuthorizer func(ctx context.Context, session *UDPSession, target Addr, payload []byte) error

	cipherOnce sync.Once
	cipher     *ServerCipher
	cipherErr  error
}

// Cipher returns the server crypto state, building it from Config on first use.
func (d *BaseUDPServerHandler) Cipher(ctx context.Context) (*ServerCipher, error) {
	d.cipherOnce.Do(func() {
		// UDP replay protection is per session, through the sliding window
		// filter, so no salt cache is involved.
		d.cipher, d.cipherErr = NewServerCipher(d.Config, nil)
		if d.cipherErr == nil && d.Users != nil {
			d.cipher.IdentityPSK = d.cipher.PSK
			d.cipher.PSK = nil
			d.cipher.Users = d.Users
		}
	})

	return d.cipher, d.cipherErr
}

// Options returns the relay parameters.
func (d *BaseUDPServerHandler) Options() UDPServerOptions {
	return UDPServerOptions{
		SessionTimeout: d.SessionTimeout,
		BufferSize:     d.BufferSize,
		FilterSize:     d.FilterSize,
		Padding:        d.Padding,
		Resolver:       d.Resolver,
	}
}

func (d *BaseUDPServerHandler) OnSession(ctx context.Context, session *UDPSession) error {
	if !d.AllowRelay {
		return fmt.Errorf("UDP relay not allowed")
	}

	slog.InfoContext(ctx, "UDP session established",
		"client_session", session.ClientSessionID(),
		"from", session.ClientAddr(),
	)
	return nil
}

func (d *BaseUDPServerHandler) ListenPacket(ctx context.Context, session *UDPSession) (*net.UDPConn, error) {
	return net.ListenUDP("udp", d.OutboundAddr)
}

func (d *BaseUDPServerHandler) OnPacket(ctx context.Context, session *UDPSession, target Addr, payload []byte) error {
	if !d.AllowRelay {
		return fmt.Errorf("UDP relay not allowed")
	}
	if d.TargetAuthorizer != nil {
		return d.TargetAuthorizer(ctx, session, target, payload)
	}
	return nil
}

func (d *BaseUDPServerHandler) OnSessionClose(ctx context.Context, session *UDPSession, errCause error) {
	slog.InfoContext(ctx, "UDP session closed",
		"client_session", session.ClientSessionID(),
		"from", session.ClientAddr(),
		"error", errCause,
	)
}

func (d *BaseUDPServerHandler) OnError(ctx context.Context, err error) {
	slog.DebugContext(ctx, "udp relay", "error", err)
}

func (d *BaseUDPServerHandler) OnPanic(ctx context.Context, r any) {
	slog.WarnContext(ctx, "panic occurred", "error", r)
}

var _ UDPServerHandler = (*BaseUDPServerHandler)(nil)
