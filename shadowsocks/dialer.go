package shadowsocks

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/33TU/socks/internal"
	socksnet "github.com/33TU/socks/net"
)

// Dialer implements a Shadowsocks proxy dialer.
type Dialer struct {
	ProxyAddr string
	Config    *Config
	Dialer    socksnet.Dialer

	// Padding decides the padding added to request headers.
	// A nil policy means PadWhenEmpty(MaxPaddingLength).
	Padding PaddingPolicy
}

// NewDialer creates a new Shadowsocks dialer instance.
func NewDialer(proxyAddr string, cfg *Config, dialer socksnet.Dialer) *Dialer {
	if dialer == nil {
		dialer = socksnet.DefaultDialer
	}

	return &Dialer{
		ProxyAddr: proxyAddr,
		Config:    cfg,
		Dialer:    dialer,
	}
}

// NewDialerFromURL creates a new Dialer from a URL of the form
// ss://method:psk@host:port[/?plugin=...][#tag]
//
// Both spellings of the userinfo are accepted. AEAD-2022 links usually carry
// method:psk directly, while SIP002 defines the userinfo as
// websafe-base64(method:psk), which is what most subscription links and QR
// codes emit.
func NewDialerFromURL(u *url.URL, dialer socksnet.Dialer) (*Dialer, error) {
	if u == nil {
		return nil, fmt.Errorf("nil proxy URL")
	}

	switch u.Scheme {
	case "ss":
	default:
		return nil, fmt.Errorf("invalid scheme: %s", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host in proxy URL")
	}

	port := u.Port()
	if port == "" {
		return nil, fmt.Errorf("missing port in proxy URL")
	}

	proxyAddr := net.JoinHostPort(host, port)

	method, psk, err := parseURLUserInfo(u.User)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Method: method,
		PSK:    psk,
		Plugin: u.Query().Get("plugin"),
		Tag:    u.Fragment,
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	return NewDialer(proxyAddr, cfg, dialer), nil
}

// NewDialerFromURLString creates a new Dialer from a URL string of the form
// ss://method:psk@host:port[/?plugin=...][#tag]
//
// Both plain and SIP002 base64 userinfo are accepted.
func NewDialerFromURLString(rawURL string, dialer socksnet.Dialer) (*Dialer, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	return NewDialerFromURL(u, dialer)
}

// parseURLUserInfo extracts the method and PSK from an ss:// URL's userinfo.
//
// A userinfo carrying a password is read as plain method:psk. One without is
// read as SIP002's websafe-base64(method:psk); the base64 spelling varies
// between emitters, so the URL-safe and standard alphabets are both accepted,
// padded or not.
func parseURLUserInfo(user *url.Userinfo) (method, psk string, err error) {
	if user == nil {
		return "", "", fmt.Errorf("missing method/psk in proxy URL")
	}

	if psk, ok := user.Password(); ok {
		method := user.Username()
		if method == "" {
			return "", "", fmt.Errorf("missing method in proxy URL")
		}
		if psk == "" {
			return "", "", fmt.Errorf("missing PSK in proxy URL")
		}
		return method, psk, nil
	}

	encoded := user.Username()
	if encoded == "" {
		return "", "", fmt.Errorf("missing method/psk in proxy URL")
	}

	// A bare method name is the plain form with its PSK left off. Saying so
	// beats complaining that it is not valid base64, which it may well be.
	if IsSupportedMethod(encoded) {
		return "", "", fmt.Errorf("missing PSK in proxy URL")
	}

	decoded, err := decodeURLUserInfo(encoded)
	if err != nil {
		return "", "", fmt.Errorf("invalid proxy URL userinfo: %w", err)
	}

	// The PSK is base64 and cannot contain a colon, so the first one separates
	// the method. Anything after it is the PSK, which for multi-user setups is
	// itself a colon-separated list.
	method, psk, ok := strings.Cut(decoded, ":")
	if !ok || method == "" || psk == "" {
		return "", "", fmt.Errorf("invalid proxy URL userinfo: want method:psk")
	}

	return method, psk, nil
}

// decodeURLUserInfo decodes the base64 spellings found in the wild.
func decodeURLUserInfo(s string) (string, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if decoded, err := enc.DecodeString(s); err == nil {
			return string(decoded), nil
		}
	}

	return "", fmt.Errorf("not base64")
}

// ProxyAddress returns the configured Shadowsocks proxy address.
func (d *Dialer) ProxyAddress() string {
	return d.ProxyAddr
}

// DialContext establishes a TCP connection via the Shadowsocks proxy.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dialProxy(ctx, network)
	if err != nil {
		return nil, err
	}

	return d.DialConnContext(ctx, conn, network, address)
}

// Dial establishes a TCP connection via the Shadowsocks proxy using background context.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialConnContext upgrades an existing connection into a Shadowsocks TCP stream.
func (d *Dialer) DialConnContext(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error) {
	keys, err := d.clientKeys()
	if err != nil {
		conn.Close()
		return nil, err
	}

	target, err := parseTargetAddr(address)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// cancellation and deadline handling
	cleanup := bindConnToContext(ctx, conn)
	defer cleanup()

	padding, err := d.buildPadding(target, 0)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer internal.PutBytes(padding)

	ssConn, err := NewClientTCPConn(conn, keys, target, padding, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssConn, nil
}

// DialConn upgrades an existing connection using background context.
func (d *Dialer) DialConn(conn net.Conn, network, address string) (net.Conn, error) {
	return d.DialConnContext(context.Background(), conn, network, address)
}

// ListenPacket opens a UDP relay session through the Shadowsocks proxy.
//
// The returned connection is a net.PacketConn: each WriteTo tunnels a datagram
// to the proxy, which relays it to the given target address. A single relay
// session is used for the life of the connection, so callers that need separate
// sessions should open separate connections.
func (d *Dialer) ListenPacket(ctx context.Context, cfg *UDPConnConfig) (*UDPConn, error) {
	keys, err := d.clientKeys()
	if err != nil {
		return nil, err
	}

	method, psk := keys.Method, keys.PSK

	serverAddr, err := net.ResolveUDPAddr("udp", d.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve proxy address %s: %w", d.ProxyAddr, err)
	}

	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = &UDPConnConfig{}
	}
	if cfg.IdentityPSKs == nil {
		cfg.IdentityPSKs = keys.IdentityPSKs
	}

	conn, err := NewUDPConn(pc, serverAddr, method, psk, cfg)
	if err != nil {
		pc.Close()
		return nil, err
	}

	return conn, nil
}

// clientKeys returns the key chain from the dialer's config.
func (d *Dialer) clientKeys() (ClientKeys, error) {
	if d == nil {
		return ClientKeys{}, fmt.Errorf("nil shadowsocks dialer")
	}
	if d.Config == nil {
		return ClientKeys{}, fmt.Errorf("missing shadowsocks config")
	}
	if err := d.Config.Validate(); err != nil {
		return ClientKeys{}, err
	}

	method, err := ParseMethod(d.Config.Method)
	if err != nil {
		return ClientKeys{}, err
	}

	list := d.Config.PSKList()
	keys := ClientKeys{Method: method}

	for i, encoded := range list {
		psk, err := DecodePSKTo(nil, method, encoded)
		if err != nil {
			return ClientKeys{}, err
		}

		// Everything before the last key names the path to it.
		if i == len(list)-1 {
			keys.PSK = psk
		} else {
			keys.IdentityPSKs = append(keys.IdentityPSKs, psk)
		}
	}

	return keys, keys.Validate()
}

// buildPadding returns random padding for a request header according to the
// dialer's padding policy. The returned slice comes from the byte pool.
func (d *Dialer) buildPadding(target Addr, payloadLen int) ([]byte, error) {
	policy := d.Padding
	if policy == nil {
		policy = PadWhenEmpty(MaxPaddingLength)
	}

	paddingLen, err := policy(target, payloadLen)
	if err != nil {
		return nil, err
	}
	if paddingLen == 0 {
		return nil, nil
	}

	padding := internal.GetBytes(paddingLen)
	if err := FillRandomBytes(padding); err != nil {
		internal.PutBytes(padding)
		return nil, err
	}

	return padding, nil
}

// dialProxy connects to the Shadowsocks proxy server.
func (d *Dialer) dialProxy(ctx context.Context, network string) (net.Conn, error) {
	dialer := d.Dialer
	if dialer == nil {
		dialer = socksnet.DefaultDialer
	}
	return dialer.DialContext(ctx, network, d.ProxyAddr)
}

func parseTargetAddr(address string) (Addr, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return Addr{}, err
	}

	port, err := net.DefaultResolver.LookupPort(context.Background(), "tcp", portStr)
	if err != nil {
		return Addr{}, err
	}

	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		return Addr{
			AddrType: AddrTypeIPv4,
			IP:       ip.To4(),
			Port:     uint16(port),
		}, nil

	case ip != nil && ip.To16() != nil:
		return Addr{
			AddrType: AddrTypeIPv6,
			IP:       ip.To16(),
			Port:     uint16(port),
		}, nil

	default:
		return Addr{
			AddrType: AddrTypeDomain,
			Domain:   host,
			Port:     uint16(port),
		}, nil
	}
}

// bindConnToContext sets connection deadlines based on context and ensures cleanup on cancellation.
func bindConnToContext(ctx context.Context, conn net.Conn) (cleanup func()) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	exitCh := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-exitCh:
		}
	}()

	return func() {
		close(exitCh)
		_ = conn.SetDeadline(time.Time{})
	}
}
