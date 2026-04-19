package shadowsocks

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"time"

	socksnet "github.com/33TU/socks/net"
)

// Dialer implements a Shadowsocks proxy dialer.
type Dialer struct {
	ProxyAddr string
	Config    *Config
	Dialer    socksnet.Dialer
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
// For AEAD-2022, userinfo must be plain method:psk and not legacy base64-wrapped userinfo.
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

	if u.User == nil {
		return nil, fmt.Errorf("missing method/psk in proxy URL")
	}

	method := u.User.Username()
	if method == "" {
		return nil, fmt.Errorf("missing method in proxy URL")
	}

	psk, hasPassword := u.User.Password()
	if !hasPassword {
		return nil, fmt.Errorf("missing PSK in proxy URL")
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
// For AEAD-2022, userinfo must be plain method:psk and not legacy base64-wrapped userinfo.
func NewDialerFromURLString(rawURL string, dialer socksnet.Dialer) (*Dialer, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	return NewDialerFromURL(u, dialer)
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
	if d == nil {
		conn.Close()
		return nil, fmt.Errorf("nil shadowsocks dialer")
	}
	if d.Config == nil {
		conn.Close()
		return nil, fmt.Errorf("missing shadowsocks config")
	}
	if err := d.Config.Validate(); err != nil {
		conn.Close()
		return nil, err
	}

	method, err := ParseMethod(d.Config.Method)
	if err != nil {
		conn.Close()
		return nil, err
	}

	psk, err := DecodePSKTo(nil, method, d.Config.PSK)
	if err != nil {
		conn.Close()
		return nil, err
	}

	target, err := parseTargetAddr(address)
	if err != nil {
		conn.Close()
		return nil, err
	}

	requestSalt := make([]byte, method.SaltSize)
	if err := FillSaltTo(requestSalt, method); err != nil {
		conn.Close()
		return nil, err
	}

	// cancellation and deadline handling
	cleanup := bindConnToContext(ctx, conn)
	defer cleanup()

	var reqStart TCPClientRequestStart
	if err := reqStart.Init(method, psk, requestSalt); err != nil {
		conn.Close()
		return nil, err
	}

	log.Println("writing request start")
	if _, err := reqStart.WriteRequestStart(conn, time.Now(), target, []byte{0}, nil); err != nil {
		conn.Close()
		return nil, err
	}

	var writer TCPChunkWriter
	if err := writer.Init(reqStart.RequestCipher); err != nil {
		conn.Close()
		return nil, err
	}

	return &TcpConn{
		Conn:     conn,
		Writer:   writer,
		reqStart: &reqStart,
	}, nil
}

// DialConn upgrades an existing connection using background context.
func (d *Dialer) DialConn(conn net.Conn, network, address string) (net.Conn, error) {
	return d.DialConnContext(context.Background(), conn, network, address)
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
