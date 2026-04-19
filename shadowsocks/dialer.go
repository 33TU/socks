package shadowsocks

import (
	"fmt"
	"net"
	"net/url"

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
