// Command socks5-local runs a local SOCKS5 server that tunnels every
// connection through a Shadowsocks 2022 proxy.
//
// This is the usual way to use a Shadowsocks client: point a browser, curl, or
// anything else that speaks SOCKS5 at the local address, and its traffic leaves
// through the Shadowsocks server.
//
//	socks5-local -proxy ss://2022-blake3-aes-128-gcm:<psk>@server:8388
//	curl --socks5-hostname 127.0.0.1:1080 https://example.com
//
// TCP and UDP both leave through the proxy: CONNECT is dialed through it, and
// UDP ASSOCIATE relays over a Shadowsocks UDP session.
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/33TU/socks/shadowsocks"
	"github.com/33TU/socks/socks5"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1080", "local address to serve SOCKS5 on")
	udp := flag.Bool("udp", true, "relay UDP as well as TCP")
	proxyURL := flag.String(
		"proxy",
		os.Getenv("SS_PROXY_URL"),
		`Shadowsocks proxy URL, e.g. ss://2022-blake3-aes-128-gcm:iDN+jVYAcTkUxwNICMTQRA==@127.0.0.1:8388`,
	)

	flag.Parse()

	if *proxyURL == "" {
		log.Fatal("missing proxy URL; set -proxy or SS_PROXY_URL")
	}

	dialer, err := shadowsocks.NewDialerFromURLString(*proxyURL, nil)
	if err != nil {
		log.Fatalf("failed to create dialer: %v", err)
	}

	// Every outbound connection the SOCKS5 server makes is dialed through the
	// Shadowsocks proxy. Target domain names are passed through untouched and
	// resolved by the Shadowsocks server, so no DNS leaks locally.
	handler := &socks5.BaseServerHandler{
		Dialer:             dialer,
		AllowConnect:       true,
		RequestTimeout:     30 * time.Second,
		ConnectConnTimeout: 5 * time.Minute,
		ConnectBufferSize:  32 * 1024,

		// Each association relays over its own Shadowsocks UDP session, so UDP
		// leaves through the proxy rather than straight out of this host.
		AllowUDPAssociate:      *udp,
		UDPAssociateTimeout:    5 * time.Minute,
		UDPAssociateBufferSize: 64 * 1024,
		UDPListenPacket: func(ctx context.Context, _ net.Conn, _ *socks5.Request) (net.PacketConn, error) {
			return dialer.ListenPacket(ctx, nil)
		},

		// BIND and RESOLVE stay off. The SOCKS5 server implements them with its
		// own listener and resolver, which would step outside the tunnel.
		AllowBind:    false,
		AllowResolve: false,

		SupportedMethods: []byte{socks5.MethodNoAuth},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("local SOCKS5 server listening",
		"address", *listen,
		"proxy", dialer.ProxyAddress(),
		"udp", *udp,
	)

	if err := socks5.ListenAndServe(ctx, "tcp", *listen, handler); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
