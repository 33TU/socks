package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	socksnet "github.com/33TU/socks/net"
	"github.com/33TU/socks/socks5"
)

type Config struct {
	Listen string

	RequestTimeout      time.Duration
	BindAcceptTimeout   time.Duration
	BindConnTimeout     time.Duration
	ConnectDialTimeout  time.Duration
	ConnectConnTimeout  time.Duration
	UDPAssociateTimeout time.Duration
	ConnectBufferSize   int

	AllowConnect      bool
	AllowBind         bool
	AllowUDPAssociate bool
	AllowResolve      bool

	ResolvePreferIPv4 bool

	LogLevel string
}

func defaultConfig() *Config {
	return &Config{
		Listen: "127.0.0.1:1080",

		RequestTimeout:      10 * time.Second,
		BindAcceptTimeout:   10 * time.Second,
		BindConnTimeout:     60 * time.Second,
		ConnectDialTimeout:  10 * time.Second,
		ConnectConnTimeout:  60 * time.Second,
		UDPAssociateTimeout: 60 * time.Second,
		ConnectBufferSize:   32 * 1024,

		AllowConnect:      true,
		AllowBind:         false,
		AllowUDPAssociate: true,
		AllowResolve:      true,

		LogLevel: "info",
	}
}

func parseFlags() *Config {
	cfg := defaultConfig()

	flag.StringVar(&cfg.Listen, "listen", cfg.Listen, "listen address")
	flag.DurationVar(&cfg.RequestTimeout, "request-timeout", cfg.RequestTimeout, "request timeout")
	flag.DurationVar(&cfg.BindAcceptTimeout, "bind-accept-timeout", cfg.BindAcceptTimeout, "bind accept timeout")
	flag.DurationVar(&cfg.BindConnTimeout, "bind-conn-timeout", cfg.BindConnTimeout, "bind conn timeout")
	flag.DurationVar(&cfg.ConnectDialTimeout, "connect-dial-timeout", cfg.ConnectDialTimeout, "connect dial timeout")
	flag.DurationVar(&cfg.ConnectConnTimeout, "connect-conn-timeout", cfg.ConnectConnTimeout, "connect conn timeout")
	flag.DurationVar(&cfg.UDPAssociateTimeout, "udp-timeout", cfg.UDPAssociateTimeout, "UDP associate timeout")
	flag.IntVar(&cfg.ConnectBufferSize, "buffer-size", cfg.ConnectBufferSize, "copy buffer size")

	flag.BoolVar(&cfg.AllowConnect, "allow-connect", cfg.AllowConnect, "allow CONNECT")
	flag.BoolVar(&cfg.AllowBind, "allow-bind", cfg.AllowBind, "allow BIND")
	flag.BoolVar(&cfg.AllowUDPAssociate, "allow-udp", cfg.AllowUDPAssociate, "allow UDP ASSOCIATE")
	flag.BoolVar(&cfg.AllowResolve, "allow-resolve", cfg.AllowResolve, "allow RESOLVE")

	flag.BoolVar(&cfg.ResolvePreferIPv4, "prefer-ipv4", false, "prefer IPv4 over IPv6")

	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level")

	flag.Parse()
	return cfg
}

func setupLogging(level string) {
	lvl := slog.LevelInfo
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	})))
}

func newHandler(cfg *Config) *socks5.BaseServerHandler {
	return &socks5.BaseServerHandler{
		Dialer: socksnet.DefaultDialer,

		RequestTimeout:      cfg.RequestTimeout,
		BindAcceptTimeout:   cfg.BindAcceptTimeout,
		BindConnTimeout:     cfg.BindConnTimeout,
		ConnectDialTimeout:  cfg.ConnectDialTimeout,
		ConnectConnTimeout:  cfg.ConnectConnTimeout,
		UDPAssociateTimeout: cfg.UDPAssociateTimeout,
		ConnectBufferSize:   cfg.ConnectBufferSize,

		AllowConnect:      cfg.AllowConnect,
		AllowBind:         cfg.AllowBind,
		AllowUDPAssociate: cfg.AllowUDPAssociate,
		AllowResolve:      cfg.AllowResolve,

		ResolveResolver:   net.DefaultResolver,
		ResolvePreferIPv4: cfg.ResolvePreferIPv4,

		SupportedMethods: []byte{
			socks5.MethodNoAuth,
		},

		UserPassAuthenticator: nil,
		GSSAPIAuthenticator:   nil,
	}
}

func run(ctx context.Context, cfg *Config) error {
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		return err
	}

	handler := newHandler(cfg)

	slog.Info("starting socks5 server",
		"listen", cfg.Listen,
		"connect", cfg.AllowConnect,
		"bind", cfg.AllowBind,
		"udp", cfg.AllowUDPAssociate,
		"resolve", cfg.AllowResolve,
	)

	return socks5.ListenAndServe(ctx, "tcp", cfg.Listen, handler)
}

func main() {
	cfg := parseFlags()
	setupLogging(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		if ctx.Err() != nil {
			slog.Info("server stopped")
			return
		}
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}
