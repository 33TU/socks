package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/33TU/socks/socks4"
)

type Config struct {
	Listen string

	RequestTimeout     time.Duration
	BindAcceptTimeout  time.Duration
	BindConnTimeout    time.Duration
	ConnectDialTimeout time.Duration
	ConnectConnTimeout time.Duration
	ConnectBufferSize  int

	AllowConnect bool
	AllowBind    bool

	LogLevel       string
	AllowedUserIDs string
	RequireUserID  bool
}

func defaultConfig() *Config {
	return &Config{
		Listen: "127.0.0.1:1080",

		RequestTimeout:     10 * time.Second,
		BindAcceptTimeout:  10 * time.Second,
		BindConnTimeout:    60 * time.Second,
		ConnectDialTimeout: 10 * time.Second,
		ConnectConnTimeout: 60 * time.Second,
		ConnectBufferSize:  32 * 1024,

		AllowConnect: true,
		AllowBind:    false,

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
	flag.IntVar(&cfg.ConnectBufferSize, "buffer-size", cfg.ConnectBufferSize, "copy buffer size")
	flag.BoolVar(&cfg.AllowConnect, "allow-connect", cfg.AllowConnect, "allow CONNECT")
	flag.BoolVar(&cfg.AllowBind, "allow-bind", cfg.AllowBind, "allow BIND")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level")
	flag.StringVar(&cfg.AllowedUserIDs, "allowed-userids", "", "allowed user IDs (comma-separated)")
	flag.BoolVar(&cfg.RequireUserID, "require-userid", false, "require non-empty user ID")

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

func userIDChecker(cfg *Config) func(context.Context, string) error {
	if !cfg.RequireUserID && cfg.AllowedUserIDs == "" {
		return nil
	}

	var allowed map[string]struct{}
	if cfg.AllowedUserIDs != "" {
		allowed = make(map[string]struct{})
		for _, id := range strings.Split(cfg.AllowedUserIDs, ",") {
			allowed[strings.TrimSpace(id)] = struct{}{}
		}
	}

	return func(_ context.Context, userID string) error {
		if cfg.RequireUserID && userID == "" {
			return errors.New("user ID required")
		}
		if allowed == nil {
			return nil
		}
		if _, ok := allowed[userID]; !ok {
			return errors.New("user ID not allowed")
		}
		return nil
	}
}

func newHandler(cfg *Config) *socks4.BaseServerHandler {
	return &socks4.BaseServerHandler{
		RequestTimeout:     cfg.RequestTimeout,
		BindAcceptTimeout:  cfg.BindAcceptTimeout,
		BindConnTimeout:    cfg.BindConnTimeout,
		ConnectDialTimeout: cfg.ConnectDialTimeout,
		ConnectConnTimeout: cfg.ConnectConnTimeout,
		ConnectBufferSize:  cfg.ConnectBufferSize,
		AllowConnect:       cfg.AllowConnect,
		AllowBind:          cfg.AllowBind,
		UserIDChecker:      userIDChecker(cfg),
	}
}

func run(ctx context.Context, cfg *Config) error {
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		return err
	}

	handler := newHandler(cfg)

	slog.Info("starting socks4 server", "listen", cfg.Listen)

	return socks4.ListenAndServe(ctx, "tcp", cfg.Listen, handler)
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
