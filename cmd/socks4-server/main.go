package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/33TU/socks/socks4"
)

type Config struct {
	Listen             string
	RequestTimeout     time.Duration
	BindAcceptTimeout  time.Duration
	BindConnTimeout    time.Duration
	ConnectDialTimeout time.Duration
	ConnectConnTimeout time.Duration
	ConnectBufferSize  int
	AllowConnect       bool
	AllowBind          bool
	LogLevel           string
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.Listen, "listen", "127.0.0.1:1080", "Address to listen on (host:port)")
	flag.DurationVar(&config.RequestTimeout, "request-timeout", 10*time.Second, "Timeout for processing requests")
	flag.DurationVar(&config.BindAcceptTimeout, "bind-accept-timeout", 10*time.Second, "Timeout for BIND accept operations")
	flag.DurationVar(&config.BindConnTimeout, "bind-conn-timeout", 60*time.Second, "Timeout for BIND connection operations")
	flag.DurationVar(&config.ConnectDialTimeout, "connect-dial-timeout", 10*time.Second, "Timeout for CONNECT dial operations")
	flag.DurationVar(&config.ConnectConnTimeout, "connect-conn-timeout", 60*time.Second, "Timeout for CONNECT connection operations")
	flag.IntVar(&config.ConnectBufferSize, "buffer-size", 32*1024, "Buffer size for data copying (bytes)")
	flag.BoolVar(&config.AllowConnect, "allow-connect", true, "Allow CONNECT requests")
	flag.BoolVar(&config.AllowBind, "allow-bind", false, "Allow BIND requests")
	flag.StringVar(&config.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "A SOCKS4/4a proxy server implementation.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -listen :1080\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -listen 127.0.0.1:9999 -allow-bind\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -listen 0.0.0.0:1080 -log-level debug\n", os.Args[0])
	}

	flag.Parse()
	return config
}

func setupLogging(level string) {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)
}

func main() {
	config := parseFlags()

	// Setup logging
	setupLogging(config.LogLevel)

	// Validate listen address
	_, _, err := net.SplitHostPort(config.Listen)
	if err != nil {
		slog.Error("Invalid listen address", "address", config.Listen, "error", err)
		os.Exit(1)
	}

	// Create server handler
	handler := &socks4.BaseServerHandler{
		RequestTimeout:     config.RequestTimeout,
		BindAcceptTimeout:  config.BindAcceptTimeout,
		BindConnTimeout:    config.BindConnTimeout,
		ConnectDialTimeout: config.ConnectDialTimeout,
		ConnectConnTimeout: config.ConnectConnTimeout,
		ConnectBufferSize:  config.ConnectBufferSize,
		AllowConnect:       config.AllowConnect,
		AllowBind:          config.AllowBind,
	}

	slog.Info("Starting SOCKS4 server",
		"listen", config.Listen,
		"allow_connect", config.AllowConnect,
		"allow_bind", config.AllowBind,
		"request_timeout", config.RequestTimeout,
		"bind_accept_timeout", config.BindAcceptTimeout,
		"bind_conn_timeout", config.BindConnTimeout,
		"connect_dial_timeout", config.ConnectDialTimeout,
		"connect_conn_timeout", config.ConnectConnTimeout,
		"buffer_size", config.ConnectBufferSize,
	)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		slog.Info("Received shutdown signal", "signal", sig)
		cancel()
	}()

	// Start server
	if err := socks4.ListenAndServe(ctx, "tcp", config.Listen, handler); err != nil {
		if ctx.Err() != nil {
			slog.Info("Server stopped gracefully")
		} else {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}
}
