package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/33TU/socks/shadowsocks"
	"golang.org/x/sync/errgroup"
)

func main() {
	listen := flag.String("listen", ":8388", "address to listen on")
	method := flag.String("method", shadowsocks.Method2022Blake3AES128GCM, "encryption method")
	psk := flag.String("psk", os.Getenv("SS_PSK"), "base64 pre-shared key; generated when empty")
	mode := flag.String("mode", modeTCPAndUDP, "which transports to relay: tcp_only, udp_only, or tcp_and_udp")

	flag.Parse()

	serveTCP, serveUDP, err := parseMode(*mode)
	if err != nil {
		log.Fatal(err)
	}

	if *psk == "" {
		generated, err := generatePSK(*method)
		if err != nil {
			log.Fatalf("failed to generate PSK: %v", err)
		}
		*psk = generated
		log.Printf("generated PSK: %s", *psk)
	}

	cfg := &shadowsocks.Config{Method: *method, PSK: *psk}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	log.Printf("proxy URL: ss://%s:%s@%s", cfg.Method, cfg.PSK, *listen)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	g, ctx := errgroup.WithContext(ctx)

	if serveTCP {
		g.Go(func() error {
			handler := &shadowsocks.BaseServerHandler{
				Config:             cfg,
				AllowConnect:       true,
				RequestTimeout:     30 * time.Second,
				ConnectConnTimeout: 5 * time.Minute,
				ConnectBufferSize:  32 * 1024,
			}

			slog.Info("shadowsocks TCP server listening", "address", *listen)
			return shadowsocks.ListenAndServe(ctx, "tcp", *listen, handler)
		})
	}

	if serveUDP {
		g.Go(func() error {
			handler := &shadowsocks.BaseUDPServerHandler{
				Config:         cfg,
				AllowRelay:     true,
				SessionTimeout: 5 * time.Minute,
			}

			slog.Info("shadowsocks UDP relay listening", "address", *listen)
			return shadowsocks.ListenAndServePacket(ctx, *listen, handler)
		})
	}

	if err := g.Wait(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// Relay modes, named as other Shadowsocks implementations name them.
const (
	modeTCPOnly   = "tcp_only"
	modeUDPOnly   = "udp_only"
	modeTCPAndUDP = "tcp_and_udp"
)

// parseMode reports which transports a mode selects. TCP and UDP are wholly
// independent in Shadowsocks, so any of the three combinations is valid, and a
// UDP-only server needs no TCP connection to work.
func parseMode(mode string) (tcp, udp bool, err error) {
	switch mode {
	case modeTCPOnly:
		return true, false, nil
	case modeUDPOnly:
		return false, true, nil
	case modeTCPAndUDP:
		return true, true, nil
	default:
		return false, false, fmt.Errorf(
			"invalid mode %q: want %s, %s, or %s",
			mode, modeTCPOnly, modeUDPOnly, modeTCPAndUDP,
		)
	}
}

// generatePSK creates a random pre-shared key of the size the method requires.
func generatePSK(methodName string) (string, error) {
	method, err := shadowsocks.ParseMethod(methodName)
	if err != nil {
		return "", err
	}

	key := make([]byte, method.KeySize)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(key), nil
}
