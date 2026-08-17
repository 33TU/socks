package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
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
	udp := flag.Bool("udp", true, "also relay UDP")

	flag.Parse()

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

	if *udp {
		g.Go(func() error {
			server := &shadowsocks.UDPServer{
				Config:         cfg,
				SessionTimeout: 5 * time.Minute,
			}

			slog.Info("shadowsocks UDP relay listening", "address", *listen)
			return server.ListenAndServe(ctx, *listen)
		})
	}

	if err := g.Wait(); err != nil {
		log.Fatalf("server error: %v", err)
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
