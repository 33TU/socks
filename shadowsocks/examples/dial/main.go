package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/33TU/socks/shadowsocks"
)

func main() {
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

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}

	client := &http.Client{
		Transport: transport,
	}

	resp, err := client.Get("https://httpbin.org/ip")
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read response body: %v", err)
	}

	fmt.Printf("status: %s\n", resp.Status)
	fmt.Printf("body:\n%s\n", body)
}
