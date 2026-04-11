// Example showing a multi-hop proxy chain (mux → SOCKS4 → SOCKS5) for an HTTP request.
package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/33TU/socks/chain"
	"github.com/33TU/socks/proxy"
	"github.com/33TU/socks/socks4"
	"github.com/33TU/socks/socks5"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Start three servers concurrently: a mux server on :1080, a SOCKS4 server on :1081, and a SOCKS5 server on :1082
	go proxy.ListenAndServe(ctx, "tcp", ":1080", &proxy.ServerHandler{
		Socks4: socks4.DefaultServerHandler,
		Socks5: socks5.DefaultServerHandler,
	})
	go socks4.ListenAndServe(ctx, "tcp", ":1081", socks4.DefaultServerHandler)
	go socks5.ListenAndServe(ctx, "tcp", ":1082", socks5.DefaultServerHandler)

	// wait for servers to start
	time.Sleep(time.Second)

	// Chain http request thro the servers.
	dialer, err := chain.New(
		&socks4.Dialer{ProxyAddr: "127.0.0.1:1080"}, // socks5 dialer also fine as the mux server supports both protocols
		&socks4.Dialer{ProxyAddr: "127.0.0.1:1081"},
		&socks5.Dialer{ProxyAddr: "127.0.0.1:1082"},
	)
	if err != nil {
		log.Fatalln("Failed to create chain dialer:", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpbin.org/ip", nil)
	if err != nil {
		log.Fatalln("Failed to make HTTP request:", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln("Failed to make HTTP request:", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln("Failed to read response body:", err)
	}

	log.Println("Success - response:", string(body))
}
