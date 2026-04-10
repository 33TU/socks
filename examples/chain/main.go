// Example showing a multi-hop proxy chain (mux → SOCKS4 → SOCKS5) for an HTTP request.
package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/33TU/socks/chain"
	"github.com/33TU/socks/proxy"
	"github.com/33TU/socks/socks4"
	"github.com/33TU/socks/socks5"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	// Start three servers concurrently: a mux server on :1080, a SOCKS4 server on :1081, and a SOCKS5 server on :1082
	g.Go(func() error {
		return proxy.ListenAndServe(ctx, "tcp", ":1080", &proxy.ServerHandler{
			Socks4: socks4.DefaultServerHandler,
			Socks5: socks5.DefaultServerHandler,
		})
	})

	g.Go(func() error {

		return socks4.ListenAndServe(ctx, "tcp", ":1081", socks4.DefaultServerHandler)
	})

	g.Go(func() error {
		return socks5.ListenAndServe(ctx, "tcp", ":1082", socks5.DefaultServerHandler)
	})

	// Make a http request through the chain of servers: mux -> socks4 -> socks5
	g.Go(func() error {
		// wait for servers to start
		time.Sleep(time.Second)

		// Chain http request thro the servers.
		dialer, err := chain.Chain(
			socks4.NewDialer("127.0.0.1:1080", "", nil), // socks5 dialer also fine as the mux server supports both protocols
			socks4.NewDialer("127.0.0.1:1081", "", nil),
			socks5.NewDialer("127.0.0.1:1082", nil, nil),
		)
		if err != nil {
			return err
		}

		transport := &http.Transport{
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
		}

		client := &http.Client{
			Transport: transport,
		}

		resp, err := client.Get("https://httpbin.org/ip")
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		log.Println("Response:")
		log.Println(string(body))
		return nil
	})

	// Wait for all goroutines to finish and check for errors.
	// Ignore accept errors, those are expected when the servers are shutting down.
	if err := g.Wait(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatalln("error:", err)
	}

	log.Println("Successfully connected through the chain")
}
