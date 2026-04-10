// Simple SOCKS4 + SOCKS5 mux server using the base handler allowing CONNECT command with default timeouts and buffer size.
package main

import (
	"context"
	"log"

	"github.com/33TU/socks/proxy"
	"github.com/33TU/socks/socks4"
	"github.com/33TU/socks/socks5"
)

func main() {
	handler := &proxy.ServerHandler{
		Socks4: socks4.DefaultServerHandler,
		Socks5: socks5.DefaultServerHandler,
	}

	log.Println("SOCKS4 + SOCKS5 mux listening on 127.0.0.1:1080")

	if err := proxy.ListenAndServe(context.Background(), "tcp", "127.0.0.1:1080", handler); err != nil {
		log.Fatal(err)
	}
}
