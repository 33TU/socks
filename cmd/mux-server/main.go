package main

import (
	"context"
	"log"

	"github.com/33TU/socks/proxy"
	"github.com/33TU/socks/socks4"
	"github.com/33TU/socks/socks5"
)

func main() {
	ctx := context.Background()

	handler := &proxy.ServerHandler{
		Socks4: socks4.DefaultServerHandler,
		Socks5: socks5.DefaultServerHandler,
	}

	log.Println("Starting proxy on :1080 (SOCKS4 + SOCKS5)")

	if err := proxy.ListenAndServe(ctx, "tcp", ":1080", handler); err != nil {
		log.Fatal(err)
	}
}
