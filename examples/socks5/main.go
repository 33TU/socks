// Simple SOCKS5 server using the base handler allowing CONNECT and BIND commands with default timeouts and buffer size.
package main

import (
	"context"
	"log"

	"github.com/33TU/socks/socks5"
)

func main() {
	handler := &socks5.BaseServerHandler{
		AllowConnect: true,
		AllowBind:    true,
	}

	log.Println("SOCKS5 listening on 127.0.0.1:1080")

	if err := socks5.ListenAndServe(context.Background(), "tcp", "127.0.0.1:1080", handler); err != nil {
		log.Fatal(err)
	}
}
