// Simple SOCKS4 server using the base handler allowing CONNECT and BIND commands with default timeouts and buffer size.
package main

import (
	"context"
	"log"

	"github.com/33TU/socks/socks4"
)

func main() {
	handler := &socks4.BaseServerHandler{
		AllowConnect: true,
		AllowBind:    true,
	}

	log.Println("SOCKS4 listening on 127.0.0.1:1080")

	if err := socks4.ListenAndServe(context.Background(), "tcp", "127.0.0.1:1080", handler); err != nil {
		log.Fatal(err)
	}
}
