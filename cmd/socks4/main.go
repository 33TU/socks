package main

import (
	"context"
	"flag"
	"log"
	"net"

	"github.com/33TU/socks/socks4"
)

var (
	FlagNetwork = flag.String("network", "tcp", "listen network")
	FlagAddress = flag.String("address", ":1080", "listen address")
)

func main() {
	flag.Parse()

	listener, err := net.Listen(*FlagNetwork, *FlagAddress)
	if err != nil {
		log.Fatalln("net.Listen:", err)
	}
	log.Printf("listening on %v", listener.Addr())

	err = socks4.Serve(listener, &socks4.ListenerOptions{
		OnAccept: func(ctx context.Context, opts *socks4.ListenerOptions, conn net.Conn) error {
			log.Printf("accept: %v", conn.RemoteAddr())
			return nil
		},
		OnError: func(ctx context.Context, opts *socks4.ListenerOptions, conn net.Conn, err error) {
			log.Printf("error: %v", err)
		},
		OnRequest: func(ctx context.Context, opts *socks4.ListenerOptions, conn net.Conn, req *socks4.Request) error {
			log.Printf("%v begin request: %v", conn.RemoteAddr(), req)
			err := socks4.OnRequestDefault(ctx, opts, conn, req)
			log.Printf("%v end request: %v", conn.RemoteAddr(), req)
			return err
		},
		OnPanic: func(ctx context.Context, opts *socks4.ListenerOptions, conn net.Conn, r any) {
			log.Printf("panic: %v", r)
		},
	})
	if err != nil {
		log.Fatalln("socks4.Serve:", err)
	}
}
