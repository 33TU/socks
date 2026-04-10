// Example SOCKS5 resolve client.
//
// This program demonstrates how to use the SOCKS5 dialer to resolve hostnames
// through the proxy using the RESOLVE command.
//
// To run this example:
//  1. Start the SOCKS5 server example with AllowResolve enabled
//     (e.g. examples/socks5 or similar)
//  2. Then run this program
//
// The SOCKS5 server must be listening on 127.0.0.1:1080.
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/33TU/socks/socks5"
)

func main() {
	d := socks5.NewDialer("127.0.0.1:1080", nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hosts := []string{
		"localhost",
		"google.com",
		"cloudflare.com",
	}

	for _, host := range hosts {
		ip, err := d.ResolveContext(ctx, "tcp", host)
		if err != nil {
			fmt.Printf("Resolve failed for %s: %v\n", host, err)
			continue
		}

		fmt.Printf("Resolved %-15s -> %v\n", host, ip)
	}
}
