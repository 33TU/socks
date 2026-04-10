// Example SOCKS5 UDP client using PacketConn.
//
// This program demonstrates how to use the SOCKS5 dialer to perform a UDP ASSOCIATE
// and send/receive UDP packets (DNS queries in this case) through the proxy.
//
// It sends multiple DNS queries to 1.1.1.1 and prints the responses, showing that
// the same PacketConn can be reused without re-establishing the UDP association.
//
// To run this example:
//  1. Start the SOCKS5 server example (e.g. examples/socks5 or UDP associate server)
//  2. Then run this program
//
// The SOCKS5 server must be listening on 127.0.0.1:1080.
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/33TU/socks/socks5"
)

func main() {
	d := socks5.NewDialer("127.0.0.1:1080", nil, nil)

	// 1. Get PacketConn (this does UDP ASSOCIATE internally)
	pc, err := d.ListenPacket(context.Background(), "tcp", nil)
	if err != nil {
		panic(err)
	}
	defer pc.Close()

	fmt.Println("SOCKS5 UDP ready")

	// Optional: timeout so Read doesn't hang forever
	pc.SetDeadline(time.Now().Add(5 * time.Second))

	// 2. DNS query (google.com A record)
	dnsQuery := []byte{
		0x12, 0x34,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,

		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,

		0x00, 0x01,
		0x00, 0x01,
	}

	target := &net.UDPAddr{
		IP:   net.IPv4(1, 1, 1, 1),
		Port: 53,
	}

	var buf [4096]byte

	// Send multiple queries to demonstrate that the same PacketConn can be reused without re-associating
	for i := 0; i < 3; i++ {
		// 3. Send DNS query
		_, err = pc.WriteTo(dnsQuery, target)
		if err != nil {
			panic(err)
		}

		fmt.Println("Sent DNS query")

		// 4. Read response
		n, addr, err := pc.ReadFrom(buf[:])
		if err != nil {
			panic(err)
		}

		fmt.Println("Received bytes:", n)
		fmt.Println("Response from:", addr)

		// 5. DNS payload is already unwrapped (no SOCKS5 header!)
		data := buf[:n]

		fmt.Println("Payload size:", len(data))
		fmt.Printf("DNS raw (first 32 bytes): %x\n", data[:min(32, len(data))])
	}
}
