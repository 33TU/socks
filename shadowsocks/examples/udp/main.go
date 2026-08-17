package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/33TU/socks/shadowsocks"
)

func main() {
	proxyURL := flag.String(
		"proxy",
		os.Getenv("SS_PROXY_URL"),
		`Shadowsocks proxy URL, e.g. ss://2022-blake3-aes-128-gcm:iDN+jVYAcTkUxwNICMTQRA==@127.0.0.1:8388`,
	)
	resolver := flag.String("resolver", "1.1.1.1:53", "DNS server to query through the proxy")
	name := flag.String("name", "example.com", "domain name to resolve")

	flag.Parse()

	if *proxyURL == "" {
		log.Fatal("missing proxy URL; set -proxy or SS_PROXY_URL")
	}

	dialer, err := shadowsocks.NewDialerFromURLString(*proxyURL, nil)
	if err != nil {
		log.Fatalf("failed to create dialer: %v", err)
	}

	// One relay session carries every datagram written to this connection.
	conn, err := dialer.ListenPacket(context.Background(), nil)
	if err != nil {
		log.Fatalf("failed to open UDP relay session: %v", err)
	}
	defer conn.Close()

	target, err := net.ResolveUDPAddr("udp", *resolver)
	if err != nil {
		log.Fatalf("failed to resolve DNS server address: %v", err)
	}

	query, err := buildDNSQuery(*name)
	if err != nil {
		log.Fatalf("failed to build DNS query: %v", err)
	}

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Fatalf("failed to set deadline: %v", err)
	}

	if _, err := conn.WriteTo(query, target); err != nil {
		log.Fatalf("failed to send query: %v", err)
	}

	buf := make([]byte, 4096)
	n, from, err := conn.ReadFrom(buf)
	if err != nil {
		log.Fatalf("failed to read response: %v", err)
	}

	fmt.Printf("received %d bytes from %s\n", n, from)

	addrs, err := parseDNSAnswers(buf[:n])
	if err != nil {
		log.Fatalf("failed to parse response: %v", err)
	}

	for _, addr := range addrs {
		fmt.Printf("%s has address %s\n", *name, addr)
	}
}

// buildDNSQuery builds a minimal DNS query for the A records of name.
func buildDNSQuery(name string) ([]byte, error) {
	msg := []byte{
		0x12, 0x34, // transaction ID
		0x01, 0x00, // standard query, recursion desired
		0x00, 0x01, // one question
		0x00, 0x00, // no answers
		0x00, 0x00, // no authority records
		0x00, 0x00, // no additional records
	}

	for label := range splitLabels(name) {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid label in %q", name)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}

	msg = append(msg, 0x00) // root label
	msg = append(msg, 0x00, 0x01)
	msg = append(msg, 0x00, 0x01)

	return msg, nil
}

// splitLabels iterates the dot-separated labels of a domain name.
func splitLabels(name string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for len(name) > 0 {
			i := 0
			for i < len(name) && name[i] != '.' {
				i++
			}
			if !yield(name[:i]) {
				return
			}
			if i == len(name) {
				return
			}
			name = name[i+1:]
		}
	}
}

// parseDNSAnswers extracts the A records from a DNS response.
func parseDNSAnswers(msg []byte) ([]net.IP, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("short DNS response")
	}

	questions := int(msg[4])<<8 | int(msg[5])
	answers := int(msg[6])<<8 | int(msg[7])

	pos := 12
	for range questions {
		n, err := skipDNSName(msg, pos)
		if err != nil {
			return nil, err
		}
		pos = n + 4 // type + class
	}

	var ips []net.IP
	for range answers {
		n, err := skipDNSName(msg, pos)
		if err != nil {
			return nil, err
		}
		pos = n

		if pos+10 > len(msg) {
			return nil, fmt.Errorf("truncated answer")
		}

		recordType := int(msg[pos])<<8 | int(msg[pos+1])
		dataLen := int(msg[pos+8])<<8 | int(msg[pos+9])
		pos += 10

		if pos+dataLen > len(msg) {
			return nil, fmt.Errorf("truncated answer data")
		}
		if recordType == 1 && dataLen == 4 {
			ips = append(ips, net.IP(msg[pos:pos+4]))
		}
		pos += dataLen
	}

	return ips, nil
}

// skipDNSName advances past a domain name, following a compression pointer.
func skipDNSName(msg []byte, pos int) (int, error) {
	for {
		if pos >= len(msg) {
			return 0, fmt.Errorf("truncated name")
		}

		length := int(msg[pos])
		switch {
		case length == 0:
			return pos + 1, nil
		case length&0xc0 == 0xc0:
			return pos + 2, nil
		default:
			pos += length + 1
		}
	}
}
