package shadowsocks_test

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/33TU/socks/socks5"
)

// startFixedDNS starts a DNS server answering every A query with ip, and
// returns its address. It stands in for the resolver a Shadowsocks server
// would use, so a test can tell remote resolution from local.
func startFixedDNS(t *testing.T, ip net.IP) string {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen fake dns: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			resp := fixedDNSAnswer(buf[:n], ip)
			if resp == nil {
				continue
			}
			if _, err := conn.WriteToUDP(resp, from); err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		conn.Close()
		<-done
	})

	return conn.LocalAddr().String()
}

// fixedDNSAnswer builds a response to query resolving the name to ip.
func fixedDNSAnswer(query []byte, ip net.IP) []byte {
	if len(query) < 12 {
		return nil
	}

	// Only the header and question are echoed. Go sends an EDNS0 record in the
	// additional section, and keeping it would leave it sitting where the
	// parser expects the answer.
	end := 12
	for end < len(query) && query[end] != 0 {
		end += int(query[end]) + 1
	}
	end += 1 + 4 // root label, then qtype and qclass
	if end > len(query) {
		return nil
	}

	qtype := binary.BigEndian.Uint16(query[end-4 : end-2])

	resp := append([]byte(nil), query[:end]...)
	resp[2] |= 0x80                            // QR: this is a response
	resp[3] = 0x80                             // recursion available, no error
	binary.BigEndian.PutUint16(resp[8:10], 0)  // no authority records
	binary.BigEndian.PutUint16(resp[10:12], 0) // no additional records

	ip4 := ip.To4()
	if qtype != 1 || ip4 == nil {
		binary.BigEndian.PutUint16(resp[6:8], 0)
		return resp
	}

	binary.BigEndian.PutUint16(resp[6:8], 1)

	// A pointer back to the question's name, then the A record itself.
	resp = append(resp, 0xc0, 0x0c)
	resp = binary.BigEndian.AppendUint16(resp, 1)  // type A
	resp = binary.BigEndian.AppendUint16(resp, 1)  // class IN
	resp = binary.BigEndian.AppendUint32(resp, 60) // TTL
	resp = binary.BigEndian.AppendUint16(resp, 4)  // RDLENGTH
	return append(resp, ip4...)
}

// socks5Associate performs a UDP ASSOCIATE over conn and returns the relay
// address, so a test can send packets the client API cannot express.
func socks5Associate(t *testing.T, conn net.Conn) *net.UDPAddr {
	t.Helper()

	var hs socks5.HandshakeRequest
	hs.Init(socks5.SocksVersion, socks5.MethodNoAuth)
	if _, err := hs.WriteTo(conn); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	var hsReply socks5.HandshakeReply
	if _, err := hsReply.ReadFrom(conn); err != nil {
		t.Fatalf("read handshake reply: %v", err)
	}

	var req socks5.Request
	req.Init(socks5.SocksVersion, socks5.CmdUDPAssociate, 0, socks5.AddrTypeIPv4, net.IPv4zero, "", 0)
	if _, err := req.WriteTo(conn); err != nil {
		t.Fatalf("write associate request: %v", err)
	}

	var reply socks5.Reply
	if _, err := reply.ReadFrom(conn); err != nil {
		t.Fatalf("read associate reply: %v", err)
	}
	if reply.Reply != socks5.RepSuccess {
		t.Fatalf("associate rejected: %d", reply.Reply)
	}

	relay, err := net.ResolveUDPAddr("udp", reply.Addr())
	if err != nil {
		t.Fatalf("resolve relay address: %v", err)
	}
	if relay.IP.IsUnspecified() {
		relay.IP = net.ParseIP("127.0.0.1")
	}

	return relay
}

// socks5DomainPacket builds a SOCKS5 UDP packet addressed to a domain.
func socks5DomainPacket(t *testing.T, domain string, port uint16, payload []byte) []byte {
	t.Helper()

	var pkt socks5.UDPPacket
	pkt.Init([2]byte{}, 0, socks5.AddrTypeDomain, nil, domain, port, payload)

	buf := make([]byte, pkt.Size())
	n, err := pkt.MarshalTo(buf)
	if err != nil {
		t.Fatalf("marshal udp packet: %v", err)
	}

	return buf[:n]
}
