package socks5

import (
	"net"
	"time"

	"github.com/33TU/socks/internal"
)

// UDPConn is a net.PacketConn that wraps the UDP socket used for SOCKS5 UDP ASSOCIATE, allowing it to be used with standard Go APIs.
type UDPConn struct {
	tcpConn   net.Conn     // control connection (UDP ASSOCIATE)
	udpConn   *net.UDPConn // actual UDP socket to proxy
	relayAddr *net.UDPAddr // proxy UDP endpoint
}

// NewUDPConn creates a new UDPConn for the given TCP control connection, UDP socket, and proxy relay address.
func NewUDPConn(tcpConn net.Conn, udpConn *net.UDPConn, relayAddr *net.UDPAddr) *UDPConn {
	return &UDPConn{
		tcpConn:   tcpConn,
		udpConn:   udpConn,
		relayAddr: relayAddr,
	}
}

// LocalAddr implements [net.PacketConn].
func (c *UDPConn) LocalAddr() net.Addr {
	return c.udpConn.LocalAddr()
}

// SetDeadline implements [net.PacketConn].
func (c *UDPConn) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}

// SetReadDeadline implements [net.PacketConn].
func (c *UDPConn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

// SetWriteDeadline implements [net.PacketConn].
func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}

// WriteTo implements [net.PacketConn].
func (c *UDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr := addr.(*net.UDPAddr)

	ip := udpAddr.IP
	addrType := AddrTypeIPv6
	if ip4 := ip.To4(); ip4 != nil {
		addrType = AddrTypeIPv4
		ip = ip4
	}

	pkt := UDPPacket{
		Reserved: [2]byte{0, 0},
		Frag:     0,
		AddrType: byte(addrType),
		IP:       ip,
		Port:     uint16(udpAddr.Port),
		Data:     p,
	}

	buf := internal.GetBytes(pkt.Size())
	defer internal.PutBytes(buf)

	n, err := pkt.MarshalTo(buf)
	if err != nil {
		return 0, err
	}

	if c.udpConn.RemoteAddr() != nil {
		// connected socket
		_, err = c.udpConn.Write(buf[:n])
	} else {
		// unconnected socket
		_, err = c.udpConn.WriteToUDP(buf[:n], c.relayAddr)
	}

	if err != nil {
		return 0, err
	}

	return len(p), nil
}

// ReadFrom implements [net.PacketConn].
func (c *UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, _, err := c.udpConn.ReadFromUDP(p)
	if err != nil {
		return 0, nil, err
	}

	var pkt UDPPacket
	_, err = pkt.UnmarshalFrom(p[:n])
	if err != nil {
		return 0, nil, err
	}

	copy(p, pkt.Data)

	addr := &net.UDPAddr{
		IP:   pkt.IP,
		Port: int(pkt.Port),
	}

	return len(pkt.Data), addr, nil
}

// Close implements [net.PacketConn].
func (c *UDPConn) Close() error {
	c.udpConn.Close()
	return c.tcpConn.Close() // MUST close control connection
}
