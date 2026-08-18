package shadowsocks_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/33TU/socks/shadowsocks"
)

// benchMethod is the method most deployments use.
func benchMethod(b *testing.B) (shadowsocks.Method, []byte) {
	b.Helper()

	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)
	if err != nil {
		b.Fatal(err)
	}

	psk := make([]byte, method.KeySize)
	for i := range psk {
		psk[i] = byte(i)
	}

	return method, psk
}

func benchCipher(b *testing.B) *shadowsocks.TCPStreamCipher {
	b.Helper()

	method, psk := benchMethod(b)
	salt := bytes.Repeat([]byte{0x11}, method.SaltSize)

	c, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, salt)
	if err != nil {
		b.Fatal(err)
	}
	return c
}

// discardConn swallows writes, so a benchmark measures framing rather than the
// kernel.
type discardConn struct{ net.Conn }

func (discardConn) Write(p []byte) (int, error) { return len(p), nil }

// discardPacketConn swallows datagrams for the same reason.
type discardPacketConn struct{ net.PacketConn }

func (discardPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (discardPacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (discardPacketConn) Close() error                              { return nil }
func (discardPacketConn) SetDeadline(time.Time) error               { return nil }
func (discardPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (discardPacketConn) SetWriteDeadline(time.Time) error          { return nil }

func BenchmarkTCPChunkWriter(b *testing.B) {
	for _, size := range []int{1400, 16 * 1024, 64 * 1024} {
		b.Run(sizeName(size), func(b *testing.B) {
			var w shadowsocks.TCPChunkWriter
			if err := w.Init(benchCipher(b), discardConn{}); err != nil {
				b.Fatal(err)
			}

			payload := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				if _, err := w.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTCPChunkReader(b *testing.B) {
	const size = 16 * 1024

	// One long stream of chunks to read back.
	var buf bytes.Buffer
	var w shadowsocks.TCPChunkWriter
	if err := w.Init(benchCipher(b), &buf); err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, size)
	const chunks = 256
	for range chunks {
		if _, err := w.Write(payload); err != nil {
			b.Fatal(err)
		}
	}

	stream := buf.Bytes()
	out := make([]byte, size)

	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i += chunks {
		var r shadowsocks.TCPChunkReader
		if err := r.Init(benchCipher(b), bytes.NewReader(stream)); err != nil {
			b.Fatal(err)
		}

		for range chunks {
			if _, err := io.ReadFull(&r, out); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkTCPStreamCipherSeal(b *testing.B) {
	c := benchCipher(b)
	payload := make([]byte, 16*1024)
	dst := make([]byte, 0, len(payload)+64)

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := c.SealTo(dst[:0], payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPSessionSeal(b *testing.B) {
	for _, methodName := range []string{
		shadowsocks.Method2022Blake3AES128GCM,
		shadowsocks.Method2022Blake3ChaCha20Poly1305,
	} {
		b.Run(methodName, func(b *testing.B) {
			method, err := shadowsocks.ParseMethod(methodName)
			if err != nil {
				b.Fatal(err)
			}

			psk := make([]byte, method.KeySize)
			cipher, err := shadowsocks.NewUDPCipher(method, psk)
			if err != nil {
				b.Fatal(err)
			}

			session, err := cipher.NewSession(1)
			if err != nil {
				b.Fatal(err)
			}

			body := make([]byte, 1400)
			dst := make([]byte, 0, 2048)

			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			b.ResetTimer()

			for i := range b.N {
				if _, err := session.SealTo(dst[:0], uint64(i), body); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkUDPSessionOpen(b *testing.B) {
	method, psk := benchMethod(b)

	cipher, err := shadowsocks.NewUDPCipher(method, psk)
	if err != nil {
		b.Fatal(err)
	}
	session, err := cipher.NewSession(1)
	if err != nil {
		b.Fatal(err)
	}

	packet, err := session.SealTo(nil, 0, make([]byte, 1400))
	if err != nil {
		b.Fatal(err)
	}

	dst := make([]byte, 0, 2048)

	b.SetBytes(1400)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, _, _, err := session.OpenTo(dst[:0], packet); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUDPConnWriteTo measures the whole client send path: header encode,
// seal, and hand off to the socket.
func BenchmarkUDPConnWriteTo(b *testing.B) {
	method, psk := benchMethod(b)

	conn, err := shadowsocks.NewUDPConn(
		discardPacketConn{},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8388},
		method, psk, nil,
	)
	if err != nil {
		b.Fatal(err)
	}

	target := &net.UDPAddr{IP: net.IPv4(93, 184, 216, 34), Port: 443}
	payload := make([]byte, 1400)

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := conn.WriteTo(payload, target); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPHeaderEncode(b *testing.B) {
	var target shadowsocks.Addr
	target.Init(shadowsocks.AddrTypeIPv4, net.IPv4(1, 1, 1, 1).To4(), "", 53)

	var h shadowsocks.UDPClientHeader
	h.Init(shadowsocks.UDPHeaderTypeClientPacket, 1700000000, nil, target)

	dst := make([]byte, 0, 64)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := h.EncodeTo(dst[:0]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddrDecode(b *testing.B) {
	var src shadowsocks.Addr
	src.Init(shadowsocks.AddrTypeIPv4, net.IPv4(93, 184, 216, 34).To4(), "", 443)

	encoded, err := src.EncodeTo(nil)
	if err != nil {
		b.Fatal(err)
	}

	var addr shadowsocks.Addr

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := addr.Decode(encoded); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSlidingWindowFilter(b *testing.B) {
	f := shadowsocks.NewSlidingWindowFilter(0)

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		f.Add(uint64(i))
	}
}

func sizeName(n int) string {
	if n >= 1024 {
		return fmt.Sprintf("%dKiB", n/1024)
	}
	return fmt.Sprintf("%dB", n)
}

// BenchmarkUDPOpenPacketTo measures the server's receive path: peek the
// separate header to route the packet, then open the body.
func BenchmarkUDPOpenPacketTo(b *testing.B) {
	method, psk := benchMethod(b)

	cipher, err := shadowsocks.NewUDPCipher(method, psk)
	if err != nil {
		b.Fatal(err)
	}
	session, err := cipher.NewSession(1)
	if err != nil {
		b.Fatal(err)
	}

	packet, err := session.SealTo(nil, 0, make([]byte, 1400))
	if err != nil {
		b.Fatal(err)
	}

	resolve := func(uint64, uint64) (*shadowsocks.UDPSessionCipher, error) { return session, nil }
	dst := make([]byte, 0, 4096)

	b.SetBytes(1400)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := cipher.OpenPacketTo(dst[:0], packet, resolve); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPPeekSeparateHeader(b *testing.B) {
	method, psk := benchMethod(b)

	cipher, err := shadowsocks.NewUDPCipher(method, psk)
	if err != nil {
		b.Fatal(err)
	}
	session, _ := cipher.NewSession(1)
	packet, _ := session.SealTo(nil, 0, make([]byte, 64))

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, _, _, err := cipher.PeekSeparateHeader(packet); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUDPRelayRoundTrip measures a datagram's whole journey through a real
// relay: client encrypt, socket, server decrypt, forward, echo, and back. It is
// the number that says whether the crypto path is worth tuning further.
func BenchmarkUDPRelayRoundTrip(b *testing.B) {
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer echo.Close()

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := echo.WriteTo(buf[:n], from); err != nil {
				return
			}
		}
	}()

	methodName := shadowsocks.Method2022Blake3AES128GCM
	psk := make([]byte, 16)
	for i := range psk {
		psk[i] = byte(i * 7)
	}

	cfg := &shadowsocks.Config{
		Method: methodName,
		PSK:    base64.StdEncoding.EncodeToString(psk),
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer pc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go shadowsocks.ServePacket(ctx, pc, &shadowsocks.BaseUDPServerHandler{
		Config:     cfg,
		AllowRelay: true,
	})

	d := shadowsocks.NewDialer(pc.LocalAddr().String(), cfg, nil)
	conn, err := d.ListenPacket(context.Background(), nil)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	target := echo.LocalAddr().(*net.UDPAddr)
	payload := make([]byte, 1400)
	buf := make([]byte, 64*1024)

	_ = conn.SetDeadline(time.Now().Add(time.Minute))

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := conn.WriteTo(payload, target); err != nil {
			b.Fatal(err)
		}
		if _, _, err := conn.ReadFrom(buf); err != nil {
			b.Fatal(err)
		}
	}
}
