package shadowsocks_test

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func newUDPTestCipher(t *testing.T, methodName string) (*shadowsocks.UDPCipher, shadowsocks.Method, []byte) {
	t.Helper()

	method, err := shadowsocks.ParseMethod(methodName)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	psk := make([]byte, method.KeySize)
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	cipher, err := shadowsocks.NewUDPCipher(method, psk)
	if err != nil {
		t.Fatalf("NewUDPCipher() error = %v", err)
	}

	return cipher, method, psk
}

func udpTestMethods() []string {
	return []string{
		shadowsocks.Method2022Blake3AES128GCM,
		shadowsocks.Method2022Blake3AES256GCM,
		shadowsocks.Method2022Blake3ChaCha20Poly1305,
	}
}

func TestUDPSessionCipher_RoundTrip(t *testing.T) {
	for _, methodName := range udpTestMethods() {
		t.Run(methodName, func(t *testing.T) {
			cipher, _, _ := newUDPTestCipher(t, methodName)

			const sessionID = 0x0123456789abcdef
			session, err := cipher.NewSession(sessionID)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}

			body := []byte("the quick brown fox jumps over the lazy dog")

			for _, packetID := range []uint64{0, 1, 42, 1 << 40} {
				packet, err := session.SealTo(nil, packetID, body)
				if err != nil {
					t.Fatalf("SealTo() error = %v", err)
				}

				if bytes.Contains(packet, body) {
					t.Fatal("packet contains plaintext body")
				}

				gotSession, gotPacket, gotBody, err := session.OpenTo(nil, packet)
				if err != nil {
					t.Fatalf("OpenTo() error = %v", err)
				}
				if gotSession != sessionID {
					t.Errorf("session ID = %d, want %d", gotSession, sessionID)
				}
				if gotPacket != packetID {
					t.Errorf("packet ID = %d, want %d", gotPacket, packetID)
				}
				if !bytes.Equal(gotBody, body) {
					t.Errorf("body = %q, want %q", gotBody, body)
				}
			}
		})
	}
}

func TestUDPSessionCipher_RejectsTamperedPacket(t *testing.T) {
	for _, methodName := range udpTestMethods() {
		t.Run(methodName, func(t *testing.T) {
			cipher, _, _ := newUDPTestCipher(t, methodName)

			session, err := cipher.NewSession(7)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}

			packet, err := session.SealTo(nil, 3, []byte("payload"))
			if err != nil {
				t.Fatalf("SealTo() error = %v", err)
			}

			for _, i := range []int{0, len(packet) / 2, len(packet) - 1} {
				tampered := append([]byte(nil), packet...)
				tampered[i] ^= 0xff

				if _, _, _, err := session.OpenTo(nil, tampered); err == nil {
					t.Errorf("OpenTo() with byte %d flipped succeeded, want failure", i)
				}
			}
		})
	}
}

func TestUDPSessionCipher_RejectsWrongPSK(t *testing.T) {
	for _, methodName := range udpTestMethods() {
		t.Run(methodName, func(t *testing.T) {
			cipher, method, psk := newUDPTestCipher(t, methodName)

			other := append([]byte(nil), psk...)
			other[0] ^= 0xff
			otherCipher, err := shadowsocks.NewUDPCipher(method, other)
			if err != nil {
				t.Fatalf("NewUDPCipher() error = %v", err)
			}

			session, err := cipher.NewSession(9)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}
			otherSession, err := otherCipher.NewSession(9)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}

			packet, err := session.SealTo(nil, 1, []byte("payload"))
			if err != nil {
				t.Fatalf("SealTo() error = %v", err)
			}

			if _, _, _, err := otherSession.OpenTo(nil, packet); err == nil {
				t.Error("OpenTo() with wrong PSK succeeded, want failure")
			}
		})
	}
}

// TestUDPCipher_AESSeparateHeaderLayout checks the on-the-wire layout of the AES
// construction: the first 16 bytes are the session and packet ID encrypted with
// a plain AES block keyed by the PSK.
func TestUDPCipher_AESSeparateHeaderLayout(t *testing.T) {
	for _, methodName := range []string{
		shadowsocks.Method2022Blake3AES128GCM,
		shadowsocks.Method2022Blake3AES256GCM,
	} {
		t.Run(methodName, func(t *testing.T) {
			cipher, _, psk := newUDPTestCipher(t, methodName)

			if !cipher.HasSeparateHeader() {
				t.Fatal("HasSeparateHeader() = false, want true")
			}

			const (
				sessionID = uint64(0xdeadbeefcafebabe)
				packetID  = uint64(0x1122334455667788)
			)

			session, err := cipher.NewSession(sessionID)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}

			body := []byte("body")
			packet, err := session.SealTo(nil, packetID, body)
			if err != nil {
				t.Fatalf("SealTo() error = %v", err)
			}

			wantLen := shadowsocks.UDPSeparateHeaderLen + len(body) + shadowsocks.AeadTagSize
			if len(packet) != wantLen {
				t.Errorf("packet length = %d, want %d", len(packet), wantLen)
			}

			block, err := aes.NewCipher(psk)
			if err != nil {
				t.Fatalf("aes.NewCipher() error = %v", err)
			}

			var separate [shadowsocks.UDPSeparateHeaderLen]byte
			block.Decrypt(separate[:], packet[:shadowsocks.UDPSeparateHeaderLen])

			if got := binary.BigEndian.Uint64(separate[:8]); got != sessionID {
				t.Errorf("session ID = %#x, want %#x", got, sessionID)
			}
			if got := binary.BigEndian.Uint64(separate[8:]); got != packetID {
				t.Errorf("packet ID = %#x, want %#x", got, packetID)
			}

			// The same IDs must be recoverable without authenticating the packet.
			gotSession, gotPacket, ok, err := cipher.PeekSeparateHeader(packet)
			if err != nil {
				t.Fatalf("PeekSeparateHeader() error = %v", err)
			}
			if !ok {
				t.Fatal("PeekSeparateHeader() ok = false, want true")
			}
			if gotSession != sessionID || gotPacket != packetID {
				t.Errorf("peeked (%#x, %#x), want (%#x, %#x)", gotSession, gotPacket, sessionID, packetID)
			}
		})
	}
}

// TestUDPCipher_ChaChaLayout checks the on-the-wire layout of the ChaCha
// construction: a random 24-byte nonce followed by the encrypted body, with the
// session and packet ID inside the body rather than in a separate header.
func TestUDPCipher_ChaChaLayout(t *testing.T) {
	cipher, _, _ := newUDPTestCipher(t, shadowsocks.Method2022Blake3ChaCha20Poly1305)

	if cipher.HasSeparateHeader() {
		t.Fatal("HasSeparateHeader() = true, want false")
	}

	if _, _, ok, err := cipher.PeekSeparateHeader(make([]byte, 64)); err != nil || ok {
		t.Errorf("PeekSeparateHeader() = (ok %v, err %v), want (false, nil)", ok, err)
	}

	session, err := cipher.NewSession(1234)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	body := []byte("body")
	packet, err := session.SealTo(nil, 5, body)
	if err != nil {
		t.Fatalf("SealTo() error = %v", err)
	}

	wantLen := shadowsocks.UDPNonceLen + shadowsocks.UDPSeparateHeaderLen + len(body) + shadowsocks.AeadTagSize
	if len(packet) != wantLen {
		t.Errorf("packet length = %d, want %d", len(packet), wantLen)
	}

	// Each packet must use a fresh nonce.
	other, err := session.SealTo(nil, 6, body)
	if err != nil {
		t.Fatalf("SealTo() error = %v", err)
	}
	if bytes.Equal(packet[:shadowsocks.UDPNonceLen], other[:shadowsocks.UDPNonceLen]) {
		t.Error("nonce reused across packets")
	}
}

func TestUDPCipher_OpenPacketToRoutesBySession(t *testing.T) {
	for _, methodName := range udpTestMethods() {
		t.Run(methodName, func(t *testing.T) {
			cipher, _, _ := newUDPTestCipher(t, methodName)

			const sessionID = uint64(99)
			session, err := cipher.NewSession(sessionID)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}

			packet, err := session.SealTo(nil, 11, []byte("routed"))
			if err != nil {
				t.Fatalf("SealTo() error = %v", err)
			}

			var resolvedSession, resolvedPacket uint64
			unpacked, err := cipher.OpenPacketTo(nil, packet, func(sid, pid uint64) (*shadowsocks.UDPSessionCipher, error) {
				resolvedSession, resolvedPacket = sid, pid
				return session, nil
			})
			if err != nil {
				t.Fatalf("OpenPacketTo() error = %v", err)
			}

			if resolvedSession != sessionID {
				t.Errorf("resolver got session %d, want %d", resolvedSession, sessionID)
			}
			if resolvedPacket != 11 {
				t.Errorf("resolver got packet %d, want %d", resolvedPacket, 11)
			}
			if unpacked.SessionID != sessionID || unpacked.PacketID != 11 {
				t.Errorf("unpacked = (%d, %d), want (%d, %d)", unpacked.SessionID, unpacked.PacketID, sessionID, 11)
			}
			if !bytes.Equal(unpacked.Body, []byte("routed")) {
				t.Errorf("body = %q, want %q", unpacked.Body, "routed")
			}
		})
	}
}

func TestUDPCipher_RejectsShortPackets(t *testing.T) {
	for _, methodName := range udpTestMethods() {
		t.Run(methodName, func(t *testing.T) {
			cipher, _, _ := newUDPTestCipher(t, methodName)

			session, err := cipher.NewSession(1)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}

			for _, size := range []int{0, 1, 15, 16, 24, 31} {
				if _, _, _, err := session.OpenTo(nil, make([]byte, size)); err == nil {
					t.Errorf("OpenTo() with %d bytes succeeded, want failure", size)
				}
			}
		})
	}
}
