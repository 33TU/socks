package shadowsocks_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/33TU/socks/shadowsocks"
)

// Wire format test vectors for the Shadowsocks 2022 Edition.
//
// Every vector below was produced with, or validated against, the reference
// implementation (github.com/database64128/shadowsocks-go): the "Ours" vectors
// are bytes this package emits that the reference parsed correctly, and the
// "Reference" vectors are bytes the reference emitted for this package to
// parse. Freezing them keeps the check without depending on that project.
//
// The wire format is fixed by the specification, so these bytes must never
// change. A diff here means a compatibility regression, not a stale vector.
//
// Only the AES methods are covered, because the reference implements no others.
// 2022-blake3-chacha20-poly1305 seals with a random nonce per packet and so has
// no fixed encoding to pin; it is covered by the round-trip tests instead.
//
// To re-derive them, build a throwaway module that requires both this package
// and github.com/database64128/shadowsocks-go, encode with one side and parse
// with the other, and print the bytes. That dependency is deliberately not part
// of this module.
const (
	// ---- 2022-blake3-aes-128-gcm ----
	// request stream start written here; the reference parsed it.
	tcpRequestStartOursAES128 = "77777777777777777777777777777777760d4bf19bab26d37bc9bf2331aa8b0bc4c114e4efa1e39a2a78e0bac612dc47a8b367edb9f9a8967b4894cbc738ee9a6b29a19dd6ed12c83825c8795360a48c3e1ad20e6e3ab80f4f6a7e8993b1f339b087cec28f46"
	// request stream start built by the reference encoders.
	tcpRequestStartReferenceAES128 = "3131313131313131313131313131313181fbd9d0fe12b873e5a88770310f148471ff9954360a72f4de618dcb0bf93411a500947ab45e7adda7199fb4530ceca088d91a42474a3956cd39eba349f27992040d176559b6fcfabed9cfd35b944f3fc078b58781a9"
	// response stream start written here; the reference parsed it.
	tcpResponseStartOursAES128 = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0461b2ae2d678d710509bc5ac7700c07ac7db5dde0d26c1ff8e92721a6447d0318915362d60cbb5ecadc10e56a57cea87b99358c8aeed1ba6b9068c58b0a6f07f9157d90d628d43b1cd9aa661950b"
	// UDP client packet written here; the reference unpacked it.
	udpClientPacketOursAES128 = "4976f8daf13653be0e535c8edd1d74ea4fdd38ff795ce8bfb1af2da59e740168eb9200f785c974ab215aa79f12b83aeca7c73ba596e11795b6c15c6435c2bc348e164298cd633447ef9ce5a3"
	// UDP server packet built by the reference encoders.
	udpServerPacketReferenceAES128 = "574269a93d43d58c0cc006b8f480b281c9c4d2319c47636a5bf0f7e6f4b69c010cfcd346024653da10ef0a9ceca2d65b3930f8ffbc633e7dcd7068807271509459370023e788bca2816be09db4de59"

	// ---- 2022-blake3-aes-256-gcm ----
	// request stream start written here; the reference parsed it.
	tcpRequestStartOursAES256 = "7777777777777777777777777777777777777777777777777777777777777777e6a717eb9df68e5f6be6d45ca5a96c16b1fb9d720660b225aa67b136c9f3726659993b18482f433d3a4ef42fcd593e63579c378e1b6d0ea71557764c1c7f53a33ac861f2db65d026cec6a46aa20c5d2133ee4173b0d5"
	// request stream start built by the reference encoders.
	tcpRequestStartReferenceAES256 = "3131313131313131313131313131313131313131313131313131313131313131cfb45d50c94298f3762a302e31798f1882816a1403fc0392406ee13f85b30ee23c7e08b1a8cf354902566796c121870ad6e6ba54f2a35139af97d1d245ec3a807b7156d29196ea1b8eb418dc2d54dcba00757860094d"
	// response stream start written here; the reference parsed it.
	tcpResponseStartOursAES256 = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0d9cb09fe3b457ad2fd9ee1d0caef36c20212d00f1ca1dad92a23c7bbb9a6865bda9801b50b1930a6066814695eb201092ce79c390b5ead29f559f793e784f06fe2771f137d253d9e18b0f1e56c9136c1d6adad67e85d2227b2fbb0b0140b"
	// UDP client packet written here; the reference unpacked it.
	udpClientPacketOursAES256 = "11845f0ab4daacb98eb22035687e2606af658305da1dfed9c76a9888d8dd67fec380e721366fc8e70ab10e26de017fe9c68eee1c28b3e0312b64495820b4f5938fcac6cb9c086ef6c1fa69ad"
	// UDP server packet built by the reference encoders.
	udpServerPacketReferenceAES256 = "edfc054930d2c40699355a4ffb92cb65f149df20274d60617faded24094a045b3921f31b00fc5bb1784c5e1cdc86c6454f90ea8c37b2cc96b73d3e7c8d72bae8fc7e1a142e1643767d42c0559de0c3"
)

// Inputs shared by every vector. Changing any of them invalidates all of them.
var vectorTime = time.Unix(1700000000, 0)

// vectorPSK returns the PSK the vectors were generated with.
func vectorPSK(method shadowsocks.Method) []byte {
	psk := make([]byte, method.KeySize)
	for i := range psk {
		psk[i] = byte(i * 3)
	}
	return psk
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid vector: %v", err)
	}
	return b
}

// wireVector groups the vectors for one method.
type wireVector struct {
	name                     string
	method                   string
	tcpRequestStartOurs      string
	tcpRequestStartReference string
	tcpResponseStartOurs     string
	udpClientPacketOurs      string
	udpServerPacketReference string
}

func wireVectors() []wireVector {
	return []wireVector{
		{
			name:                     "aes-128-gcm",
			method:                   shadowsocks.Method2022Blake3AES128GCM,
			tcpRequestStartOurs:      tcpRequestStartOursAES128,
			tcpRequestStartReference: tcpRequestStartReferenceAES128,
			tcpResponseStartOurs:     tcpResponseStartOursAES128,
			udpClientPacketOurs:      udpClientPacketOursAES128,
			udpServerPacketReference: udpServerPacketReferenceAES128,
		},
		{
			name:                     "aes-256-gcm",
			method:                   shadowsocks.Method2022Blake3AES256GCM,
			tcpRequestStartOurs:      tcpRequestStartOursAES256,
			tcpRequestStartReference: tcpRequestStartReferenceAES256,
			tcpResponseStartOurs:     tcpResponseStartOursAES256,
			udpClientPacketOurs:      udpClientPacketOursAES256,
			udpServerPacketReference: udpServerPacketReferenceAES256,
		},
	}
}

// TestWireVector_TCPRequestStart checks that a request stream start still
// encodes to the exact bytes the reference implementation accepted.
func TestWireVector_TCPRequestStart(t *testing.T) {
	for _, v := range wireVectors() {
		t.Run(v.name, func(t *testing.T) {
			method, err := shadowsocks.ParseMethod(v.method)
			if err != nil {
				t.Fatalf("ParseMethod() error = %v", err)
			}

			var target shadowsocks.Addr
			target.Init(shadowsocks.AddrTypeDomain, nil, "example.com", 443)

			var buf bytes.Buffer
			if _, _, err := shadowsocks.WriteTCPRequestStart(
				&buf,
				shadowsocks.ClientKeys{Method: method, PSK: vectorPSK(method)},
				bytes.Repeat([]byte{0x77}, method.SaltSize),
				vectorTime,
				target,
				bytes.Repeat([]byte{0x00}, 8),
				[]byte("GET / HTTP/1.1\r\n\r\n"),
			); err != nil {
				t.Fatalf("WriteTCPRequestStart() error = %v", err)
			}

			if got := hex.EncodeToString(buf.Bytes()); got != v.tcpRequestStartOurs {
				t.Errorf("request stream start changed\n got: %s\nwant: %s", got, v.tcpRequestStartOurs)
			}
		})
	}
}

// TestWireVector_TCPRequestStartFromReference checks that a request stream start
// produced by the reference encoders is still parsed correctly here.
func TestWireVector_TCPRequestStartFromReference(t *testing.T) {
	for _, v := range wireVectors() {
		t.Run(v.name, func(t *testing.T) {
			method, err := shadowsocks.ParseMethod(v.method)
			if err != nil {
				t.Fatalf("ParseMethod() error = %v", err)
			}

			wire := bytes.NewReader(mustHex(t, v.tcpRequestStartReference))

			parsed, _, err := shadowsocks.ReadTCPRequestStart(wire, &shadowsocks.ServerCipher{Method: method, PSK: vectorPSK(method)}, vectorTime)
			if err != nil {
				t.Fatalf("ReadTCPRequestStart() error = %v", err)
			}

			if parsed.Header.Target.Domain != "example.org" || parsed.Header.Target.Port != 8080 {
				t.Errorf("target = %s, want example.org:8080", parsed.Header.Target.Addr())
			}
			if !bytes.Equal(parsed.Header.InitialData, []byte("hello")) {
				t.Errorf("initial payload = %q, want %q", parsed.Header.InitialData, "hello")
			}
			if parsed.Header.PaddingLen != 21 {
				t.Errorf("padding length = %d, want 21", parsed.Header.PaddingLen)
			}
			if parsed.Fixed.Timestamp != uint64(vectorTime.Unix()) {
				t.Errorf("timestamp = %d, want %d", parsed.Fixed.Timestamp, vectorTime.Unix())
			}
		})
	}
}

// TestWireVector_TCPResponseStart checks the response stream start in both
// directions: it must encode to the frozen bytes and parse back from them.
func TestWireVector_TCPResponseStart(t *testing.T) {
	for _, v := range wireVectors() {
		t.Run(v.name, func(t *testing.T) {
			method, err := shadowsocks.ParseMethod(v.method)
			if err != nil {
				t.Fatalf("ParseMethod() error = %v", err)
			}

			psk := vectorPSK(method)
			requestSalt := bytes.Repeat([]byte{0x0f}, method.SaltSize)
			payload := []byte("HTTP/1.1 200 OK\r\n\r\n")

			var buf bytes.Buffer
			if _, _, err := shadowsocks.WriteTCPResponseStart(
				&buf,
				method,
				psk,
				bytes.Repeat([]byte{0xf0}, method.SaltSize),
				vectorTime,
				requestSalt,
				payload,
			); err != nil {
				t.Fatalf("WriteTCPResponseStart() error = %v", err)
			}

			if got := hex.EncodeToString(buf.Bytes()); got != v.tcpResponseStartOurs {
				t.Errorf("response stream start changed\n got: %s\nwant: %s", got, v.tcpResponseStartOurs)
			}

			wire := bytes.NewReader(mustHex(t, v.tcpResponseStartOurs))

			parsed, _, err := shadowsocks.ReadTCPResponseStart(wire, method, psk, requestSalt, vectorTime)
			if err != nil {
				t.Fatalf("ReadTCPResponseStart() error = %v", err)
			}
			if !bytes.Equal(parsed.InitialPayload, payload) {
				t.Errorf("initial payload = %q, want %q", parsed.InitialPayload, payload)
			}
		})
	}
}

// TestWireVector_UDPClientPacket checks that a client packet still encodes to
// the exact bytes the reference implementation unpacked.
func TestWireVector_UDPClientPacket(t *testing.T) {
	for _, v := range wireVectors() {
		t.Run(v.name, func(t *testing.T) {
			method, err := shadowsocks.ParseMethod(v.method)
			if err != nil {
				t.Fatalf("ParseMethod() error = %v", err)
			}

			cipher, err := shadowsocks.NewUDPCipher(method, vectorPSK(method))
			if err != nil {
				t.Fatalf("NewUDPCipher() error = %v", err)
			}

			session, err := cipher.NewSession(0x1122334455667788)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}

			var target shadowsocks.Addr
			target.Init(shadowsocks.AddrTypeIPv4, net.IPv4(1, 1, 1, 1).To4(), "", 53)

			var header shadowsocks.UDPClientHeader
			header.Init(
				shadowsocks.UDPHeaderTypeClientPacket,
				uint64(vectorTime.Unix()),
				bytes.Repeat([]byte{0x00}, 11),
				target,
			)

			body, err := header.EncodeTo(nil)
			if err != nil {
				t.Fatalf("EncodeTo() error = %v", err)
			}
			body = append(body, []byte("dns query bytes")...)

			packet, err := session.SealTo(nil, 9, body)
			if err != nil {
				t.Fatalf("SealTo() error = %v", err)
			}

			if got := hex.EncodeToString(packet); got != v.udpClientPacketOurs {
				t.Errorf("UDP client packet changed\n got: %s\nwant: %s", got, v.udpClientPacketOurs)
			}
		})
	}
}

// TestWireVector_UDPServerPacketFromReference checks that a server packet
// produced by the reference encoders is still unpacked correctly here.
func TestWireVector_UDPServerPacketFromReference(t *testing.T) {
	const (
		serverSessionID = uint64(0xaabbccddeeff0011)
		clientSessionID = uint64(0x0102030405060708)
		packetID        = uint64(3)
	)

	for _, v := range wireVectors() {
		t.Run(v.name, func(t *testing.T) {
			method, err := shadowsocks.ParseMethod(v.method)
			if err != nil {
				t.Fatalf("ParseMethod() error = %v", err)
			}

			cipher, err := shadowsocks.NewUDPCipher(method, vectorPSK(method))
			if err != nil {
				t.Fatalf("NewUDPCipher() error = %v", err)
			}

			packet := mustHex(t, v.udpServerPacketReference)

			gotSession, gotPacket, ok, err := cipher.PeekSeparateHeader(packet)
			if err != nil || !ok {
				t.Fatalf("PeekSeparateHeader() = (ok %v, err %v)", ok, err)
			}
			if gotSession != serverSessionID || gotPacket != packetID {
				t.Errorf("peeked (%#x, %d), want (%#x, %d)", gotSession, gotPacket, serverSessionID, packetID)
			}

			session, err := cipher.NewSession(serverSessionID)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}

			_, _, body, err := session.OpenTo(nil, packet)
			if err != nil {
				t.Fatalf("OpenTo() error = %v", err)
			}

			var header shadowsocks.UDPServerHeader
			n, err := header.Decode(body)
			if err != nil {
				t.Fatalf("UDPServerHeader.Decode() error = %v", err)
			}
			if header.ClientSessionID != clientSessionID {
				t.Errorf("client session ID = %#x, want %#x", header.ClientSessionID, clientSessionID)
			}
			if header.Source.Addr() != "93.184.216.34:443" {
				t.Errorf("source = %s, want 93.184.216.34:443", header.Source.Addr())
			}
			if header.Timestamp != uint64(vectorTime.Unix()) {
				t.Errorf("timestamp = %d, want %d", header.Timestamp, vectorTime.Unix())
			}
			if !bytes.Equal(body[n:], []byte("response bytes")) {
				t.Errorf("payload = %q, want %q", body[n:], "response bytes")
			}
		})
	}
}

// Identity headers for a two-layer chain, checked byte for byte against the
// reference implementation before being frozen here. Inputs: aes-128-gcm,
// iPSK0/iPSK1/uPSK seeded 1/2/3, salt of 0x42 repeated.
const identityHeadersAES128 = "424c76a704df58731af64062f3d154a668095017ec636dee6e0ca5f976ae3587"

// TestWireVector_TCPIdentityHeaders checks that identity headers still encode
// exactly as the reference implementation produces them.
func TestWireVector_TCPIdentityHeaders(t *testing.T) {
	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	key := func(seed byte) []byte {
		b := make([]byte, method.KeySize)
		for i := range b {
			b[i] = seed + byte(i)
		}
		return b
	}

	headers, err := shadowsocks.EncodeTCPIdentityHeadersTo(
		nil, method,
		[][]byte{key(1), key(2)},
		key(3),
		bytes.Repeat([]byte{0x42}, method.SaltSize),
	)
	if err != nil {
		t.Fatalf("EncodeTCPIdentityHeadersTo() error = %v", err)
	}

	if got := hex.EncodeToString(headers); got != identityHeadersAES128 {
		t.Errorf("identity headers changed\n got: %s\nwant: %s", got, identityHeadersAES128)
	}
}

// A UDP identity header, checked against the reference implementation before
// being frozen. Inputs: aes-128-gcm, iPSK/uPSK seeded 1/3, session 0x1122334455667788,
// packet 7. Unlike TCP's, it is keyed by the identity PSK itself and masked
// with the separate header.
const udpIdentityHeaderAES128 = "5c0278d741070277403036269c8b03f3"

func TestWireVector_UDPIdentityHeader(t *testing.T) {
	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	key := func(seed byte) []byte {
		b := make([]byte, method.KeySize)
		for i := range b {
			b[i] = seed + byte(i)
		}
		return b
	}

	var separate [shadowsocks.UDPSeparateHeaderLen]byte
	binary.BigEndian.PutUint64(separate[:shadowsocks.UDPSessionIDLen], 0x1122334455667788)
	binary.BigEndian.PutUint64(separate[shadowsocks.UDPSessionIDLen:], 7)

	header, err := shadowsocks.EncodeUDPIdentityHeadersTo(nil, [][]byte{key(1)}, key(3), separate[:])
	if err != nil {
		t.Fatalf("EncodeUDPIdentityHeadersTo() error = %v", err)
	}

	if got := hex.EncodeToString(header); got != udpIdentityHeaderAES128 {
		t.Errorf("UDP identity header changed\n got: %s\nwant: %s", got, udpIdentityHeaderAES128)
	}
}
