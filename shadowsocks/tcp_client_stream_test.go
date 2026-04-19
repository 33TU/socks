package shadowsocks_test

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/33TU/socks/shadowsocks"
)

func newTCPClientStartTestMethod(t *testing.T) shadowsocks.Method {
	t.Helper()

	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	return method
}

func newTCPClientStartTestPSKAndSalt(method shadowsocks.Method) ([]byte, []byte) {
	psk := make([]byte, method.KeySize)
	salt := make([]byte, method.SaltSize)

	for i := range psk {
		psk[i] = byte(i + 1)
	}
	for i := range salt {
		salt[i] = byte(i + 101)
	}

	return psk, salt
}

func TestTCPClientRequestStart_Init_Validate(t *testing.T) {
	t.Parallel()

	method := newTCPClientStartTestMethod(t)
	psk, requestSalt := newTCPClientStartTestPSKAndSalt(method)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		var s shadowsocks.TCPClientRequestStart
		if err := s.Init(method, psk, requestSalt); err != nil {
			t.Fatalf("Init() error = %v", err)
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("invalid psk length", func(t *testing.T) {
		t.Parallel()

		var s shadowsocks.TCPClientRequestStart
		err := s.Init(method, psk[:len(psk)-1], requestSalt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid PSK length") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid request salt length", func(t *testing.T) {
		t.Parallel()

		var s shadowsocks.TCPClientRequestStart
		err := s.Init(method, psk, requestSalt[:len(requestSalt)-1])
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid request salt length") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("nil receiver validate", func(t *testing.T) {
		t.Parallel()

		var s *shadowsocks.TCPClientRequestStart
		err := s.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nil TCP client request start") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing request cipher", func(t *testing.T) {
		t.Parallel()

		s := &shadowsocks.TCPClientRequestStart{
			Method:      method,
			PSK:         psk,
			RequestSalt: requestSalt,
		}

		err := s.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing request cipher") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestTCPClientRequestStart_EncodedRequestStartLen(t *testing.T) {
	t.Parallel()

	method := newTCPClientStartTestMethod(t)
	psk, requestSalt := newTCPClientStartTestPSKAndSalt(method)

	var s shadowsocks.TCPClientRequestStart
	if err := s.Init(method, psk, requestSalt); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	got, err := s.EncodedRequestStartLen(123)
	if err != nil {
		t.Fatalf("EncodedRequestStartLen() error = %v", err)
	}

	want := len(requestSalt) +
		(shadowsocks.TcpRequestFixedHeaderLen + method.TagSize) +
		(123 + method.TagSize)

	if got != want {
		t.Fatalf("EncodedRequestStartLen() = %d, want %d", got, want)
	}

	_, err = s.EncodedRequestStartLen(-1)
	if err == nil {
		t.Fatal("expected error for negative variable header length")
	}
}

func TestTCPClientRequestStart_WriteRequestStart(t *testing.T) {
	t.Parallel()

	method := newTCPClientStartTestMethod(t)
	psk, requestSalt := newTCPClientStartTestPSKAndSalt(method)

	var s shadowsocks.TCPClientRequestStart
	if err := s.Init(method, psk, requestSalt); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	ts := time.Unix(1700000000, 0)
	target := shadowsocks.Addr{
		AddrType: shadowsocks.AddrTypeDomain,
		Domain:   "example.com",
		Port:     443,
	}
	padding := []byte{1, 2, 3}
	initialData := []byte("hello")

	var buf bytes.Buffer
	n, err := s.WriteRequestStart(&buf, ts, target, padding, initialData)
	if err != nil {
		t.Fatalf("WriteRequestStart() error = %v", err)
	}

	var variableHeader shadowsocks.TCPRequestVariableHeader
	variableHeader.Init(target, padding, initialData)

	wantLen, err := s.EncodedRequestStartLen(variableHeader.EncodedLen())
	if err != nil {
		t.Fatalf("EncodedRequestStartLen() error = %v", err)
	}

	if int(n) != wantLen {
		t.Fatalf("WriteRequestStart() wrote %d bytes, want %d", n, wantLen)
	}
	if buf.Len() != wantLen {
		t.Fatalf("buffer len = %d, want %d", buf.Len(), wantLen)
	}

	out := buf.Bytes()
	if !bytes.Equal(out[:len(requestSalt)], requestSalt) {
		t.Fatalf("request salt mismatch: got %v, want %v", out[:len(requestSalt)], requestSalt)
	}
}

func TestTCPClientRequestStart_WriteRequestStart_InvalidTarget(t *testing.T) {
	t.Parallel()

	method := newTCPClientStartTestMethod(t)
	psk, requestSalt := newTCPClientStartTestPSKAndSalt(method)

	var s shadowsocks.TCPClientRequestStart
	if err := s.Init(method, psk, requestSalt); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	var buf bytes.Buffer
	_, err := s.WriteRequestStart(
		&buf,
		time.Unix(1700000000, 0),
		shadowsocks.Addr{},
		nil,
		[]byte("x"),
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestTCPClientResponseStart_Validate(t *testing.T) {
	t.Parallel()

	method := newTCPClientStartTestMethod(t)
	psk, requestSalt := newTCPClientStartTestPSKAndSalt(method)
	responseSalt := make([]byte, method.SaltSize)
	for i := range responseSalt {
		responseSalt[i] = byte(i + 51)
	}

	responseCipher, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, responseSalt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK() error = %v", err)
	}

	initialPayload := []byte("hello")
	var hdr shadowsocks.TCPResponseHeader
	hdr.Init(
		shadowsocks.TCPHeaderTypeServerStream,
		1700000000,
		requestSalt,
		uint16(len(initialPayload)),
	)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		s := &shadowsocks.TCPClientResponseStart{
			ResponseSalt:   append([]byte(nil), responseSalt...),
			ResponseCipher: responseCipher,
			Header:         hdr,
			InitialPayload: append([]byte(nil), initialPayload...),
		}

		if err := s.Validate(method, requestSalt); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("nil receiver", func(t *testing.T) {
		t.Parallel()

		var s *shadowsocks.TCPClientResponseStart
		err := s.Validate(method, requestSalt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nil TCP client response start") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("bad response salt len", func(t *testing.T) {
		t.Parallel()

		s := &shadowsocks.TCPClientResponseStart{
			ResponseSalt:   responseSalt[:len(responseSalt)-1],
			ResponseCipher: responseCipher,
			Header:         hdr,
			InitialPayload: append([]byte(nil), initialPayload...),
		}

		err := s.Validate(method, requestSalt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid response salt length") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing response cipher", func(t *testing.T) {
		t.Parallel()

		s := &shadowsocks.TCPClientResponseStart{
			ResponseSalt:   responseSalt,
			Header:         hdr,
			InitialPayload: append([]byte(nil), initialPayload...),
		}

		err := s.Validate(method, requestSalt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing response cipher") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("request salt mismatch", func(t *testing.T) {
		t.Parallel()

		badRequestSalt := append([]byte(nil), requestSalt...)
		badRequestSalt[0] ^= 0xff

		s := &shadowsocks.TCPClientResponseStart{
			ResponseSalt:   responseSalt,
			ResponseCipher: responseCipher,
			Header:         hdr,
			InitialPayload: append([]byte(nil), initialPayload...),
		}

		err := s.Validate(method, badRequestSalt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "response request salt mismatch") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("initial payload length mismatch", func(t *testing.T) {
		t.Parallel()

		s := &shadowsocks.TCPClientResponseStart{
			ResponseSalt:   responseSalt,
			ResponseCipher: responseCipher,
			Header:         hdr,
			InitialPayload: nil,
		}

		err := s.Validate(method, requestSalt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid initial payload length") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestTCPClientRequestStart_ReadResponseStart(t *testing.T) {
	t.Parallel()

	method := newTCPClientStartTestMethod(t)
	psk, requestSalt := newTCPClientStartTestPSKAndSalt(method)

	var clientStart shadowsocks.TCPClientRequestStart
	if err := clientStart.Init(method, psk, requestSalt); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	responseSalt := make([]byte, method.SaltSize)
	for i := range responseSalt {
		responseSalt[i] = byte(i + 201)
	}

	responseCipher, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, responseSalt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK() error = %v", err)
	}

	initialPayload := []byte("hello")

	var hdr shadowsocks.TCPResponseHeader
	hdr.Init(
		shadowsocks.TCPHeaderTypeServerStream,
		uint64(time.Unix(1700000100, 0).Unix()),
		requestSalt,
		uint16(len(initialPayload)),
	)

	encHeader, err := responseCipher.EncodeResponseHeaderTo(nil, &hdr, nil)
	if err != nil {
		t.Fatalf("EncodeResponseHeaderTo() error = %v", err)
	}

	encPayload, err := responseCipher.EncodeChunkPayloadTo(nil, initialPayload)
	if err != nil {
		t.Fatalf("EncodeChunkPayloadTo() error = %v", err)
	}

	var wire bytes.Buffer
	wire.Write(responseSalt)
	wire.Write(encHeader)
	wire.Write(encPayload)

	resp, n, err := clientStart.ReadResponseStart(&wire)
	if err != nil {
		t.Fatalf("ReadResponseStart() error = %v", err)
	}

	wantN := int64(len(responseSalt) + len(encHeader) + len(encPayload))
	if n != wantN {
		t.Fatalf("ReadResponseStart() read %d bytes, want %d", n, wantN)
	}

	if !bytes.Equal(resp.ResponseSalt, responseSalt) {
		t.Fatalf("ResponseSalt = %v, want %v", resp.ResponseSalt, responseSalt)
	}
	if resp.ResponseCipher == nil {
		t.Fatal("ResponseCipher is nil")
	}
	if resp.Header.Type != hdr.Type || resp.Header.Timestamp != hdr.Timestamp || resp.Header.Length != hdr.Length {
		t.Fatalf("Header = %+v, want %+v", resp.Header, hdr)
	}
	if !bytes.Equal(resp.Header.RequestSalt, requestSalt) {
		t.Fatalf("Header.RequestSalt = %v, want %v", resp.Header.RequestSalt, requestSalt)
	}
	if !bytes.Equal(resp.InitialPayload, initialPayload) {
		t.Fatalf("InitialPayload = %q, want %q", resp.InitialPayload, initialPayload)
	}
}

func TestTCPClientRequestStart_ReadResponseStart_ShortRead(t *testing.T) {
	t.Parallel()

	method := newTCPClientStartTestMethod(t)
	psk, requestSalt := newTCPClientStartTestPSKAndSalt(method)

	var clientStart shadowsocks.TCPClientRequestStart
	if err := clientStart.Init(method, psk, requestSalt); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	short := bytes.NewReader(make([]byte, method.SaltSize-1))

	_, n, err := clientStart.ReadResponseStart(short)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if n != int64(method.SaltSize-1) {
		t.Fatalf("bytes read = %d, want %d", n, method.SaltSize-1)
	}
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTCPClientRequestStart_ReadResponseStart_RequestSaltMismatch(t *testing.T) {
	t.Parallel()

	method := newTCPClientStartTestMethod(t)
	psk, requestSalt := newTCPClientStartTestPSKAndSalt(method)

	var clientStart shadowsocks.TCPClientRequestStart
	if err := clientStart.Init(method, psk, requestSalt); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	responseSalt := make([]byte, method.SaltSize)
	for i := range responseSalt {
		responseSalt[i] = byte(i + 201)
	}

	responseCipher, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, responseSalt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK() error = %v", err)
	}

	badRequestSalt := append([]byte(nil), requestSalt...)
	badRequestSalt[0] ^= 0xff

	initialPayload := []byte("hello")

	var hdr shadowsocks.TCPResponseHeader
	hdr.Init(
		shadowsocks.TCPHeaderTypeServerStream,
		uint64(time.Unix(1700000100, 0).Unix()),
		badRequestSalt,
		uint16(len(initialPayload)),
	)

	encHeader, err := responseCipher.EncodeResponseHeaderTo(nil, &hdr, nil)
	if err != nil {
		t.Fatalf("EncodeResponseHeaderTo() error = %v", err)
	}

	encPayload, err := responseCipher.EncodeChunkPayloadTo(nil, initialPayload)
	if err != nil {
		t.Fatalf("EncodeChunkPayloadTo() error = %v", err)
	}

	var wire bytes.Buffer
	wire.Write(responseSalt)
	wire.Write(encHeader)
	wire.Write(encPayload)

	_, _, err = clientStart.ReadResponseStart(&wire)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "response request salt mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}
