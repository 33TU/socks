package shadowsocks_test

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/33TU/socks/shadowsocks"
)

func newTCPServerStartTestMethod(t *testing.T) shadowsocks.Method {
	t.Helper()

	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	return method
}

func newTCPServerStartTestPSKAndSalt(method shadowsocks.Method) ([]byte, []byte) {
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

func TestTCPServerRequestStart_Init_Validate(t *testing.T) {
	t.Parallel()

	method := newTCPServerStartTestMethod(t)
	psk, requestSalt := newTCPServerStartTestPSKAndSalt(method)

	target := shadowsocks.Addr{
		AddrType: shadowsocks.AddrTypeDomain,
		Domain:   "example.com",
		Port:     443,
	}

	var fixed shadowsocks.TCPRequestFixedHeader
	var variable shadowsocks.TCPRequestVariableHeader
	variable.Init(target, []byte{1, 2, 3}, []byte("hello"))
	fixed.Init(
		shadowsocks.TCPHeaderTypeClientStream,
		1700000000,
		uint16(variable.EncodedLen()),
	)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		var s shadowsocks.TCPServerRequestStart
		if err := s.Init(method, psk, requestSalt); err != nil {
			t.Fatalf("Init() error = %v", err)
		}

		s.FixedHeader = fixed
		s.Header = variable

		if err := s.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("invalid psk length", func(t *testing.T) {
		t.Parallel()

		var s shadowsocks.TCPServerRequestStart
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

		var s shadowsocks.TCPServerRequestStart
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

		var s *shadowsocks.TCPServerRequestStart
		err := s.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nil TCP server request start") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing request cipher", func(t *testing.T) {
		t.Parallel()

		s := &shadowsocks.TCPServerRequestStart{
			Method:      method,
			PSK:         psk,
			RequestSalt: requestSalt,
			FixedHeader: fixed,
			Header:      variable,
		}

		err := s.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing request cipher") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("variable header length mismatch", func(t *testing.T) {
		t.Parallel()

		var s shadowsocks.TCPServerRequestStart
		if err := s.Init(method, psk, requestSalt); err != nil {
			t.Fatalf("Init() error = %v", err)
		}

		s.FixedHeader.Init(
			shadowsocks.TCPHeaderTypeClientStream,
			1700000000,
			uint16(variable.EncodedLen()+1),
		)
		s.Header = variable

		err := s.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "request variable header length mismatch") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestTCPServerRequestStart_ReadRequestStart(t *testing.T) {
	t.Parallel()

	method := newTCPServerStartTestMethod(t)
	psk, requestSalt := newTCPServerStartTestPSKAndSalt(method)

	clientRequestCipher, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, requestSalt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK() error = %v", err)
	}

	target := shadowsocks.Addr{
		AddrType: shadowsocks.AddrTypeDomain,
		Domain:   "example.com",
		Port:     443,
	}

	var variableHeader shadowsocks.TCPRequestVariableHeader
	variableHeader.Init(target, []byte{1, 2, 3}, []byte("hello"))

	var fixedHeader shadowsocks.TCPRequestFixedHeader
	fixedHeader.Init(
		shadowsocks.TCPHeaderTypeClientStream,
		uint64(time.Unix(1700000000, 0).Unix()),
		uint16(variableHeader.EncodedLen()),
	)

	encFixed, err := clientRequestCipher.EncodeRequestFixedHeaderTo(nil, &fixedHeader, nil)
	if err != nil {
		t.Fatalf("EncodeRequestFixedHeaderTo() error = %v", err)
	}

	encVariable, err := clientRequestCipher.EncodeRequestVariableHeaderTo(nil, &variableHeader, nil)
	if err != nil {
		t.Fatalf("EncodeRequestVariableHeaderTo() error = %v", err)
	}

	var wire bytes.Buffer
	wire.Write(requestSalt)
	wire.Write(encFixed)
	wire.Write(encVariable)

	var s shadowsocks.TCPServerRequestStart
	n, err := s.ReadRequestStart(&wire, method, psk)
	if err != nil {
		t.Fatalf("ReadRequestStart() error = %v", err)
	}

	wantN := int64(len(requestSalt) + len(encFixed) + len(encVariable))
	if n != wantN {
		t.Fatalf("ReadRequestStart() read %d bytes, want %d", n, wantN)
	}

	if !bytes.Equal(s.RequestSalt, requestSalt) {
		t.Fatalf("RequestSalt = %v, want %v", s.RequestSalt, requestSalt)
	}
	if s.RequestCipher == nil {
		t.Fatal("RequestCipher is nil")
	}

	if s.FixedHeader.Type != fixedHeader.Type ||
		s.FixedHeader.Timestamp != fixedHeader.Timestamp ||
		s.FixedHeader.Length != fixedHeader.Length {
		t.Fatalf("FixedHeader = %+v, want %+v", s.FixedHeader, fixedHeader)
	}

	if s.Header.Target.AddrType != variableHeader.Target.AddrType {
		t.Fatalf("Header.Target.AddrType = %v, want %v", s.Header.Target.AddrType, variableHeader.Target.AddrType)
	}
	if s.Header.Target.Domain != variableHeader.Target.Domain {
		t.Fatalf("Header.Target.Domain = %q, want %q", s.Header.Target.Domain, variableHeader.Target.Domain)
	}
	if s.Header.Target.Port != variableHeader.Target.Port {
		t.Fatalf("Header.Target.Port = %d, want %d", s.Header.Target.Port, variableHeader.Target.Port)
	}
	if s.Header.PaddingLen != variableHeader.PaddingLen {
		t.Fatalf("Header.PaddingLen = %d, want %d", s.Header.PaddingLen, variableHeader.PaddingLen)
	}
	if !bytes.Equal(s.Header.Padding, variableHeader.Padding) {
		t.Fatalf("Header.Padding = %v, want %v", s.Header.Padding, variableHeader.Padding)
	}
	if !bytes.Equal(s.Header.InitialData, variableHeader.InitialData) {
		t.Fatalf("Header.InitialData = %v, want %v", s.Header.InitialData, variableHeader.InitialData)
	}
}

func TestTCPServerRequestStart_ReadRequestStart_ShortRead(t *testing.T) {
	t.Parallel()

	method := newTCPServerStartTestMethod(t)
	psk, _ := newTCPServerStartTestPSKAndSalt(method)

	short := bytes.NewReader(make([]byte, method.SaltSize-1))

	var s shadowsocks.TCPServerRequestStart
	n, err := s.ReadRequestStart(short, method, psk)
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

func TestTCPServerRequestStart_ReadRequestStart_InvalidPSK(t *testing.T) {
	t.Parallel()

	method := newTCPServerStartTestMethod(t)
	psk, requestSalt := newTCPServerStartTestPSKAndSalt(method)

	var wire bytes.Buffer
	wire.Write(requestSalt)

	var s shadowsocks.TCPServerRequestStart
	_, err := s.ReadRequestStart(&wire, method, psk[:len(psk)-1])
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid PSK length") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTCPServerResponseStart_Init_Validate(t *testing.T) {
	t.Parallel()

	method := newTCPServerStartTestMethod(t)
	psk, responseSalt := newTCPServerStartTestPSKAndSalt(method)
	requestSalt := make([]byte, method.SaltSize)
	for i := range requestSalt {
		requestSalt[i] = byte(i + 51)
	}

	responseCipher, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, responseSalt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK() error = %v", err)
	}

	initialPayload := []byte("pong")

	var hdr shadowsocks.TCPResponseHeader
	hdr.Init(
		shadowsocks.TCPHeaderTypeServerStream,
		1700000000,
		requestSalt,
		uint16(len(initialPayload)),
	)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		var s shadowsocks.TCPServerResponseStart
		if err := s.Init(method, psk, responseSalt); err != nil {
			t.Fatalf("Init() error = %v", err)
		}
		s.Header = hdr
		s.InitialPayload = append([]byte(nil), initialPayload...)

		if err := s.Validate(requestSalt); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("invalid psk length", func(t *testing.T) {
		t.Parallel()

		var s shadowsocks.TCPServerResponseStart
		err := s.Init(method, psk[:len(psk)-1], responseSalt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid PSK length") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid response salt length", func(t *testing.T) {
		t.Parallel()

		var s shadowsocks.TCPServerResponseStart
		err := s.Init(method, psk, responseSalt[:len(responseSalt)-1])
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid response salt length") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("nil receiver validate", func(t *testing.T) {
		t.Parallel()

		var s *shadowsocks.TCPServerResponseStart
		err := s.Validate(requestSalt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nil TCP server response start") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing response cipher", func(t *testing.T) {
		t.Parallel()

		s := &shadowsocks.TCPServerResponseStart{
			Method:         method,
			PSK:            psk,
			ResponseSalt:   responseSalt,
			Header:         hdr,
			InitialPayload: append([]byte(nil), initialPayload...),
		}

		err := s.Validate(requestSalt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing response cipher") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("request salt mismatch", func(t *testing.T) {
		t.Parallel()

		s := &shadowsocks.TCPServerResponseStart{
			Method:         method,
			PSK:            psk,
			ResponseSalt:   responseSalt,
			ResponseCipher: responseCipher,
			Header:         hdr,
			InitialPayload: append([]byte(nil), initialPayload...),
		}

		badRequestSalt := append([]byte(nil), requestSalt...)
		badRequestSalt[0] ^= 0xff

		err := s.Validate(badRequestSalt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "response request salt mismatch") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("initial payload length mismatch", func(t *testing.T) {
		t.Parallel()

		s := &shadowsocks.TCPServerResponseStart{
			Method:         method,
			PSK:            psk,
			ResponseSalt:   responseSalt,
			ResponseCipher: responseCipher,
			Header:         hdr,
			InitialPayload: nil,
		}

		err := s.Validate(requestSalt)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid initial payload length") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestTCPServerResponseStart_WriteResponseStart(t *testing.T) {
	t.Parallel()

	method := newTCPServerStartTestMethod(t)
	psk, responseSalt := newTCPServerStartTestPSKAndSalt(method)
	requestSalt := make([]byte, method.SaltSize)
	for i := range requestSalt {
		requestSalt[i] = byte(i + 51)
	}

	var s shadowsocks.TCPServerResponseStart
	if err := s.Init(method, psk, responseSalt); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	ts := time.Unix(1700000100, 0)
	initialPayload := []byte("pong")

	var buf bytes.Buffer
	n, err := s.WriteResponseStart(&buf, ts, requestSalt, initialPayload)
	if err != nil {
		t.Fatalf("WriteResponseStart() error = %v", err)
	}

	headerPlainLen := 1 + 8 + len(requestSalt) + 2
	wantLen := len(responseSalt) +
		(headerPlainLen + method.TagSize) +
		(len(initialPayload) + method.TagSize)

	if int(n) != wantLen {
		t.Fatalf("WriteResponseStart() wrote %d bytes, want %d", n, wantLen)
	}
	if buf.Len() != wantLen {
		t.Fatalf("buffer len = %d, want %d", buf.Len(), wantLen)
	}

	out := buf.Bytes()
	if !bytes.Equal(out[:len(responseSalt)], responseSalt) {
		t.Fatalf("response salt mismatch: got %v, want %v", out[:len(responseSalt)], responseSalt)
	}

	if s.Header.Type != shadowsocks.TCPHeaderTypeServerStream {
		t.Fatalf("Header.Type = %v, want %v", s.Header.Type, shadowsocks.TCPHeaderTypeServerStream)
	}
	if s.Header.Timestamp != uint64(ts.Unix()) {
		t.Fatalf("Header.Timestamp = %d, want %d", s.Header.Timestamp, uint64(ts.Unix()))
	}
	if !bytes.Equal(s.Header.RequestSalt, requestSalt) {
		t.Fatalf("Header.RequestSalt = %v, want %v", s.Header.RequestSalt, requestSalt)
	}
	if s.Header.Length != uint16(len(initialPayload)) {
		t.Fatalf("Header.Length = %d, want %d", s.Header.Length, len(initialPayload))
	}
	if !bytes.Equal(s.InitialPayload, initialPayload) {
		t.Fatalf("InitialPayload = %q, want %q", s.InitialPayload, initialPayload)
	}
}

func TestTCPServerResponseStart_WriteResponseStart_InvalidRequestSalt(t *testing.T) {
	t.Parallel()

	method := newTCPServerStartTestMethod(t)
	psk, responseSalt := newTCPServerStartTestPSKAndSalt(method)

	var s shadowsocks.TCPServerResponseStart
	if err := s.Init(method, psk, responseSalt); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	var buf bytes.Buffer
	_, err := s.WriteResponseStart(&buf, time.Unix(1700000100, 0), responseSalt[:len(responseSalt)-1], nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid request salt length") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTCPServerResponseStart_WriteResponseStart_NilReceiver(t *testing.T) {
	t.Parallel()

	method := newTCPServerStartTestMethod(t)
	_, requestSalt := newTCPServerStartTestPSKAndSalt(method)

	var s *shadowsocks.TCPServerResponseStart
	var buf bytes.Buffer

	_, err := s.WriteResponseStart(&buf, time.Unix(1700000100, 0), requestSalt, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "nil TCP server response start") {
		t.Fatalf("unexpected error: %v", err)
	}
}
