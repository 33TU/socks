package shadowsocks

import (
	"fmt"
	"io"
	"time"
)

// TCPClientRequestStart represents the client-side Shadowsocks 2022 TCP startup state.
// Deprecated: prefer WriteTCPRequestStart and ReadTCPResponseStart.
type TCPClientRequestStart struct {
	Method        Method
	PSK           []byte
	RequestSalt   []byte
	RequestCipher *TCPStreamCipher
}

func (s *TCPClientRequestStart) Init(method Method, psk, requestSalt []byte) error {
	if err := method.Validate(); err != nil {
		return err
	}
	if len(psk) != method.KeySize {
		return fmt.Errorf("invalid PSK length: got %d, want %d", len(psk), method.KeySize)
	}
	if len(requestSalt) != method.SaltSize {
		return fmt.Errorf("invalid request salt length: got %d, want %d", len(requestSalt), method.SaltSize)
	}
	cipher, err := NewTCPStreamCipherFromPSK(method, psk, requestSalt)
	if err != nil {
		return err
	}
	s.Method = method
	s.PSK = append(s.PSK[:0], psk...)
	s.RequestSalt = append(s.RequestSalt[:0], requestSalt...)
	s.RequestCipher = cipher
	return nil
}

func (s *TCPClientRequestStart) Validate() error {
	if s == nil {
		return fmt.Errorf("nil TCP client request start")
	}
	if err := s.Method.Validate(); err != nil {
		return err
	}
	if len(s.PSK) != s.Method.KeySize {
		return fmt.Errorf("invalid PSK length: got %d, want %d", len(s.PSK), s.Method.KeySize)
	}
	if len(s.RequestSalt) != s.Method.SaltSize {
		return fmt.Errorf("invalid request salt length: got %d, want %d", len(s.RequestSalt), s.Method.SaltSize)
	}
	if s.RequestCipher == nil {
		return fmt.Errorf("missing request cipher")
	}
	return s.RequestCipher.Validate()
}

func (s *TCPClientRequestStart) EncodedRequestStartLen(variableHeaderLen int) (int, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}
	return EncodedTCPRequestStartLen(s.Method, s.RequestSalt, variableHeaderLen)
}

func (s *TCPClientRequestStart) WriteRequestStart(dst io.Writer, timestamp time.Time, target Addr, padding []byte, initialData []byte) (int64, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}
	cipher, n, err := WriteTCPRequestStart(dst, s.Method, s.PSK, s.RequestSalt, timestamp, target, padding, initialData)
	if err == nil {
		s.RequestCipher = cipher
	}
	return n, err
}

// TCPClientResponseStart represents the parsed server response startup.
// Deprecated: prefer ParsedTCPResponseStart.
type TCPClientResponseStart struct {
	ResponseSalt   []byte
	ResponseCipher *TCPStreamCipher
	Header         TCPResponseHeader
	InitialPayload []byte
}

func (s *TCPClientResponseStart) Validate(method Method, requestSalt []byte) error {
	if s == nil {
		return fmt.Errorf("nil TCP client response start")
	}
	parsed := &ParsedTCPResponseStart{
		Salt:           s.ResponseSalt,
		Cipher:         s.ResponseCipher,
		Header:         s.Header,
		InitialPayload: s.InitialPayload,
	}
	return parsed.Validate(method, requestSalt)
}

func (s *TCPClientRequestStart) ReadResponseStart(src io.Reader) (*TCPClientResponseStart, int64, error) {
	if err := s.Validate(); err != nil {
		return nil, 0, err
	}
	parsed, n, err := ReadTCPResponseStart(src, s.Method, s.PSK, s.RequestSalt)
	if err != nil {
		return nil, n, err
	}
	return &TCPClientResponseStart{
		ResponseSalt:   parsed.Salt,
		ResponseCipher: parsed.Cipher,
		Header:         parsed.Header,
		InitialPayload: parsed.InitialPayload,
	}, n, nil
}
