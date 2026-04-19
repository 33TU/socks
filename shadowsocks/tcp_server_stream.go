package shadowsocks

import (
	"fmt"
	"io"
	"time"
)

// TCPServerRequestStart represents the parsed client request startup on the server side.
// Deprecated: prefer ParsedTCPRequestStart.
type TCPServerRequestStart struct {
	Method        Method
	PSK           []byte
	RequestSalt   []byte
	RequestCipher *TCPStreamCipher
	FixedHeader   TCPRequestFixedHeader
	Header        TCPRequestVariableHeader
}

func (s *TCPServerRequestStart) Init(method Method, psk, requestSalt []byte) error {
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

func (s *TCPServerRequestStart) Validate() error {
	if s == nil {
		return fmt.Errorf("nil TCP server request start")
	}
	parsed := &ParsedTCPRequestStart{
		Salt:   s.RequestSalt,
		Cipher: s.RequestCipher,
		Fixed:  s.FixedHeader,
		Header: s.Header,
	}
	return parsed.Validate(s.Method)
}

func (s *TCPServerRequestStart) ReadRequestStart(src io.Reader, method Method, psk []byte) (int64, error) {
	parsed, n, err := ReadTCPRequestStart(src, method, psk)
	if err != nil {
		return n, err
	}
	s.Method = method
	s.PSK = append(s.PSK[:0], psk...)
	s.RequestSalt = parsed.Salt
	s.RequestCipher = parsed.Cipher
	s.FixedHeader = parsed.Fixed
	s.Header = parsed.Header
	return n, nil
}

// TCPServerResponseStart represents the server-side response startup state.
// Deprecated: prefer WriteTCPResponseStart.
type TCPServerResponseStart struct {
	Method         Method
	PSK            []byte
	ResponseSalt   []byte
	ResponseCipher *TCPStreamCipher
	Header         TCPResponseHeader
	InitialPayload []byte
}

func (s *TCPServerResponseStart) Init(method Method, psk, responseSalt []byte) error {
	if err := method.Validate(); err != nil {
		return err
	}
	if len(psk) != method.KeySize {
		return fmt.Errorf("invalid PSK length: got %d, want %d", len(psk), method.KeySize)
	}
	if len(responseSalt) != method.SaltSize {
		return fmt.Errorf("invalid response salt length: got %d, want %d", len(responseSalt), method.SaltSize)
	}
	cipher, err := NewTCPStreamCipherFromPSK(method, psk, responseSalt)
	if err != nil {
		return err
	}
	s.Method = method
	s.PSK = append(s.PSK[:0], psk...)
	s.ResponseSalt = append(s.ResponseSalt[:0], responseSalt...)
	s.ResponseCipher = cipher
	return nil
}

func (s *TCPServerResponseStart) Validate(requestSalt []byte) error {
	if s == nil {
		return fmt.Errorf("nil TCP server response start")
	}
	parsed := &ParsedTCPResponseStart{
		Salt:           s.ResponseSalt,
		Cipher:         s.ResponseCipher,
		Header:         s.Header,
		InitialPayload: s.InitialPayload,
	}
	return parsed.Validate(s.Method, requestSalt)
}

func (s *TCPServerResponseStart) WriteResponseStart(dst io.Writer, timestamp time.Time, requestSalt []byte, initialPayload []byte) (int64, error) {
	if s == nil {
		return 0, fmt.Errorf("nil TCP server response start")
	}
	if err := s.Method.Validate(); err != nil {
		return 0, err
	}
	if len(s.PSK) != s.Method.KeySize {
		return 0, fmt.Errorf("invalid PSK length: got %d, want %d", len(s.PSK), s.Method.KeySize)
	}
	if len(s.ResponseSalt) != s.Method.SaltSize {
		return 0, fmt.Errorf("invalid response salt length: got %d, want %d", len(s.ResponseSalt), s.Method.SaltSize)
	}
	if s.ResponseCipher == nil {
		return 0, fmt.Errorf("missing response cipher")
	}
	cipher, n, err := WriteTCPResponseStart(dst, s.Method, s.PSK, s.ResponseSalt, timestamp, requestSalt, initialPayload)
	if err == nil {
		s.ResponseCipher = cipher
		var header TCPResponseHeader
		header.Init(TCPHeaderTypeServerStream, uint64(timestamp.Unix()), requestSalt, uint16(len(initialPayload)))
		s.Header = header
		s.InitialPayload = append(s.InitialPayload[:0], initialPayload...)
	}
	return n, err
}
