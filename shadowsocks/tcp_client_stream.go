package shadowsocks

import (
	"bytes"
	"fmt"
	"io"
	"time"

	ibuf "github.com/33TU/socks/internal"
)

const tcpClientRequestStartStackBufSize = 1024

// TCPClientRequestStart represents the client-side Shadowsocks 2022 TCP startup state.
type TCPClientRequestStart struct {
	Method        Method
	PSK           []byte
	RequestSalt   []byte
	RequestCipher *TCPStreamCipher
}

// Init initializes the client request-start state from method, PSK, and request salt.
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

	requestCipher, err := NewTCPStreamCipherFromPSK(method, psk, requestSalt)
	if err != nil {
		return err
	}

	s.Method = method
	s.PSK = psk
	s.RequestSalt = requestSalt
	s.RequestCipher = requestCipher

	return nil
}

// Validate checks whether the client request-start state is internally valid.
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
	if err := s.RequestCipher.Validate(); err != nil {
		return err
	}

	return nil
}

// EncodedRequestStartLen returns the total encoded request-start length for the
// given plaintext variable header length.
func (s *TCPClientRequestStart) EncodedRequestStartLen(variableHeaderLen int) (int, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}
	if variableHeaderLen < 0 {
		return 0, fmt.Errorf("invalid variable header length: %d", variableHeaderLen)
	}

	return len(s.RequestSalt) +
		(TcpRequestFixedHeaderLen + s.Method.TagSize) +
		(variableHeaderLen + s.Method.TagSize), nil
}

// WriteRequestStart writes a full client request start:
//
//	request salt || encrypted request fixed header || encrypted request variable header
//
// The request fixed header Length field is set to the plaintext encoded variable
// header length.
func (s *TCPClientRequestStart) WriteRequestStart(
	dst io.Writer,
	timestamp time.Time,
	target Addr,
	padding []byte,
	initialData []byte,
) (int64, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}

	var variableHeader TCPRequestVariableHeader
	variableHeader.Init(target, padding, initialData)
	if err := variableHeader.Validate(); err != nil {
		return 0, err
	}

	var fixedHeader TCPRequestFixedHeader
	fixedHeader.Init(
		TCPHeaderTypeClientStream,
		uint64(timestamp.Unix()),
		uint16(variableHeader.EncodedLen()),
	)

	scratchLen := TcpRequestFixedHeaderLen
	if variableHeader.EncodedLen() > scratchLen {
		scratchLen = variableHeader.EncodedLen()
	}

	plainScratch := ibuf.GetBytes(scratchLen)
	defer ibuf.PutBytes(plainScratch)

	var stackBuf [tcpClientRequestStartStackBufSize]byte
	out := stackBuf[:0]

	out = append(out, s.RequestSalt...)

	var err error
	out, err = s.RequestCipher.EncodeRequestFixedHeaderTo(out, &fixedHeader, plainScratch[:0])
	if err != nil {
		return 0, err
	}

	out, err = s.RequestCipher.EncodeRequestVariableHeaderTo(out, &variableHeader, plainScratch[:0])
	if err != nil {
		return 0, err
	}

	n, err := dst.Write(out)
	return int64(n), err
}

// TCPClientResponseStart represents the parsed server response startup.
type TCPClientResponseStart struct {
	ResponseSalt   []byte
	ResponseCipher *TCPStreamCipher
	Header         TCPResponseHeader
}

// Validate checks whether the parsed client response-start state is internally valid.
func (s *TCPClientResponseStart) Validate(method Method, requestSalt []byte) error {
	if s == nil {
		return fmt.Errorf("nil TCP client response start")
	}
	if err := method.Validate(); err != nil {
		return err
	}
	if len(s.ResponseSalt) != method.SaltSize {
		return fmt.Errorf("invalid response salt length: got %d, want %d", len(s.ResponseSalt), method.SaltSize)
	}
	if s.ResponseCipher == nil {
		return fmt.Errorf("missing response cipher")
	}
	if err := s.ResponseCipher.Validate(); err != nil {
		return err
	}
	if err := s.Header.Validate(); err != nil {
		return err
	}
	if len(s.Header.RequestSalt) != len(requestSalt) {
		return fmt.Errorf("invalid echoed request salt length: got %d, want %d", len(s.Header.RequestSalt), len(requestSalt))
	}
	if !bytes.Equal(s.Header.RequestSalt, requestSalt) {
		return fmt.Errorf("response request salt mismatch")
	}

	return nil
}

// ReadResponseStart reads and decrypts the server response startup:
//
//	response salt || encrypted response header
func (s *TCPClientRequestStart) ReadResponseStart(
	src io.Reader,
) (*TCPClientResponseStart, int64, error) {
	if err := s.Validate(); err != nil {
		return nil, 0, err
	}

	var total int64

	responseSaltLen := s.Method.SaltSize
	responseSaltBuf := ibuf.GetBytes(responseSaltLen)
	defer ibuf.PutBytes(responseSaltBuf)

	n, err := io.ReadFull(src, responseSaltBuf)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	responseCipher, err := NewTCPStreamCipherFromPSK(s.Method, s.PSK, responseSaltBuf)
	if err != nil {
		return nil, total, err
	}

	encHeaderLen := TcpResponseFixedBaseLen + s.Method.SaltSize + s.Method.TagSize
	encHeader := ibuf.GetBytes(encHeaderLen)
	defer ibuf.PutBytes(encHeader)

	n, err = io.ReadFull(src, encHeader)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	plainScratch := ibuf.GetBytes(TcpResponseFixedBaseLen + s.Method.SaltSize)
	defer ibuf.PutBytes(plainScratch)

	header, err := responseCipher.DecodeResponseHeader(encHeader, plainScratch[:0])
	if err != nil {
		return nil, total, err
	}

	resp := &TCPClientResponseStart{
		ResponseSalt:   append([]byte(nil), responseSaltBuf...),
		ResponseCipher: responseCipher,
		Header:         header,
	}
	if err := resp.Validate(s.Method, s.RequestSalt); err != nil {
		return nil, total, err
	}

	return resp, total, nil
}
