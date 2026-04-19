package shadowsocks

import (
	"bytes"
	"fmt"
	"io"
	"time"

	ibuf "github.com/33TU/socks/internal"
)

const tcpServerResponseStartStackBufSize = 256

// TCPServerRequestStart represents the parsed client request startup on the server side.
type TCPServerRequestStart struct {
	Method        Method
	PSK           []byte
	RequestSalt   []byte
	RequestCipher *TCPStreamCipher
	FixedHeader   TCPRequestFixedHeader
	Header        TCPRequestVariableHeader
}

// Init initializes the server request-start state from method, PSK, and request salt.
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

// Validate checks whether the parsed server request-start state is internally valid.
func (s *TCPServerRequestStart) Validate() error {
	if s == nil {
		return fmt.Errorf("nil TCP server request start")
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
	if err := s.FixedHeader.Validate(); err != nil {
		return err
	}
	if err := s.Header.Validate(); err != nil {
		return err
	}
	if int(s.FixedHeader.Length) != s.Header.EncodedLen() {
		return fmt.Errorf("request variable header length mismatch: got %d, want %d", s.FixedHeader.Length, s.Header.EncodedLen())
	}

	return nil
}

// ReadRequestStart reads and decrypts the full client request startup:
//
//	request salt || encrypted request fixed header || encrypted request variable header
func (s *TCPServerRequestStart) ReadRequestStart(
	src io.Reader,
	method Method,
	psk []byte,
) (int64, error) {
	var total int64

	if err := method.Validate(); err != nil {
		return 0, err
	}
	if len(psk) != method.KeySize {
		return 0, fmt.Errorf("invalid PSK length: got %d, want %d", len(psk), method.KeySize)
	}

	requestSaltLen := method.SaltSize
	requestSaltBuf := ibuf.GetBytes(requestSaltLen)
	defer ibuf.PutBytes(requestSaltBuf)

	n, err := io.ReadFull(src, requestSaltBuf)
	total += int64(n)
	if err != nil {
		return total, err
	}

	if err := s.Init(method, psk, requestSaltBuf); err != nil {
		return total, err
	}

	encFixedLen := TcpRequestFixedHeaderLen + method.TagSize
	encFixed := ibuf.GetBytes(encFixedLen)
	defer ibuf.PutBytes(encFixed)

	n, err = io.ReadFull(src, encFixed)
	total += int64(n)
	if err != nil {
		return total, err
	}

	fixedPlainScratch := ibuf.GetBytes(TcpRequestFixedHeaderLen)
	defer ibuf.PutBytes(fixedPlainScratch)

	fixedHeader, err := s.RequestCipher.DecodeRequestFixedHeader(encFixed, fixedPlainScratch[:0])
	if err != nil {
		return total, err
	}
	s.FixedHeader = fixedHeader

	encVariableLen := int(s.FixedHeader.Length) + method.TagSize
	encVariable := ibuf.GetBytes(encVariableLen)
	defer ibuf.PutBytes(encVariable)

	n, err = io.ReadFull(src, encVariable)
	total += int64(n)
	if err != nil {
		return total, err
	}

	variablePlainScratch := ibuf.GetBytes(int(s.FixedHeader.Length))
	defer ibuf.PutBytes(variablePlainScratch)

	variableHeader, err := s.RequestCipher.DecodeRequestVariableHeader(encVariable, variablePlainScratch[:0])
	if err != nil {
		return total, err
	}
	s.Header = variableHeader

	if err := s.Validate(); err != nil {
		return total, err
	}

	s.RequestSalt = append([]byte(nil), requestSaltBuf...)

	return total, nil
}

// TCPServerResponseStart represents the server-side response startup state.
type TCPServerResponseStart struct {
	Method         Method
	PSK            []byte
	ResponseSalt   []byte
	ResponseCipher *TCPStreamCipher
	Header         TCPResponseHeader
	InitialPayload []byte
}

// Init initializes the server response-start state from method, PSK, and response salt.
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

	responseCipher, err := NewTCPStreamCipherFromPSK(method, psk, responseSalt)
	if err != nil {
		return err
	}

	s.Method = method
	s.PSK = psk
	s.ResponseSalt = responseSalt
	s.ResponseCipher = responseCipher

	return nil
}

// Validate checks whether the server response-start state is internally valid.
func (s *TCPServerResponseStart) Validate(requestSalt []byte) error {
	if s == nil {
		return fmt.Errorf("nil TCP server response start")
	}
	if err := s.Method.Validate(); err != nil {
		return err
	}
	if len(s.PSK) != s.Method.KeySize {
		return fmt.Errorf("invalid PSK length: got %d, want %d", len(s.PSK), s.Method.KeySize)
	}
	if len(s.ResponseSalt) != s.Method.SaltSize {
		return fmt.Errorf("invalid response salt length: got %d, want %d", len(s.ResponseSalt), s.Method.SaltSize)
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
	if !bytes.Equal(s.Header.RequestSalt, requestSalt) {
		return fmt.Errorf("response request salt mismatch")
	}
	if int(s.Header.Length) != len(s.InitialPayload) {
		return fmt.Errorf("invalid initial payload length: got %d, want %d", len(s.InitialPayload), s.Header.Length)
	}

	return nil
}

// WriteResponseStart writes the full server response startup:
//
//	response salt || encrypted response header || encrypted first response payload
func (s *TCPServerResponseStart) WriteResponseStart(
	dst io.Writer,
	timestamp time.Time,
	requestSalt []byte,
	initialPayload []byte,
) (int64, error) {
	if s == nil {
		return 0, fmt.Errorf("nil TCP server response start")
	}
	if err := s.Method.Validate(); err != nil {
		return 0, err
	}
	if len(requestSalt) != s.Method.SaltSize {
		return 0, fmt.Errorf("invalid request salt length: got %d, want %d", len(requestSalt), s.Method.SaltSize)
	}
	if len(s.ResponseSalt) != s.Method.SaltSize {
		return 0, fmt.Errorf("invalid response salt length: got %d, want %d", len(s.ResponseSalt), s.Method.SaltSize)
	}
	if s.ResponseCipher == nil {
		return 0, fmt.Errorf("missing response cipher")
	}
	if err := s.ResponseCipher.Validate(); err != nil {
		return 0, err
	}

	var header TCPResponseHeader
	header.Init(
		TCPHeaderTypeServerStream,
		uint64(timestamp.Unix()),
		requestSalt,
		uint16(len(initialPayload)),
	)
	if err := header.Validate(); err != nil {
		return 0, err
	}
	s.Header = header
	s.InitialPayload = append(s.InitialPayload[:0], initialPayload...)

	headerPlainScratch := ibuf.GetBytes(s.Header.EncodedLen())
	defer ibuf.PutBytes(headerPlainScratch)

	var stackBuf [tcpServerResponseStartStackBufSize]byte
	out := stackBuf[:0]

	out = append(out, s.ResponseSalt...)

	var err error
	out, err = s.ResponseCipher.EncodeResponseHeaderTo(out, &s.Header, headerPlainScratch[:0])
	if err != nil {
		return 0, err
	}

	out, err = s.ResponseCipher.EncodeChunkPayloadTo(out, s.InitialPayload)
	if err != nil {
		return 0, err
	}

	n, err := dst.Write(out)
	return int64(n), err
}
