package shadowsocks

import (
	"bytes"
	"fmt"
	"io"
	"time"

	ibuf "github.com/33TU/socks/internal"
)

const (
	tcpRequestStartStackBufSize  = 1024
	tcpResponseStartStackBufSize = 256
)

// ParsedTCPRequestStart is the parsed startup state for a TCP request stream.
type ParsedTCPRequestStart struct {
	Salt   []byte
	Cipher *TCPStreamCipher
	Fixed  TCPRequestFixedHeader
	Header TCPRequestVariableHeader
}

func (s *ParsedTCPRequestStart) Validate(method Method) error {
	if s == nil {
		return fmt.Errorf("nil parsed TCP request start")
	}
	if err := method.Validate(); err != nil {
		return err
	}
	if len(s.Salt) != method.SaltSize {
		return fmt.Errorf("invalid request salt length: got %d, want %d", len(s.Salt), method.SaltSize)
	}
	if s.Cipher == nil {
		return fmt.Errorf("missing request cipher")
	}
	if err := s.Cipher.Validate(); err != nil {
		return err
	}
	if err := s.Fixed.Validate(); err != nil {
		return err
	}
	if err := s.Header.Validate(); err != nil {
		return err
	}
	if int(s.Fixed.Length) != s.Header.EncodedLen() {
		return fmt.Errorf("request variable header length mismatch: got %d, want %d", s.Fixed.Length, s.Header.EncodedLen())
	}
	return nil
}

// ParsedTCPResponseStart is the parsed startup state for a TCP response stream.
type ParsedTCPResponseStart struct {
	Salt           []byte
	Cipher         *TCPStreamCipher
	Header         TCPResponseHeader
	InitialPayload []byte
}

func (s *ParsedTCPResponseStart) Validate(method Method, expectedRequestSalt []byte) error {
	if s == nil {
		return fmt.Errorf("nil parsed TCP response start")
	}
	if err := method.Validate(); err != nil {
		return err
	}
	if len(s.Salt) != method.SaltSize {
		return fmt.Errorf("invalid response salt length: got %d, want %d", len(s.Salt), method.SaltSize)
	}
	if s.Cipher == nil {
		return fmt.Errorf("missing response cipher")
	}
	if err := s.Cipher.Validate(); err != nil {
		return err
	}
	if err := s.Header.Validate(); err != nil {
		return err
	}
	if len(s.Header.RequestSalt) != len(expectedRequestSalt) {
		return fmt.Errorf("invalid echoed request salt length: got %d, want %d", len(s.Header.RequestSalt), len(expectedRequestSalt))
	}
	if !bytes.Equal(s.Header.RequestSalt, expectedRequestSalt) {
		return fmt.Errorf("response request salt mismatch")
	}
	if int(s.Header.Length) != len(s.InitialPayload) {
		return fmt.Errorf("invalid initial payload length: got %d, want %d", len(s.InitialPayload), s.Header.Length)
	}
	return nil
}

func EncodedTCPRequestStartLen(method Method, requestSalt []byte, variableHeaderLen int) (int, error) {
	if err := method.Validate(); err != nil {
		return 0, err
	}
	if len(requestSalt) != method.SaltSize {
		return 0, fmt.Errorf("invalid request salt length: got %d, want %d", len(requestSalt), method.SaltSize)
	}
	if variableHeaderLen < 0 {
		return 0, fmt.Errorf("invalid variable header length: %d", variableHeaderLen)
	}
	return len(requestSalt) + (TcpRequestFixedHeaderLen + method.TagSize) + (variableHeaderLen + method.TagSize), nil
}

// WriteTCPRequestStart writes request salt, encrypted fixed header, and encrypted variable header.
func WriteTCPRequestStart(dst io.Writer, method Method, psk, requestSalt []byte, timestamp time.Time, target Addr, padding, initialData []byte) (*TCPStreamCipher, int64, error) {
	if err := method.Validate(); err != nil {
		return nil, 0, err
	}
	requestCipher, err := NewTCPStreamCipherFromPSK(method, psk, requestSalt)
	if err != nil {
		return nil, 0, err
	}

	var variableHeader TCPRequestVariableHeader
	variableHeader.Init(target, padding, initialData)
	if err := variableHeader.Validate(); err != nil {
		return nil, 0, err
	}

	var fixedHeader TCPRequestFixedHeader
	fixedHeader.Init(TCPHeaderTypeClientStream, uint64(timestamp.Unix()), uint16(variableHeader.EncodedLen()))

	scratchLen := TcpRequestFixedHeaderLen
	if variableHeader.EncodedLen() > scratchLen {
		scratchLen = variableHeader.EncodedLen()
	}
	plainScratch := ibuf.GetBytes(scratchLen)
	defer ibuf.PutBytes(plainScratch)

	var stackBuf [tcpRequestStartStackBufSize]byte
	out := stackBuf[:0]
	out = append(out, requestSalt...)

	out, err = requestCipher.EncodeRequestFixedHeaderTo(out, &fixedHeader, plainScratch[:0])
	if err != nil {
		return nil, 0, err
	}
	out, err = requestCipher.EncodeRequestVariableHeaderTo(out, &variableHeader, plainScratch[:0])
	if err != nil {
		return nil, 0, err
	}

	n, err := dst.Write(out)
	return requestCipher, int64(n), err
}

// ReadTCPRequestStart reads and decrypts a full client request startup.
func ReadTCPRequestStart(src io.Reader, method Method, psk []byte) (*ParsedTCPRequestStart, int64, error) {
	var total int64
	if err := method.Validate(); err != nil {
		return nil, 0, err
	}
	if len(psk) != method.KeySize {
		return nil, 0, fmt.Errorf("invalid PSK length: got %d, want %d", len(psk), method.KeySize)
	}

	requestSaltBuf := ibuf.GetBytes(method.SaltSize)
	defer ibuf.PutBytes(requestSaltBuf)
	n, err := io.ReadFull(src, requestSaltBuf)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	requestCipher, err := NewTCPStreamCipherFromPSK(method, psk, requestSaltBuf)
	if err != nil {
		return nil, total, err
	}

	encFixed := ibuf.GetBytes(TcpRequestFixedHeaderLen + method.TagSize)
	defer ibuf.PutBytes(encFixed)
	n, err = io.ReadFull(src, encFixed)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	fixedPlainScratch := ibuf.GetBytes(TcpRequestFixedHeaderLen)
	defer ibuf.PutBytes(fixedPlainScratch)
	fixedHeader, err := requestCipher.DecodeRequestFixedHeader(encFixed, fixedPlainScratch[:0])
	if err != nil {
		return nil, total, err
	}

	encVariable := ibuf.GetBytes(int(fixedHeader.Length) + method.TagSize)
	defer ibuf.PutBytes(encVariable)
	n, err = io.ReadFull(src, encVariable)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	variablePlainScratch := ibuf.GetBytes(int(fixedHeader.Length))
	defer ibuf.PutBytes(variablePlainScratch)
	variableHeader, err := requestCipher.DecodeRequestVariableHeader(encVariable, variablePlainScratch[:0])
	if err != nil {
		return nil, total, err
	}

	parsed := &ParsedTCPRequestStart{
		Salt:   append([]byte(nil), requestSaltBuf...),
		Cipher: requestCipher,
		Fixed:  fixedHeader,
		Header: variableHeader,
	}
	if err := parsed.Validate(method); err != nil {
		return nil, total, err
	}
	return parsed, total, nil
}

// WriteTCPResponseStart writes response salt, encrypted response header, and first encrypted payload.
func WriteTCPResponseStart(dst io.Writer, method Method, psk, responseSalt []byte, timestamp time.Time, requestSalt, initialPayload []byte) (*TCPStreamCipher, int64, error) {
	if err := method.Validate(); err != nil {
		return nil, 0, err
	}
	if len(requestSalt) != method.SaltSize {
		return nil, 0, fmt.Errorf("invalid request salt length: got %d, want %d", len(requestSalt), method.SaltSize)
	}
	responseCipher, err := NewTCPStreamCipherFromPSK(method, psk, responseSalt)
	if err != nil {
		return nil, 0, err
	}

	var header TCPResponseHeader
	header.Init(TCPHeaderTypeServerStream, uint64(timestamp.Unix()), requestSalt, uint16(len(initialPayload)))
	if err := header.Validate(); err != nil {
		return nil, 0, err
	}

	headerPlainScratch := ibuf.GetBytes(header.EncodedLen())
	defer ibuf.PutBytes(headerPlainScratch)

	var stackBuf [tcpResponseStartStackBufSize]byte
	out := stackBuf[:0]
	out = append(out, responseSalt...)
	out, err = responseCipher.EncodeResponseHeaderTo(out, &header, headerPlainScratch[:0])
	if err != nil {
		return nil, 0, err
	}
	out, err = responseCipher.EncodeChunkPayloadTo(out, initialPayload)
	if err != nil {
		return nil, 0, err
	}

	n, err := dst.Write(out)
	return responseCipher, int64(n), err
}

// ReadTCPResponseStart reads and decrypts a full server response startup.
func ReadTCPResponseStart(src io.Reader, method Method, psk, expectedRequestSalt []byte) (*ParsedTCPResponseStart, int64, error) {
	var total int64
	if err := method.Validate(); err != nil {
		return nil, 0, err
	}
	if len(psk) != method.KeySize {
		return nil, 0, fmt.Errorf("invalid PSK length: got %d, want %d", len(psk), method.KeySize)
	}
	if len(expectedRequestSalt) != method.SaltSize {
		return nil, 0, fmt.Errorf("invalid request salt length: got %d, want %d", len(expectedRequestSalt), method.SaltSize)
	}

	responseSaltBuf := ibuf.GetBytes(method.SaltSize)
	defer ibuf.PutBytes(responseSaltBuf)
	n, err := io.ReadFull(src, responseSaltBuf)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	responseCipher, err := NewTCPStreamCipherFromPSK(method, psk, responseSaltBuf)
	if err != nil {
		return nil, total, err
	}

	encHeaderLen := 1 + 8 + method.SaltSize + 2 + method.TagSize
	encHeader := ibuf.GetBytes(encHeaderLen)
	defer ibuf.PutBytes(encHeader)
	n, err = io.ReadFull(src, encHeader)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	plainHeaderScratch := ibuf.GetBytes(1 + 8 + method.SaltSize + 2)
	defer ibuf.PutBytes(plainHeaderScratch)
	header, err := responseCipher.DecodeResponseHeader(encHeader, plainHeaderScratch[:0])
	if err != nil {
		return nil, total, err
	}

	encPayloadBuf := ibuf.GetBytes(responseCipher.EncryptedPayloadLength(int(header.Length)))
	defer ibuf.PutBytes(encPayloadBuf)
	n, err = io.ReadFull(src, encPayloadBuf)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	payloadScratch := ibuf.GetBytes(int(header.Length))
	defer ibuf.PutBytes(payloadScratch)
	initialPayload, err := responseCipher.DecodeChunkPayloadTo(payloadScratch[:0], encPayloadBuf)
	if err != nil {
		return nil, total, err
	}

	parsed := &ParsedTCPResponseStart{
		Salt:           append([]byte(nil), responseSaltBuf...),
		Cipher:         responseCipher,
		Header:         header,
		InitialPayload: append([]byte(nil), initialPayload...),
	}
	if err := parsed.Validate(method, expectedRequestSalt); err != nil {
		return nil, total, err
	}
	return parsed, total, nil
}
