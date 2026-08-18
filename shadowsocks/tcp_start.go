package shadowsocks

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/33TU/socks/internal"
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

	// User is the user an identity header named, empty on a single-user server.
	User User
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

// ClientKeys are the keys a client authenticates with.
//
// PSK protects the session. IdentityPSKs, when present, are the keys naming the
// path to it: each gets an identity header naming the key after it, so a relay
// or multi-user server can route the request without holding PSK itself.
type ClientKeys struct {
	Method       Method
	IdentityPSKs [][]byte
	PSK          []byte
}

// Validate checks whether the key chain is internally valid.
func (k ClientKeys) Validate() error {
	if err := k.Method.Validate(); err != nil {
		return err
	}
	if len(k.PSK) != k.Method.KeySize {
		return fmt.Errorf("invalid PSK length: got %d, want %d", len(k.PSK), k.Method.KeySize)
	}

	for i, identityPSK := range k.IdentityPSKs {
		if len(identityPSK) != k.Method.KeySize {
			return fmt.Errorf("invalid identity PSK %d length: got %d, want %d", i, len(identityPSK), k.Method.KeySize)
		}
	}

	return nil
}

// WriteTCPRequestStart writes request salt, any identity headers, the encrypted
// fixed header, and the encrypted variable header, in a single write.
func WriteTCPRequestStart(dst io.Writer, keys ClientKeys, requestSalt []byte, timestamp time.Time, target Addr, padding, initialData []byte) (*TCPStreamCipher, int64, error) {
	if err := keys.Validate(); err != nil {
		return nil, 0, err
	}

	method, psk := keys.Method, keys.PSK

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

	scratchLen := TCPRequestFixedHeaderLen
	if variableHeader.EncodedLen() > scratchLen {
		scratchLen = variableHeader.EncodedLen()
	}
	plainScratch := internal.GetBuffer(scratchLen)
	defer internal.PutBuffer(plainScratch)

	var stackBuf [tcpRequestStartStackBufSize]byte
	out := stackBuf[:0]
	out = append(out, requestSalt...)

	// Identity headers sit between the salt and the AEAD chunks.
	out, err = EncodeTCPIdentityHeadersTo(out, method, keys.IdentityPSKs, psk, requestSalt)
	if err != nil {
		return nil, 0, err
	}

	out, err = requestCipher.EncodeRequestFixedHeaderTo(out, &fixedHeader, plainScratch.B[:0])
	if err != nil {
		return nil, 0, err
	}
	out, err = requestCipher.EncodeRequestVariableHeaderTo(out, &variableHeader, plainScratch.B[:0])
	if err != nil {
		return nil, 0, err
	}

	n, err := dst.Write(out)
	return requestCipher, int64(n), err
}

// ReadTCPRequestStart reads and decrypts a full client request startup.
//
// The salt and the fixed-length header are consumed with a single read call, as
// required for detection prevention. The header timestamp is checked against now,
// and the request salt is checked against replay, which may be nil to skip the
// replay check.
func ReadTCPRequestStart(src io.Reader, cipher *ServerCipher, now time.Time) (*ParsedTCPRequestStart, int64, error) {
	var total int64
	if err := cipher.Validate(); err != nil {
		return nil, 0, err
	}

	method := cipher.Method

	// A multi-user server expects one identity header naming the user, which is
	// read together with everything else so the read pattern never varies.
	identityLen := 0
	if cipher.MultiUser() {
		identityLen = IdentityHeaderLen
	}

	// The salt and the fixed-length header must be read in one call so that the
	// number of bytes consumed never depends on how far validation got.
	encFixedLen := TCPRequestFixedHeaderLen + method.TagSize
	startBuf := internal.GetBuffer(method.SaltSize + identityLen + encFixedLen)
	defer internal.PutBuffer(startBuf)
	n, err := io.ReadFull(src, startBuf.B)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	requestSaltBuf := startBuf.B[:method.SaltSize]
	identityHeader := startBuf.B[method.SaltSize : method.SaltSize+identityLen]
	encFixed := startBuf.B[method.SaltSize+identityLen:]

	psk, user, err := cipher.SessionPSK(identityHeader, requestSaltBuf)
	if err != nil {
		return nil, total, err
	}

	requestCipher, err := NewTCPStreamCipherFromPSK(method, psk, requestSaltBuf)
	if err != nil {
		return nil, total, err
	}

	fixedPlainScratch := internal.GetBuffer(TCPRequestFixedHeaderLen)
	defer internal.PutBuffer(fixedPlainScratch)
	fixedHeader, err := requestCipher.DecodeRequestFixedHeader(encFixed, fixedPlainScratch.B[:0])
	if err != nil {
		return nil, total, err
	}

	if err := ValidateTimestamp(fixedHeader.Timestamp, now); err != nil {
		return nil, total, err
	}

	// Salts are only stored once the message is known to be authentic and fresh,
	// so unauthenticated traffic cannot fill the cache.
	if cipher.Replay != nil && cipher.Replay.SeenOrAdd(requestSaltBuf, now, ReplayWindowDuration) {
		return nil, total, ErrReplayDetected
	}

	encVariable := internal.GetBuffer(int(fixedHeader.Length) + method.TagSize)
	defer internal.PutBuffer(encVariable)
	n, err = io.ReadFull(src, encVariable.B)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	variablePlainScratch := internal.GetBuffer(int(fixedHeader.Length))
	defer internal.PutBuffer(variablePlainScratch)
	variableHeader, err := requestCipher.DecodeRequestVariableHeader(encVariable.B, variablePlainScratch.B[:0])
	if err != nil {
		return nil, total, err
	}

	parsed := &ParsedTCPRequestStart{
		Salt:   append([]byte(nil), requestSaltBuf...),
		Cipher: requestCipher,
		Fixed:  fixedHeader,
		Header: variableHeader,
		User:   user,
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

	headerPlainScratch := internal.GetBuffer(header.EncodedLen())
	defer internal.PutBuffer(headerPlainScratch)

	var stackBuf [tcpResponseStartStackBufSize]byte
	out := stackBuf[:0]
	out = append(out, responseSalt...)
	out, err = responseCipher.EncodeResponseHeaderTo(out, &header, headerPlainScratch.B[:0])
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
//
// The salt and the fixed-length header are consumed with a single read call, as
// required for detection prevention. The header timestamp is checked against now,
// and its echoed request salt against expectedRequestSalt.
func ReadTCPResponseStart(src io.Reader, method Method, psk, expectedRequestSalt []byte, now time.Time) (*ParsedTCPResponseStart, int64, error) {
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

	// The salt and the fixed-length header must be read in one call so that the
	// number of bytes consumed never depends on how far validation got.
	plainHeaderLen := TCPResponseFixedBaseLen + method.SaltSize
	startBuf := internal.GetBuffer(method.SaltSize + plainHeaderLen + method.TagSize)
	defer internal.PutBuffer(startBuf)
	n, err := io.ReadFull(src, startBuf.B)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	responseSaltBuf, encHeader := startBuf.B[:method.SaltSize], startBuf.B[method.SaltSize:]

	responseCipher, err := NewTCPStreamCipherFromPSK(method, psk, responseSaltBuf)
	if err != nil {
		return nil, total, err
	}

	plainHeaderScratch := internal.GetBuffer(plainHeaderLen)
	defer internal.PutBuffer(plainHeaderScratch)
	header, err := responseCipher.DecodeResponseHeader(encHeader, plainHeaderScratch.B[:0])
	if err != nil {
		return nil, total, err
	}

	if err := ValidateTimestamp(header.Timestamp, now); err != nil {
		return nil, total, err
	}

	encPayloadBuf := internal.GetBuffer(responseCipher.EncryptedPayloadLength(int(header.Length)))
	defer internal.PutBuffer(encPayloadBuf)
	n, err = io.ReadFull(src, encPayloadBuf.B)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	payloadScratch := internal.GetBuffer(int(header.Length))
	defer internal.PutBuffer(payloadScratch)
	initialPayload, err := responseCipher.DecodeChunkPayloadTo(payloadScratch.B[:0], encPayloadBuf.B)
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
