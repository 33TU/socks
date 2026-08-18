package shadowsocks

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// TCPStreamCipher manages AEAD state for a single Shadowsocks 2022 TCP stream.
type TCPStreamCipher struct {
	Method Method
	AEAD   cipher.AEAD
	Nonce  [AeadNonceSize]byte

	// lenBuf holds the length chunk being encoded. It lives here rather than on
	// the stack because passing it to the AEAD would otherwise escape it, once
	// per chunk written. A stream cipher already carries per-operation state in
	// Nonce, so it was never usable from two goroutines at once.
	lenBuf [TCPChunkLengthLen]byte
}

// NewTCPStreamCipher creates a new TCP stream cipher from an already-derived subkey.
func NewTCPStreamCipher(method Method, subkey []byte) (*TCPStreamCipher, error) {
	if err := method.Validate(); err != nil {
		return nil, err
	}
	if len(subkey) != method.KeySize {
		return nil, fmt.Errorf("invalid subkey length: got %d, want %d", len(subkey), method.KeySize)
	}

	aead, err := method.NewAEAD(subkey)
	if err != nil {
		return nil, err
	}

	return &TCPStreamCipher{
		Method: method,
		AEAD:   aead,
	}, nil
}

// NewTCPStreamCipherFromPSK creates a new TCP stream cipher from a PSK and salt.
func NewTCPStreamCipherFromPSK(method Method, psk, salt []byte) (*TCPStreamCipher, error) {
	if err := method.Validate(); err != nil {
		return nil, err
	}
	if len(psk) != method.KeySize {
		return nil, fmt.Errorf("invalid PSK length: got %d, want %d", len(psk), method.KeySize)
	}
	if len(salt) != method.SaltSize {
		return nil, fmt.Errorf("invalid salt length: got %d, want %d", len(salt), method.SaltSize)
	}

	subkey := make([]byte, method.KeySize)
	if err := DeriveSubkeyTo(subkey, method, psk, salt); err != nil {
		return nil, err
	}

	return NewTCPStreamCipher(method, subkey)
}

// Reset resets the stream nonce to zero.
func (s *TCPStreamCipher) Reset() {
	clear(s.Nonce[:])
}

// SealTo encrypts plaintext into dst using the current nonce and increments the nonce.
func (s *TCPStreamCipher) SealTo(dst, plaintext []byte) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("nil TCP stream cipher")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}

	out := s.AEAD.Seal(dst, s.Nonce[:], plaintext, nil)
	s.incNonce()
	return out, nil
}

// OpenTo decrypts ciphertext into dst using the current nonce and increments the nonce.
func (s *TCPStreamCipher) OpenTo(dst, ciphertext []byte) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("nil TCP stream cipher")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}

	out, err := s.AEAD.Open(dst, s.Nonce[:], ciphertext, nil)
	if err != nil {
		return nil, err
	}

	s.incNonce()
	return out, nil
}

// Validate checks whether the TCP stream cipher is internally valid.
func (s *TCPStreamCipher) Validate() error {
	if s == nil {
		return fmt.Errorf("nil TCP stream cipher")
	}
	if err := s.Method.Validate(); err != nil {
		return err
	}
	if s.AEAD == nil {
		return fmt.Errorf("missing AEAD")
	}
	if s.AEAD.NonceSize() != s.Method.NonceSize {
		return fmt.Errorf("invalid AEAD nonce size: got %d, want %d", s.AEAD.NonceSize(), s.Method.NonceSize)
	}
	if s.AEAD.Overhead() != s.Method.TagSize {
		return fmt.Errorf("invalid AEAD tag size: got %d, want %d", s.AEAD.Overhead(), s.Method.TagSize)
	}

	return nil
}

// EncryptedChunkLength returns the ciphertext size of a TCP chunk length field.
func (s *TCPStreamCipher) EncryptedChunkLength() int {
	return TCPChunkLengthLen + s.Method.TagSize
}

// EncryptedPayloadLength returns the ciphertext size of a TCP payload chunk.
func (s *TCPStreamCipher) EncryptedPayloadLength(payloadLen int) int {
	return payloadLen + s.Method.TagSize
}

// EncodeChunkLengthTo encrypts a 2-byte big-endian payload length into dst.
func (s *TCPStreamCipher) EncodeChunkLengthTo(dst []byte, payloadLen uint16) ([]byte, error) {
	binary.BigEndian.PutUint16(s.lenBuf[:], payloadLen)
	return s.SealTo(dst, s.lenBuf[:])
}

// DecodeChunkLength decrypts and parses a 2-byte big-endian payload length.
func (s *TCPStreamCipher) DecodeChunkLength(src []byte, scratch []byte) (uint16, error) {
	plain, err := s.OpenTo(scratch[:0], src)
	if err != nil {
		return 0, err
	}
	if len(plain) != TCPChunkLengthLen {
		return 0, fmt.Errorf("invalid TCP chunk length size: got %d, want %d", len(plain), TCPChunkLengthLen)
	}

	return binary.BigEndian.Uint16(plain), nil
}

// EncodeChunkPayloadTo encrypts a TCP payload chunk into dst.
func (s *TCPStreamCipher) EncodeChunkPayloadTo(dst, payload []byte) ([]byte, error) {
	if len(payload) > MaxTCPChunkPayloadLength {
		return nil, fmt.Errorf("payload too large: got %d, max %d", len(payload), MaxTCPChunkPayloadLength)
	}
	return s.SealTo(dst, payload)
}

// DecodeChunkPayloadTo decrypts a TCP payload chunk into dst.
func (s *TCPStreamCipher) DecodeChunkPayloadTo(dst, src []byte) ([]byte, error) {
	return s.OpenTo(dst, src)
}

// EncodeRequestFixedHeaderTo encodes and encrypts a TCP request fixed header into dst.
func (s *TCPStreamCipher) EncodeRequestFixedHeaderTo(dst []byte, h *TCPRequestFixedHeader, scratch []byte) ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("nil TCP request fixed header")
	}

	plain, err := h.EncodeTo(scratch[:0])
	if err != nil {
		return nil, err
	}

	return s.SealTo(dst, plain)
}

// DecodeRequestFixedHeader decrypts and decodes a TCP request fixed header from src.
func (s *TCPStreamCipher) DecodeRequestFixedHeader(src []byte, scratch []byte) (TCPRequestFixedHeader, error) {
	var h TCPRequestFixedHeader

	plain, err := s.OpenTo(scratch[:0], src)
	if err != nil {
		return TCPRequestFixedHeader{}, err
	}
	if _, err := h.Decode(plain); err != nil {
		return TCPRequestFixedHeader{}, err
	}

	return h, nil
}

// EncodeRequestVariableHeaderTo encodes and encrypts a TCP request variable header into dst.
// scratch is used as the plaintext scratch buffer and may be nil.
func (s *TCPStreamCipher) EncodeRequestVariableHeaderTo(dst []byte, h *TCPRequestVariableHeader, scratch []byte) ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("nil TCP request variable header")
	}

	plain, err := h.EncodeTo(scratch[:0])
	if err != nil {
		return nil, err
	}

	return s.SealTo(dst, plain)
}

// DecodeRequestVariableHeader decrypts and decodes a TCP request variable header from src.
func (s *TCPStreamCipher) DecodeRequestVariableHeader(src []byte, scratch []byte) (TCPRequestVariableHeader, error) {
	var h TCPRequestVariableHeader

	plain, err := s.OpenTo(scratch[:0], src)
	if err != nil {
		return TCPRequestVariableHeader{}, err
	}
	if _, err := h.Decode(plain); err != nil {
		return TCPRequestVariableHeader{}, err
	}

	return h, nil
}

// EncodeResponseHeaderTo encodes and encrypts a TCP response header into dst.
// scratch is used as the plaintext scratch buffer and may be nil.
func (s *TCPStreamCipher) EncodeResponseHeaderTo(dst []byte, h *TCPResponseHeader, scratch []byte) ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("nil TCP response header")
	}

	plain, err := h.EncodeTo(scratch[:0])
	if err != nil {
		return nil, err
	}

	return s.SealTo(dst, plain)
}

// DecodeResponseHeader decrypts and decodes a TCP response header from src.
func (s *TCPStreamCipher) DecodeResponseHeader(src []byte, scratch []byte) (TCPResponseHeader, error) {
	var h TCPResponseHeader

	plain, err := s.OpenTo(scratch[:0], src)
	if err != nil {
		return TCPResponseHeader{}, err
	}
	if _, err := h.Decode(plain, s.Method.SaltSize); err != nil {
		return TCPResponseHeader{}, err
	}

	return h, nil
}

// incNonce increments the TCP stream nonce as a 12-byte little-endian integer.
func (s *TCPStreamCipher) incNonce() {
	for i := range len(s.Nonce) {
		s.Nonce[i]++
		if s.Nonce[i] != 0 {
			return
		}
	}
}
