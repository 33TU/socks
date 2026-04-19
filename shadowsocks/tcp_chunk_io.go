package shadowsocks

import (
	"fmt"
	"io"
)

// TCPChunkReader reads encrypted Shadowsocks 2022 TCP chunks.
type TCPChunkReader struct {
	Cipher *TCPStreamCipher

	encLenBuf     []byte
	encPayloadBuf []byte
	lenScratch    [TcpChunkLengthLen]byte
}

// Init initializes the chunk reader for a TCP stream cipher.
func (r *TCPChunkReader) Init(c *TCPStreamCipher) error {
	if c == nil {
		return fmt.Errorf("nil TCP stream cipher")
	}
	if err := c.Validate(); err != nil {
		return err
	}

	r.Cipher = c

	encLenSize := c.EncryptedChunkLength()
	if cap(r.encLenBuf) < encLenSize {
		r.encLenBuf = make([]byte, encLenSize)
	} else {
		r.encLenBuf = r.encLenBuf[:encLenSize]
	}

	r.encPayloadBuf = r.encPayloadBuf[:0]
	return nil
}

// Validate checks whether the chunk reader is internally valid.
func (r *TCPChunkReader) Validate() error {
	if r == nil {
		return fmt.Errorf("nil TCP chunk reader")
	}
	if r.Cipher == nil {
		return fmt.Errorf("missing TCP stream cipher")
	}
	return r.Cipher.Validate()
}

// ReadChunkTo reads a full encrypted TCP chunk from src, decrypts it, and
// appends the plaintext payload into dst. It returns the resulting slice and
// total bytes read.
func (r *TCPChunkReader) ReadChunkTo(dst []byte, src io.Reader) ([]byte, int64, error) {
	if err := r.Validate(); err != nil {
		return nil, 0, err
	}

	var total int64

	n, err := io.ReadFull(src, r.encLenBuf)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	payloadLen, err := r.Cipher.DecodeChunkLength(r.encLenBuf, r.lenScratch[:0])
	if err != nil {
		return nil, total, err
	}

	encPayloadLen := r.Cipher.EncryptedPayloadLength(int(payloadLen))
	if cap(r.encPayloadBuf) < encPayloadLen {
		r.encPayloadBuf = make([]byte, encPayloadLen)
	} else {
		r.encPayloadBuf = r.encPayloadBuf[:encPayloadLen]
	}

	n, err = io.ReadFull(src, r.encPayloadBuf)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	dst, err = r.Cipher.DecodeChunkPayloadTo(dst, r.encPayloadBuf)
	if err != nil {
		return nil, total, err
	}

	return dst, total, nil
}

// TCPChunkWriter writes encrypted Shadowsocks 2022 TCP chunks.
type TCPChunkWriter struct {
	Cipher *TCPStreamCipher
	outBuf []byte
}

// Init initializes the chunk writer for a TCP stream cipher.
func (w *TCPChunkWriter) Init(c *TCPStreamCipher) error {
	if c == nil {
		return fmt.Errorf("nil TCP stream cipher")
	}
	if err := c.Validate(); err != nil {
		return err
	}

	w.Cipher = c
	w.outBuf = w.outBuf[:0]
	return nil
}

// Validate checks whether the chunk writer is internally valid.
func (w *TCPChunkWriter) Validate() error {
	if w == nil {
		return fmt.Errorf("nil TCP chunk writer")
	}
	if w.Cipher == nil {
		return fmt.Errorf("missing TCP stream cipher")
	}
	return w.Cipher.Validate()
}

// WriteChunk writes a full encrypted TCP chunk to dst and returns the total
// bytes written.
func (w *TCPChunkWriter) WriteChunk(dst io.Writer, payload []byte) (int64, error) {
	if err := w.Validate(); err != nil {
		return 0, err
	}
	if len(payload) > 0xFFFF {
		return 0, fmt.Errorf("payload too large: got %d, max %d", len(payload), 0xFFFF)
	}

	need := w.Cipher.EncryptedChunkLength() + w.Cipher.EncryptedPayloadLength(len(payload))
	if cap(w.outBuf) < need {
		w.outBuf = make([]byte, 0, need)
	} else {
		w.outBuf = w.outBuf[:0]
	}

	var err error
	w.outBuf, err = w.Cipher.EncodeChunkLengthTo(w.outBuf, uint16(len(payload)))
	if err != nil {
		return 0, err
	}

	w.outBuf, err = w.Cipher.EncodeChunkPayloadTo(w.outBuf, payload)
	if err != nil {
		return 0, err
	}

	n, err := dst.Write(w.outBuf)
	return int64(n), err
}
