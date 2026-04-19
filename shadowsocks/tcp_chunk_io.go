package shadowsocks

import (
	"fmt"
	"io"

	ibuf "github.com/33TU/socks/internal"
)

// TCPChunkReader reads encrypted Shadowsocks 2022 TCP chunks.
type TCPChunkReader struct {
	Cipher *TCPStreamCipher
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

	encLenBuf := ibuf.GetBytes(r.Cipher.EncryptedChunkLength())
	defer ibuf.PutBytes(encLenBuf)

	n, err := io.ReadFull(src, encLenBuf)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	lenScratch := ibuf.GetBytes(TcpChunkLengthLen)
	defer ibuf.PutBytes(lenScratch)

	payloadLen, err := r.Cipher.DecodeChunkLength(encLenBuf, lenScratch[:0])
	if err != nil {
		return nil, total, err
	}

	encPayloadBuf := ibuf.GetBytes(r.Cipher.EncryptedPayloadLength(int(payloadLen)))
	defer ibuf.PutBytes(encPayloadBuf)

	n, err = io.ReadFull(src, encPayloadBuf)
	total += int64(n)
	if err != nil {
		return nil, total, err
	}

	dst, err = r.Cipher.DecodeChunkPayloadTo(dst, encPayloadBuf)
	if err != nil {
		return nil, total, err
	}

	return dst, total, nil
}

// TCPChunkWriter writes encrypted Shadowsocks 2022 TCP chunks.
type TCPChunkWriter struct {
	Cipher *TCPStreamCipher
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

	out := ibuf.GetBytes(
		w.Cipher.EncryptedChunkLength() +
			w.Cipher.EncryptedPayloadLength(len(payload)),
	)
	defer ibuf.PutBytes(out)

	out = out[:0]

	var err error
	out, err = w.Cipher.EncodeChunkLengthTo(out, uint16(len(payload)))
	if err != nil {
		return 0, err
	}

	out, err = w.Cipher.EncodeChunkPayloadTo(out, payload)
	if err != nil {
		return 0, err
	}

	n, err := dst.Write(out)
	return int64(n), err
}
