package shadowsocks

import (
	"fmt"
	"io"
)

// TCPChunkReader reads encrypted Shadowsocks 2022 TCP chunks and exposes a
// stream-style io.Reader view over the decrypted payload.
type TCPChunkReader struct {
	Cipher *TCPStreamCipher
	Src    io.Reader

	encLenBuf     []byte
	encPayloadBuf []byte
	lenScratch    [TcpChunkLengthLen]byte

	chunkBuf []byte
	readBuf  []byte
}

// Init initializes the chunk reader for a TCP stream cipher and source.
func (r *TCPChunkReader) Init(c *TCPStreamCipher, src io.Reader) error {
	if c == nil {
		return fmt.Errorf("nil TCP stream cipher")
	}
	if src == nil {
		return fmt.Errorf("nil TCP chunk source")
	}
	if err := c.Validate(); err != nil {
		return err
	}

	r.Cipher = c
	r.Src = src

	encLenSize := c.EncryptedChunkLength()
	if cap(r.encLenBuf) < encLenSize {
		r.encLenBuf = make([]byte, encLenSize)
	} else {
		r.encLenBuf = r.encLenBuf[:encLenSize]
	}

	r.encPayloadBuf = r.encPayloadBuf[:0]
	r.chunkBuf = r.chunkBuf[:0]
	r.readBuf = r.readBuf[:0]

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
	if r.Src == nil {
		return fmt.Errorf("missing TCP chunk source")
	}
	return r.Cipher.Validate()
}

// ReadChunkTo reads one full encrypted TCP chunk from the underlying source,
// decrypts it, and appends the plaintext payload into dst. It returns the
// resulting slice and total bytes read from the underlying source.
func (r *TCPChunkReader) ReadChunkTo(dst []byte) ([]byte, int64, error) {
	if err := r.Validate(); err != nil {
		return nil, 0, err
	}

	var total int64

	n, err := io.ReadFull(r.Src, r.encLenBuf)
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

	n, err = io.ReadFull(r.Src, r.encPayloadBuf)
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

// Read implements io.Reader over the decrypted TCP stream.
func (r *TCPChunkReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := r.Validate(); err != nil {
		return 0, err
	}

	if len(r.readBuf) == 0 {
		buf, _, err := r.ReadChunkTo(r.chunkBuf[:0])
		if err != nil {
			return 0, err
		}
		r.chunkBuf = buf
		r.readBuf = buf
	}

	n := copy(p, r.readBuf)
	r.readBuf = r.readBuf[n:]
	return n, nil
}

var _ io.Reader = (*TCPChunkReader)(nil)

// TCPChunkWriter writes encrypted Shadowsocks 2022 TCP chunks and exposes a
// stream-style io.Writer interface over plaintext payload.
type TCPChunkWriter struct {
	Cipher *TCPStreamCipher
	Dst    io.Writer
	outBuf []byte
}

// Init initializes the chunk writer for a TCP stream cipher and destination.
func (w *TCPChunkWriter) Init(c *TCPStreamCipher, dst io.Writer) error {
	if c == nil {
		return fmt.Errorf("nil TCP stream cipher")
	}
	if dst == nil {
		return fmt.Errorf("nil TCP chunk destination")
	}
	if err := c.Validate(); err != nil {
		return err
	}

	w.Cipher = c
	w.Dst = dst
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
	if w.Dst == nil {
		return fmt.Errorf("missing TCP chunk destination")
	}
	return w.Cipher.Validate()
}

// WriteChunk writes one full encrypted TCP chunk to the underlying destination
// and returns the total bytes written to the underlying writer.
func (w *TCPChunkWriter) WriteChunk(payload []byte) (int64, error) {
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

	n, err := w.Dst.Write(w.outBuf)
	return int64(n), err
}

// Write implements io.Writer over the plaintext TCP stream.
func (w *TCPChunkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := w.Validate(); err != nil {
		return 0, err
	}

	written := 0
	for len(p) > 0 {
		nn := min(len(p), 0xFFFF)
		if _, err := w.WriteChunk(p[:nn]); err != nil {
			return written, err
		}
		written += nn
		p = p[nn:]
	}
	return written, nil
}

var _ io.Writer = (*TCPChunkWriter)(nil)
