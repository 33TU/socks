package shadowsocks_test

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func newTCPConnTestMethod(t *testing.T) shadowsocks.Method {
	t.Helper()

	method, err := shadowsocks.ParseMethod(shadowsocks.Method2022Blake3AES128GCM)
	if err != nil {
		t.Fatalf("ParseMethod() error = %v", err)
	}

	return method
}

func newTCPConnTestPSKAndSalt(method shadowsocks.Method) ([]byte, []byte) {
	psk := make([]byte, method.KeySize)
	salt := make([]byte, method.SaltSize)

	for i := range psk {
		psk[i] = byte(i + 1)
	}
	for i := range salt {
		salt[i] = byte(i + 101)
	}

	return psk, salt
}

func newTCPConnCipherPair(t *testing.T) (*shadowsocks.TCPStreamCipher, *shadowsocks.TCPStreamCipher) {
	t.Helper()

	method := newTCPConnTestMethod(t)
	psk, salt := newTCPConnTestPSKAndSalt(method)

	enc, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, salt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK(enc) error = %v", err)
	}

	dec, err := shadowsocks.NewTCPStreamCipherFromPSK(method, psk, salt)
	if err != nil {
		t.Fatalf("NewTCPStreamCipherFromPSK(dec) error = %v", err)
	}

	return enc, dec
}

func TestTCPConn_Read(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	enc, dec := newTCPConnCipherPair(t)

	var writer shadowsocks.TCPChunkWriter
	if err := writer.Init(enc); err != nil {
		t.Fatalf("writer.Init() error = %v", err)
	}

	var reader shadowsocks.TCPChunkReader
	if err := reader.Init(dec); err != nil {
		t.Fatalf("reader.Init() error = %v", err)
	}

	c := &shadowsocks.TCPConn{
		Conn:   clientConn,
		Reader: reader,
		Writer: writer,
	}

	want := []byte("hello world")

	go func() {
		defer serverConn.Close()
		if _, err := writer.WriteChunk(serverConn, want); err != nil {
			t.Errorf("WriteChunk() error = %v", err)
		}
	}()

	buf := make([]byte, len(want))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != len(want) {
		t.Fatalf("Read() n = %d, want %d", n, len(want))
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("Read() = %q, want %q", buf[:n], want)
	}
}

func TestTCPConn_Read_PartialBuffered(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	enc, dec := newTCPConnCipherPair(t)

	var writer shadowsocks.TCPChunkWriter
	if err := writer.Init(enc); err != nil {
		t.Fatalf("writer.Init() error = %v", err)
	}

	var reader shadowsocks.TCPChunkReader
	if err := reader.Init(dec); err != nil {
		t.Fatalf("reader.Init() error = %v", err)
	}

	c := &shadowsocks.TCPConn{
		Conn:   clientConn,
		Reader: reader,
		Writer: writer,
	}

	want := []byte("hello world")

	go func() {
		defer serverConn.Close()
		if _, err := writer.WriteChunk(serverConn, want); err != nil {
			t.Errorf("WriteChunk() error = %v", err)
		}
	}()

	buf1 := make([]byte, 5)
	n1, err := c.Read(buf1)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if n1 != 5 {
		t.Fatalf("first Read() n = %d, want 5", n1)
	}
	if !bytes.Equal(buf1[:n1], []byte("hello")) {
		t.Fatalf("first Read() = %q, want %q", buf1[:n1], "hello")
	}

	buf2 := make([]byte, 6)
	n2, err := c.Read(buf2)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if n2 != 6 {
		t.Fatalf("second Read() n = %d, want 6", n2)
	}
	if !bytes.Equal(buf2[:n2], []byte(" world")) {
		t.Fatalf("second Read() = %q, want %q", buf2[:n2], " world")
	}
}

func TestTCPConn_Write(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	enc, dec := newTCPConnCipherPair(t)

	var writer shadowsocks.TCPChunkWriter
	if err := writer.Init(enc); err != nil {
		t.Fatalf("writer.Init() error = %v", err)
	}

	var reader shadowsocks.TCPChunkReader
	if err := reader.Init(dec); err != nil {
		t.Fatalf("reader.Init() error = %v", err)
	}

	c := &shadowsocks.TCPConn{
		Conn:   clientConn,
		Reader: reader,
		Writer: writer,
	}

	want := []byte("hello world")
	errCh := make(chan error, 1)

	go func() {
		defer serverConn.Close()

		got, _, err := reader.ReadChunkTo(nil, serverConn)
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(got, want) {
			errCh <- errors.New("payload mismatch")
			return
		}
		errCh <- nil
	}()

	n, err := c.Write(want)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(want) {
		t.Fatalf("Write() n = %d, want %d", n, len(want))
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server read error = %v", err)
	}
}

func TestTCPConn_Write_Empty(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	enc, dec := newTCPConnCipherPair(t)

	var writer shadowsocks.TCPChunkWriter
	if err := writer.Init(enc); err != nil {
		t.Fatalf("writer.Init() error = %v", err)
	}

	var reader shadowsocks.TCPChunkReader
	if err := reader.Init(dec); err != nil {
		t.Fatalf("reader.Init() error = %v", err)
	}

	c := &shadowsocks.TCPConn{
		Conn:   clientConn,
		Reader: reader,
		Writer: writer,
	}

	n, err := c.Write(nil)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != 0 {
		t.Fatalf("Write() n = %d, want 0", n)
	}
}

func TestTCPConn_Write_SplitsLargePayload(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	enc, dec := newTCPConnCipherPair(t)

	var writer shadowsocks.TCPChunkWriter
	if err := writer.Init(enc); err != nil {
		t.Fatalf("writer.Init() error = %v", err)
	}

	var reader shadowsocks.TCPChunkReader
	if err := reader.Init(dec); err != nil {
		t.Fatalf("reader.Init() error = %v", err)
	}

	c := &shadowsocks.TCPConn{
		Conn:   clientConn,
		Reader: reader,
		Writer: writer,
	}

	want := bytes.Repeat([]byte("a"), 0x10000+123)
	done := make(chan error, 1)

	go func() {
		defer serverConn.Close()

		var got []byte

		part1, _, err := reader.ReadChunkTo(nil, serverConn)
		if err != nil {
			done <- err
			return
		}
		got = append(got, part1...)

		part2, _, err := reader.ReadChunkTo(nil, serverConn)
		if err != nil {
			done <- err
			return
		}
		got = append(got, part2...)

		if !bytes.Equal(got, want) {
			done <- errors.New("payload mismatch")
			return
		}
		done <- nil
	}()

	n, err := c.Write(want)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(want) {
		t.Fatalf("Write() n = %d, want %d", n, len(want))
	}

	if err := <-done; err != nil {
		t.Fatalf("server read error = %v", err)
	}
}
