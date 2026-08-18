package internal

import (
	"math/bits"
	"sync"
)

const (
	minPow = 0  // 2^0 = 1 byte
	maxPow = 31 // 2^31 = 2GB
)

// Buffer is a pooled byte buffer.
//
// The buffer is handed around inside a struct rather than as a bare slice
// because a sync.Pool stores any: putting a slice into one boxes its header,
// which allocates. Keeping the pointer means a Get/Put cycle allocates nothing
// and needs only one pool.
//
// Callers may reslice B freely, including growing it by appending; whatever it
// has become is what goes back to the pool. They must not move its start, since
// the buffer would then shrink a little on every trip.
type Buffer struct {
	B []byte
}

// bufferPool is an array of sync.Pool for buffers of sizes 2^0, 2^1, ..., 2^31.
var bufferPool [maxPow + 1]*sync.Pool

func init() {
	for i := minPow; i <= maxPow; i++ {
		size := 1 << i

		bufferPool[i] = &sync.Pool{
			New: func(sz int) func() any {
				return func() any {
					return &Buffer{B: make([]byte, sz)}
				}
			}(size),
		}
	}
}

// GetBuffer returns a buffer whose B is n bytes long.
func GetBuffer(n int) *Buffer {
	if n < 0 {
		n = 0
	}

	i := ceilLog2(n)
	if i > maxPow {
		return &Buffer{B: make([]byte, n)} // too large, don't pool
	}

	buf := bufferPool[i].Get().(*Buffer)
	buf.B = buf.B[:n]

	return buf
}

// PutBuffer returns a buffer to the pool. It must not be used afterwards.
func PutBuffer(buf *Buffer) {
	// A zero capacity buffer has no class to go back to.
	if buf == nil || cap(buf.B) == 0 {
		return
	}

	// Rounded down, so the buffer always covers the class it goes back to. A
	// capacity that is not a power of two, as an appended buffer's is, would
	// otherwise be sliced past its end.
	i := floorLog2(cap(buf.B))
	if i > maxPow {
		return
	}

	buf.B = buf.B[:1<<i]
	bufferPool[i].Put(buf)
}

// ceilLog2 returns the smallest i where 1<<i >= n.
func ceilLog2(n int) int {
	if n <= 1 {
		return 0
	}
	n--
	return bits.Len(uint(n))
}

// floorLog2 returns the largest i where 1<<i <= n.
func floorLog2(n int) int {
	if n <= 1 {
		return 0
	}
	return bits.Len(uint(n)) - 1
}

// BytesWriter is a simple wrapper around a byte slice that implements io.Writer.
type BytesWriter struct {
	b   []byte
	pos int
}

// Init initializes the BytesWriter with a byte slice.
func (w *BytesWriter) Init(buf []byte) {
	w.b = buf
	w.pos = 0
}

// Bytes returns the written portion of the byte slice.
func (w *BytesWriter) Bytes() []byte {
	return w.b[:w.pos]
}

// Write implements [io.Writer].
func (w *BytesWriter) Write(p []byte) (int, error) {
	n := copy(w.b[w.pos:], p)
	w.pos += n
	return n, nil
}
