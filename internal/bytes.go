package internal

import (
	"math/bits"
	"sync"
)

const (
	minPow = 0  // 2^0 = 1 byte
	maxPow = 31 // 2^31 = 2GB
)

// bytesPool is an array of sync.Pool for byte slices of sizes 2^0, 2^1, ..., 2^31.
//
// The pools hold *[]byte rather than []byte: a sync.Pool stores any, and
// putting a slice in one boxes its header, which allocates on every Put. Every
// relayed chunk and datagram passes through here at least twice, so that
// allocation showed up on all of them.
var bytesPool [maxPow + 1]*sync.Pool

// headerPool recycles the pointers the buffers are handed over in, so that
// avoiding the boxing does not simply move the allocation to the pointer.
var headerPool = sync.Pool{
	New: func() any { return new([]byte) },
}

func init() {
	for i := minPow; i <= maxPow; i++ {
		size := 1 << i

		bytesPool[i] = &sync.Pool{
			New: func(sz int) func() any {
				return func() any {
					b := make([]byte, sz)
					return &b
				}
			}(size),
		}
	}
}

// GetBytes returns a byte slice of at least n bytes from the pool.
func GetBytes(n int) []byte {
	if n <= 0 {
		return nil
	}

	i := ceilLog2(n)
	if i > maxPow {
		return make([]byte, n) // too large, don’t pool
	}

	p := bytesPool[i].Get().(*[]byte)
	b := *p

	*p = nil
	headerPool.Put(p)

	return b[:n]
}

// PutBytes returns a byte slice to the pool.
func PutBytes(b []byte) {
	// A zero capacity slice has no class to go back to, and slicing it to one
	// would panic.
	if cap(b) == 0 {
		return
	}

	// Rounded down, so the buffer always covers the class it goes back to. A
	// capacity that is not a power of two, as an appended buffer has, would
	// otherwise be sliced past its end.
	i := floorLog2(cap(b))
	if i > maxPow {
		return
	}

	p := headerPool.Get().(*[]byte)
	*p = b[:1<<i]

	bytesPool[i].Put(p)
}

// floorLog2 returns the largest i where 1<<i <= n.
func floorLog2(n int) int {
	if n <= 1 {
		return 0
	}
	return bits.Len(uint(n)) - 1
}

func ceilLog2(n int) int {
	if n <= 1 {
		return 0
	}
	n--
	return bits.Len(uint(n))
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
