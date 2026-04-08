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
var bytesPool [maxPow + 1]*sync.Pool

func init() {
	for i := minPow; i <= maxPow; i++ {
		size := 1 << i

		bytesPool[i] = &sync.Pool{
			New: func(sz int) func() any {
				return func() any {
					return make([]byte, sz)
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

	return bytesPool[i].Get().([]byte)[:n]
}

// PutBytes returns a byte slice to the pool.
func PutBytes(b []byte) {
	if b == nil {
		return
	}

	i := ceilLog2(cap(b))
	if i > maxPow {
		return
	}

	bytesPool[i].Put(b[:1<<i])
}

func ceilLog2(n int) int {
	if n <= 1 {
		return 0
	}
	n--
	return bits.Len(uint(n))
}
