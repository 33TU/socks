package internal

import "testing"

// BenchmarkBytesPool measures a Get/Put cycle, which every relayed chunk and
// datagram performs at least twice.
func BenchmarkBytesPool(b *testing.B) {
	for _, size := range []int{64, 1400, 16 * 1024, 64 * 1024} {
		b.Run(sizeLabel(size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				buf := GetBytes(size)
				PutBytes(buf)
			}
		})
	}
}

func sizeLabel(n int) string {
	switch n {
	case 64:
		return "64B"
	case 1400:
		return "1400B"
	case 16 * 1024:
		return "16KiB"
	default:
		return "64KiB"
	}
}

// TestPutBytesEdgeCases guards the sizes that have no pool class of their own.
func TestPutBytesEdgeCases(t *testing.T) {
	PutBytes(nil)
	PutBytes([]byte{})
	PutBytes(make([]byte, 0, 0))

	// An appended buffer has a capacity that is not a power of two.
	grown := append(make([]byte, 0, 8), make([]byte, 100)...)
	PutBytes(grown)

	// A buffer larger than the largest class is dropped rather than pooled.
	PutBytes(make([]byte, 16))

	if got := GetBytes(0); got != nil {
		t.Errorf("GetBytes(0) = %v, want nil", got)
	}
	if got := GetBytes(100); len(got) != 100 || cap(got) < 100 {
		t.Errorf("GetBytes(100) = len %d cap %d, want at least 100", len(got), cap(got))
	}
}
