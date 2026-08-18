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
				PutBuffer(GetBuffer(size))
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
func TestPutBufferEdgeCases(t *testing.T) {
	PutBuffer(nil)
	PutBuffer(&Buffer{})
	PutBuffer(&Buffer{B: []byte{}})

	// An appended buffer has a capacity that is not a power of two, so it goes
	// back to the largest class it fully covers.
	PutBuffer(&Buffer{B: append(make([]byte, 0, 8), make([]byte, 100)...)})

	if got := GetBuffer(0); len(got.B) != 0 {
		t.Errorf("GetBuffer(0) length = %d, want 0", len(got.B))
	}
	if got := GetBuffer(100); len(got.B) != 100 || cap(got.B) < 100 {
		t.Errorf("GetBuffer(100) = len %d cap %d, want at least 100", len(got.B), cap(got.B))
	}

	// A buffer that grew past its class comes back at the larger class, and is
	// still usable afterwards.
	buf := GetBuffer(64)
	buf.B = append(buf.B, make([]byte, 4000)...)
	PutBuffer(buf)

	if reused := GetBuffer(4096); len(reused.B) != 4096 {
		t.Errorf("GetBuffer(4096) length = %d, want 4096", len(reused.B))
	}
}
