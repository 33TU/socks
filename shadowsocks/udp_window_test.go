package shadowsocks_test

import (
	"testing"

	"github.com/33TU/socks/shadowsocks"
)

func TestSlidingWindowFilter_AcceptsFreshCounters(t *testing.T) {
	f := shadowsocks.NewSlidingWindowFilter(0)

	for i := uint64(0); i < 10_000; i++ {
		if !f.Add(i) {
			t.Fatalf("Add(%d) = false, want true", i)
		}
	}
}

func TestSlidingWindowFilter_RejectsDuplicates(t *testing.T) {
	f := shadowsocks.NewSlidingWindowFilter(0)

	if !f.Add(0) {
		t.Fatal("Add(0) = false, want true")
	}
	if f.Add(0) {
		t.Fatal("Add(0) twice = true, want false")
	}

	for i := uint64(1); i <= 100; i++ {
		if !f.Add(i) {
			t.Fatalf("Add(%d) = false, want true", i)
		}
	}
	for i := uint64(0); i <= 100; i++ {
		if f.Add(i) {
			t.Fatalf("replay of %d accepted, want rejection", i)
		}
	}
}

func TestSlidingWindowFilter_AcceptsOutOfOrderInsideWindow(t *testing.T) {
	f := shadowsocks.NewSlidingWindowFilter(0)

	if !f.Add(100) {
		t.Fatal("Add(100) = false, want true")
	}

	// Anything within the window behind the highest counter is still new.
	for i := uint64(0); i < 100; i++ {
		if !f.Add(i) {
			t.Fatalf("Add(%d) after 100 = false, want true", i)
		}
	}
	for i := uint64(0); i < 100; i++ {
		if f.Add(i) {
			t.Fatalf("replay of %d accepted, want rejection", i)
		}
	}
}

func TestSlidingWindowFilter_RejectsTooOld(t *testing.T) {
	f := shadowsocks.NewSlidingWindowFilter(64)

	high := uint64(100_000)
	if !f.Add(high) {
		t.Fatalf("Add(%d) = false, want true", high)
	}

	stale := high - f.Size() - 1
	if f.IsOk(stale) {
		t.Fatalf("IsOk(%d) = true, want false: counter is outside the window", stale)
	}
	if f.Add(stale) {
		t.Fatalf("Add(%d) = true, want false", stale)
	}

	edge := high - f.Size()
	if !f.IsOk(edge) {
		t.Fatalf("IsOk(%d) = false, want true: counter is on the window edge", edge)
	}
}

func TestSlidingWindowFilter_IsOkDoesNotRecord(t *testing.T) {
	f := shadowsocks.NewSlidingWindowFilter(0)

	if !f.IsOk(7) {
		t.Fatal("IsOk(7) = false, want true")
	}
	if !f.IsOk(7) {
		t.Fatal("IsOk(7) twice = false, want true: checking must not record")
	}
	if !f.Add(7) {
		t.Fatal("Add(7) = false, want true")
	}
	if f.IsOk(7) {
		t.Fatal("IsOk(7) after Add = true, want false")
	}
}

func TestSlidingWindowFilter_LargeJumpClearsWindow(t *testing.T) {
	f := shadowsocks.NewSlidingWindowFilter(0)

	for i := uint64(0); i < 500; i++ {
		f.Add(i)
	}

	// Jumping far ahead must clear stale bits rather than leave them set.
	far := uint64(1_000_000)
	if !f.Add(far) {
		t.Fatalf("Add(%d) = false, want true", far)
	}
	for i := far - 100; i < far; i++ {
		if !f.IsOk(i) {
			t.Fatalf("IsOk(%d) = false, want true: window was not cleared", i)
		}
	}
	if f.IsOk(far) {
		t.Fatalf("IsOk(%d) = true, want false", far)
	}
}

func TestSlidingWindowFilter_Reset(t *testing.T) {
	f := shadowsocks.NewSlidingWindowFilter(0)

	f.Add(42)
	if f.IsOk(42) {
		t.Fatal("IsOk(42) = true before reset, want false")
	}

	f.Reset()
	if !f.IsOk(42) {
		t.Fatal("IsOk(42) = false after Reset, want true")
	}
}

// TestSlidingWindowFilter_HonoursRequestedSize checks that the filter remembers
// at least as many packet IDs as asked for. Rounding the ring down would
// silently give callers a shorter window than they configured.
func TestSlidingWindowFilter_HonoursRequestedSize(t *testing.T) {
	for _, size := range []uint64{1, 64, 65, 128, 200, 256, 1000, 4096, 10_000} {
		f := shadowsocks.NewSlidingWindowFilter(size)

		if f.Size() < size {
			t.Errorf("NewSlidingWindowFilter(%d).Size() = %d, want at least %d", size, f.Size(), size)
			continue
		}

		// Every ID within the requested window must still be accepted.
		high := uint64(1_000_000)
		if !f.Add(high) {
			t.Fatalf("Add(%d) = false, want true", high)
		}
		if !f.IsOk(high - size) {
			t.Errorf("size %d: IsOk(%d) = false, want true", size, high-size)
		}
	}
}
