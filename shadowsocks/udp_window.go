package shadowsocks

import "math/bits"

// Sliding window filter geometry. Packet IDs are tracked as bits in a ring of
// 64-bit blocks, indexed by the packet ID's upper bits.
const (
	windowBlockBits = 6
	windowBlockSize = 1 << windowBlockBits // packet IDs per block
	windowBlockMask = windowBlockSize - 1

	// DefaultSlidingWindowFilterSize is the default number of packet IDs
	// remembered behind the highest one seen.
	DefaultSlidingWindowFilterSize = 256
)

// SlidingWindowFilter rejects duplicate and out-of-window packet IDs within a
// UDP relay session, following the scheme used by IPsec and WireGuard.
//
// A packet ID is acceptable if it is ahead of every ID seen so far, or if it
// falls inside the window behind the highest one and has not been seen yet.
// Checking and recording are separate operations: the protocol allows the
// packet ID to be screened as soon as the separate header is decrypted, but the
// filter must not be updated until the packet's header has been validated.
//
// A SlidingWindowFilter is not safe for concurrent use.
type SlidingWindowFilter struct {
	size uint64
	mask uint64
	last uint64
	ring []uint64
}

// NewSlidingWindowFilter creates a filter remembering at least size packet IDs.
// A zero size means DefaultSlidingWindowFilterSize.
func NewSlidingWindowFilter(size uint64) *SlidingWindowFilter {
	f := &SlidingWindowFilter{}
	f.Init(size)
	return f
}

// Init resets the filter and sizes it to remember at least size packet IDs.
func (f *SlidingWindowFilter) Init(size uint64) {
	if size == 0 {
		size = DefaultSlidingWindowFilterSize
	}

	// The ring holds a power-of-two number of blocks so block indices can be
	// masked, plus one block of headroom for the block being filled. The block
	// count is rounded up past the requested size, since one block of the ring
	// is headroom and the window would otherwise come out short.
	blocks := uint64(1) << bits.Len64(size/windowBlockSize+1)
	if blocks < 2 {
		blocks = 2
	}

	f.ring = make([]uint64, blocks)
	f.mask = blocks - 1
	f.size = blocks*windowBlockSize - windowBlockSize
	f.last = 0
}

// Size returns the number of packet IDs remembered behind the highest one seen.
func (f *SlidingWindowFilter) Size() uint64 {
	return f.size
}

// Reset clears the filter, forgetting every packet ID seen so far.
func (f *SlidingWindowFilter) Reset() {
	clear(f.ring)
	f.last = 0
}

// IsOk reports whether counter would be accepted, without recording it.
func (f *SlidingWindowFilter) IsOk(counter uint64) bool {
	if len(f.ring) == 0 {
		f.Init(0)
	}

	if counter > f.last {
		return true
	}
	if f.last-counter > f.size {
		return false
	}

	return !f.isSet(counter)
}

// Add records counter and reports whether it was acceptable. A counter that is
// rejected leaves the filter unchanged.
func (f *SlidingWindowFilter) Add(counter uint64) bool {
	if !f.IsOk(counter) {
		return false
	}

	if counter > f.last {
		// Clear the blocks the window has just moved past, so their old bits are
		// not mistaken for packet IDs in the new window.
		current := f.last >> windowBlockBits
		next := counter >> windowBlockBits

		diff := min(next-current, uint64(len(f.ring)))
		for i := uint64(1); i <= diff; i++ {
			f.ring[(current+i)&f.mask] = 0
		}

		f.last = counter
	}

	f.set(counter)
	return true
}

func (f *SlidingWindowFilter) isSet(counter uint64) bool {
	index := (counter >> windowBlockBits) & f.mask
	return f.ring[index]&(1<<(counter&windowBlockMask)) != 0
}

func (f *SlidingWindowFilter) set(counter uint64) {
	index := (counter >> windowBlockBits) & f.mask
	f.ring[index] |= 1 << (counter & windowBlockMask)
}
