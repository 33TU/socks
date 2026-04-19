package shadowsocks

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// FillRandomBytes fills dst with cryptographically secure random bytes.
func FillRandomBytes(dst []byte) error {
	if len(dst) == 0 {
		return nil
	}
	n, err := rand.Read(dst)
	if err != nil {
		return err
	}
	if n != len(dst) {
		return fmt.Errorf("short random read: got %d, want %d", n, len(dst))
	}
	return nil
}

// RandomInt returns a random integer in the inclusive range [min, max].
func RandomInt(min, max int) (int, error) {
	if min > max {
		return 0, fmt.Errorf("invalid random range: min %d > max %d", min, max)
	}
	if min == max {
		return min, nil
	}

	span := uint64(max - min + 1)
	if span == 0 {
		return 0, fmt.Errorf("invalid random range")
	}

	var buf [8]byte
	limit := ^uint64(0) - (^uint64(0) % span)

	for {
		if err := FillRandomBytes(buf[:]); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint64(buf[:])
		if v < limit {
			return min + int(v%span), nil
		}
	}
}
