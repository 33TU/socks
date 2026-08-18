package shadowsocks

import (
	"crypto/rand"
	"fmt"
	"math/big"
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

	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return 0, err
	}
	return min + int(n.Int64()), nil
}
