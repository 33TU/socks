package shadowsocks

import (
	"errors"
	"fmt"
	"time"
)

// ErrBadTimestamp is returned when a header timestamp is outside the allowed window.
var ErrBadTimestamp = errors.New("bad timestamp")

// ValidateTimestamp checks a header's Unix epoch timestamp against now.
// Timestamps more than MaxTimestampDiff away in either direction are replays.
func ValidateTimestamp(timestamp uint64, now time.Time) error {
	nowEpoch := now.Unix()
	if nowEpoch < 0 {
		nowEpoch = 0
	}
	nowTimestamp := uint64(nowEpoch)

	// Compared as unsigned. A signed difference overflows for timestamps near
	// the top of the u64 range, and negating the result then wraps them back
	// inside the window.
	diff := timestamp - nowTimestamp
	if nowTimestamp > timestamp {
		diff = nowTimestamp - timestamp
	}

	if diff > uint64(MaxTimestampDiff/time.Second) {
		return fmt.Errorf("%w: off by %ds", ErrBadTimestamp, diff)
	}

	return nil
}
