package shadowsocks_test

import (
	"errors"
	"testing"
	"time"

	"github.com/33TU/socks/shadowsocks"
)

func TestValidateTimestamp(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name    string
		offset  time.Duration
		wantErr bool
	}{
		{"exact", 0, false},
		{"just behind", -29 * time.Second, false},
		{"just ahead", 29 * time.Second, false},
		{"on the window edge behind", -30 * time.Second, false},
		{"on the window edge ahead", 30 * time.Second, false},
		{"too far behind", -31 * time.Second, true},
		{"too far ahead", 31 * time.Second, true},
		{"hours behind", -3 * time.Hour, true},
		{"hours ahead", 3 * time.Hour, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := uint64(now.Add(tt.offset).Unix())

			err := shadowsocks.ValidateTimestamp(ts, now)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ValidateTimestamp(%d) = nil, want error", ts)
				}
				if !errors.Is(err, shadowsocks.ErrBadTimestamp) {
					t.Fatalf("error = %v, want ErrBadTimestamp", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateTimestamp(%d) error = %v", ts, err)
			}
		})
	}
}

func TestValidateTimestamp_Zero(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	if err := shadowsocks.ValidateTimestamp(0, now); err == nil {
		t.Fatal("ValidateTimestamp(0) = nil, want error")
	}
}

// TestValidateTimestamp_NoSignedOverflow guards the freshness check against
// timestamps near the top of the u64 range. Computing the difference as a
// signed integer overflows there, and negating the result wraps the value back
// inside the window, so a peer could defeat the 30 second limit entirely.
func TestValidateTimestamp_NoSignedOverflow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	timestamps := []uint64{
		1 << 63,
		1<<63 + uint64(now.Unix()),
		^uint64(0),
		^uint64(0) - 30,
	}

	for _, ts := range timestamps {
		if err := shadowsocks.ValidateTimestamp(ts, now); err == nil {
			t.Errorf("ValidateTimestamp(%#x) = nil, want error", ts)
		}
	}
}
