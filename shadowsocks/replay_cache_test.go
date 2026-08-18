package shadowsocks_test

import (
	"testing"
	"time"

	"github.com/33TU/socks/shadowsocks"
)

func TestNewReplayCache(t *testing.T) {
	t.Parallel()

	c := shadowsocks.NewReplayCache()
	if c == nil {
		t.Fatal("NewReplayCache() returned nil")
	}
	if got := c.Len(time.Now()); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}
}

func TestReplayCache_SeenAndAdd(t *testing.T) {
	t.Parallel()

	c := shadowsocks.NewReplayCache()
	now := time.Unix(1700000000, 0)
	salt := []byte("salt1")

	if c.Seen(salt, now) {
		t.Fatal("Seen() = true before Add, want false")
	}

	c.Add(salt, now, time.Minute)

	if !c.Seen(salt, now) {
		t.Fatal("Seen() = false after Add, want true")
	}

	if got := c.Len(now); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
}

func TestReplayCache_SeenOrAdd(t *testing.T) {
	t.Parallel()

	c := shadowsocks.NewReplayCache()
	now := time.Unix(1700000000, 0)
	salt := []byte("salt1")

	if got := c.SeenOrAdd(salt, now, time.Minute); got {
		t.Fatal("SeenOrAdd() first call = true, want false")
	}

	if got := c.SeenOrAdd(salt, now, time.Minute); !got {
		t.Fatal("SeenOrAdd() second call = false, want true")
	}

	if got := c.Len(now); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
}

func TestReplayCache_Expiry(t *testing.T) {
	t.Parallel()

	c := shadowsocks.NewReplayCache()
	now := time.Unix(1700000000, 0)
	salt := []byte("salt1")

	c.Add(salt, now, time.Minute)

	if !c.Seen(salt, now.Add(30*time.Second)) {
		t.Fatal("Seen() before expiry = false, want true")
	}

	if c.Seen(salt, now.Add(61*time.Second)) {
		t.Fatal("Seen() after expiry = true, want false")
	}

	if got := c.Len(now.Add(61 * time.Second)); got != 0 {
		t.Fatalf("Len() after expiry = %d, want 0", got)
	}
}

func TestReplayCache_Remove(t *testing.T) {
	t.Parallel()

	c := shadowsocks.NewReplayCache()
	now := time.Unix(1700000000, 0)
	salt := []byte("salt1")

	c.Add(salt, now, time.Minute)
	c.Remove(salt)

	if c.Seen(salt, now) {
		t.Fatal("Seen() after Remove = true, want false")
	}

	if got := c.Len(now); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}
}

func TestReplayCache_PurgeExpired(t *testing.T) {
	t.Parallel()

	c := shadowsocks.NewReplayCache()
	now := time.Unix(1700000000, 0)

	c.Add([]byte("salt1"), now, time.Minute)
	c.Add([]byte("salt2"), now, 2*time.Minute)

	c.PurgeExpired(now.Add(90 * time.Second))

	if got := c.Len(now.Add(90 * time.Second)); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}

	if c.Seen([]byte("salt1"), now.Add(90*time.Second)) {
		t.Fatal("salt1 still present after expiry")
	}
	if !c.Seen([]byte("salt2"), now.Add(90*time.Second)) {
		t.Fatal("salt2 missing before expiry")
	}
}

func TestReplayCache_NilCache(t *testing.T) {
	t.Parallel()

	var c *shadowsocks.ReplayCache
	now := time.Unix(1700000000, 0)
	salt := []byte("salt1")

	if c.Seen(salt, now) {
		t.Fatal("Seen() on nil cache = true, want false")
	}
	if got := c.SeenOrAdd(salt, now, time.Minute); got {
		t.Fatal("SeenOrAdd() on nil cache = true, want false")
	}

	c.Add(salt, now, time.Minute)
	c.Remove(salt)
	c.PurgeExpired(now)

	if got := c.Len(now); got != 0 {
		t.Fatalf("Len() on nil cache = %d, want 0", got)
	}
}

func TestReplayCache_EmptySaltOrNonPositiveTTL(t *testing.T) {
	t.Parallel()

	c := shadowsocks.NewReplayCache()
	now := time.Unix(1700000000, 0)

	c.Add(nil, now, time.Minute)
	c.Add([]byte{}, now, time.Minute)
	c.Add([]byte("salt1"), now, 0)
	c.Add([]byte("salt2"), now, -time.Second)

	if got := c.Len(now); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}

	if got := c.SeenOrAdd(nil, now, time.Minute); got {
		t.Fatal("SeenOrAdd(nil) = true, want false")
	}
	if got := c.SeenOrAdd([]byte{}, now, time.Minute); got {
		t.Fatal("SeenOrAdd(empty) = true, want false")
	}
	if got := c.SeenOrAdd([]byte("salt1"), now, 0); got {
		t.Fatal("SeenOrAdd(ttl=0) = true, want false")
	}
	if got := c.SeenOrAdd([]byte("salt2"), now, -time.Second); got {
		t.Fatal("SeenOrAdd(ttl<0) = true, want false")
	}
}

func TestReplayCache_SeenOrAdd_ReaddsExpired(t *testing.T) {
	t.Parallel()

	c := shadowsocks.NewReplayCache()
	now := time.Unix(1700000000, 0)
	salt := []byte("salt1")

	if got := c.SeenOrAdd(salt, now, time.Minute); got {
		t.Fatal("SeenOrAdd() first call = true, want false")
	}

	if got := c.SeenOrAdd(salt, now.Add(61*time.Second), time.Minute); got {
		t.Fatal("SeenOrAdd() after expiry = true, want false")
	}

	if got := c.Len(now.Add(61 * time.Second)); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
}
