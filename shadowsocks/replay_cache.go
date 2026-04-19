package shadowsocks

import (
	"sync"
	"time"
)

// ReplayCache stores recently seen TCP salts for replay protection.
type ReplayCache struct {
	mu    sync.Mutex
	items map[string]time.Time
}

// NewReplayCache creates a new replay cache.
func NewReplayCache() *ReplayCache {
	return &ReplayCache{
		items: make(map[string]time.Time),
	}
}

// Seen reports whether salt is already present and not expired.
func (c *ReplayCache) Seen(salt []byte, now time.Time) bool {
	if c == nil {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.purgeExpiredLocked(now)

	expiry, ok := c.items[string(salt)]
	if !ok {
		return false
	}
	if !expiry.After(now) {
		delete(c.items, string(salt))
		return false
	}

	return true
}

// Add stores salt until now+ttl.
func (c *ReplayCache) Add(salt []byte, now time.Time, ttl time.Duration) {
	if c == nil || len(salt) == 0 || ttl <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.purgeExpiredLocked(now)
	c.items[string(salt)] = now.Add(ttl)
}

// SeenOrAdd reports whether salt is already present and not expired.
// If not present, it stores the salt until now+ttl and returns false.
func (c *ReplayCache) SeenOrAdd(salt []byte, now time.Time, ttl time.Duration) bool {
	if c == nil || len(salt) == 0 || ttl <= 0 {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.purgeExpiredLocked(now)

	key := string(salt)
	expiry, ok := c.items[key]
	if ok && expiry.After(now) {
		return true
	}

	c.items[key] = now.Add(ttl)
	return false
}

// Remove deletes a salt from the cache.
func (c *ReplayCache) Remove(salt []byte) {
	if c == nil || len(salt) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, string(salt))
}

// PurgeExpired removes expired entries.
func (c *ReplayCache) PurgeExpired(now time.Time) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.purgeExpiredLocked(now)
}

// Len returns the number of currently stored entries after purging expired ones.
func (c *ReplayCache) Len(now time.Time) int {
	if c == nil {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.purgeExpiredLocked(now)
	return len(c.items)
}

func (c *ReplayCache) purgeExpiredLocked(now time.Time) {
	for k, expiry := range c.items {
		if !expiry.After(now) {
			delete(c.items, k)
		}
	}
}
