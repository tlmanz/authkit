package authkit

import (
	"sync"
	"time"
)

// permCache is a small TTL cache for resolved role permissions, keyed by
// "tenantID|role". It bounds how stale a live permission resolution can be:
// a role or permission change takes effect within ttl rather than only on the
// user's next login. A zero/absent cache means resolve every request.
type permCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]permEntry
	// now is injected for tests; defaults to time.Now.
	now func() time.Time
}

type permEntry struct {
	perms []string
	exp   time.Time
}

func newPermCache(ttl time.Duration) *permCache {
	return &permCache{
		ttl:     ttl,
		entries: make(map[string]permEntry),
		now:     time.Now,
	}
}

// get returns the cached permissions for key if present and unexpired.
func (c *permCache) get(key string) ([]string, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || c.now().After(e.exp) {
		return nil, false
	}
	return e.perms, true
}

// put stores perms for key with the cache's TTL. A defensive copy is kept so
// callers cannot mutate cached state.
func (c *permCache) put(key string, perms []string) {
	cp := make([]string, len(perms))
	copy(cp, perms)
	c.mu.Lock()
	c.entries[key] = permEntry{perms: cp, exp: c.now().Add(c.ttl)}
	c.mu.Unlock()
}
