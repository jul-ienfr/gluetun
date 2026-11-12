package verify

import (
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
)

type cache struct {
	mutex     sync.Mutex
	entry     egress.Verification
	expiresAt time.Time
	valid     bool
}

func (c *cache) get(now time.Time) (verification egress.Verification, ok bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !c.valid || !now.Before(c.expiresAt) {
		return verification, false
	}
	return c.entry, true
}

func (c *cache) set(verification egress.Verification, now time.Time,
	ttl time.Duration,
) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if ttl <= 0 {
		c.entry = egress.Verification{}
		c.expiresAt = time.Time{}
		c.valid = false
		return
	}

	c.entry = verification
	c.expiresAt = now.Add(ttl)
	c.valid = true
}

type backoffEntry struct {
	failures int
	until    time.Time
	reason   egress.Reason
}

type backoffTracker struct {
	mutex   sync.Mutex
	entries map[string]backoffEntry
}

func newBackoffTracker() *backoffTracker {
	return &backoffTracker{entries: make(map[string]backoffEntry)}
}

func (b *backoffTracker) active(source string, now time.Time) (
	reason egress.Reason, active bool,
) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	entry, ok := b.entries[source]
	if !ok || !now.Before(entry.until) {
		return "", false
	}
	return entry.reason, true
}

func (b *backoffTracker) failure(source string, reason egress.Reason,
	now time.Time, base, maximum time.Duration,
) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	entry := b.entries[source]
	entry.failures++
	entry.reason = reason
	delay := backoffDelay(base, maximum, entry.failures)
	entry.until = now.Add(delay)
	b.entries[source] = entry
}

func (b *backoffTracker) success(source string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	delete(b.entries, source)
}

func backoffDelay(base, maximum time.Duration, failures int) time.Duration {
	delay := base
	for range failures - 1 {
		if delay >= maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}
