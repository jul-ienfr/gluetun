package catalog

import (
	"strings"
	"sync"
	"time"
)

const (
	// DefaultCooldownBase is the first cooldown applied to a hostname after a
	// failed rotation attempt.
	DefaultCooldownBase = 30 * time.Second
	// DefaultCooldownMax caps the exponential cooldown backoff.
	DefaultCooldownMax = 5 * time.Minute
)

// CooldownOptions configure the per-hostname cooldown tracker.
type CooldownOptions struct {
	Base time.Duration
	Max  time.Duration
}

// Cooldown tracks failed rotation hostnames and their exponential backoff.
// It is local to the fork: it never feeds the global IP score.
type Cooldown struct {
	base  time.Duration
	max   time.Duration
	mutex sync.Mutex
	hosts map[string]cooldownEntry
}

type cooldownEntry struct {
	failures int
	until    time.Time
}

// NewCooldown creates a cooldown tracker.
func NewCooldown(options CooldownOptions) *Cooldown {
	base := options.Base
	if base <= 0 {
		base = DefaultCooldownBase
	}
	maxCooldown := options.Max
	if maxCooldown <= 0 {
		maxCooldown = DefaultCooldownMax
	}
	if maxCooldown < base {
		maxCooldown = base
	}
	return &Cooldown{
		base:  base,
		max:   maxCooldown,
		hosts: make(map[string]cooldownEntry),
	}
}

// Available reports whether a hostname may be attempted at the time given.
func (c *Cooldown) Available(hostname string, now time.Time) bool {
	if c == nil {
		return true
	}
	hostname = normalizeHostname(hostname)
	if hostname == "" {
		return false
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry, found := c.hosts[hostname]
	if !found {
		return true
	}
	return !now.Before(entry.until)
}

// Until returns the cooldown end of a hostname, if it is cooling down.
func (c *Cooldown) Until(hostname string) (until time.Time, cooling bool) {
	if c == nil {
		return time.Time{}, false
	}
	hostname = normalizeHostname(hostname)
	if hostname == "" {
		return time.Time{}, false
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry, found := c.hosts[hostname]
	if !found || entry.until.IsZero() {
		return time.Time{}, false
	}
	return entry.until, true
}

// RecordFailure increments the failure count and starts an exponential
// cooldown for the hostname.
func (c *Cooldown) RecordFailure(hostname string, now time.Time) (
	until time.Time,
) {
	if c == nil {
		return time.Time{}
	}
	hostname = normalizeHostname(hostname)
	if hostname == "" {
		return time.Time{}
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry := c.hosts[hostname]
	entry.failures++
	if entry.failures > 32 {
		entry.failures = 32
	}
	entry.until = now.Add(c.backoff(entry.failures))
	c.hosts[hostname] = entry
	return entry.until
}

// RecordSuccess clears any cooldown state for the hostname.
func (c *Cooldown) RecordSuccess(hostname string) {
	if c == nil {
		return
	}
	hostname = normalizeHostname(hostname)
	if hostname == "" {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.hosts, hostname)
}

func (c *Cooldown) backoff(failures int) time.Duration {
	if failures <= 1 {
		return c.base
	}
	duration := c.base
	for index := 1; index < failures; index++ {
		duration *= 2
		if duration >= c.max {
			return c.max
		}
	}
	return duration
}

func normalizeHostname(hostname string) string {
	return strings.ToLower(strings.TrimSpace(hostname))
}
