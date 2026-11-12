package verify

import (
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/stretchr/testify/assert"
)

func Test_cache(t *testing.T) {
	t.Parallel()

	var cache cache
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	verification := egress.Verification{Verified: true, VerifiedAt: now}

	_, ok := cache.get(now)
	assert.False(t, ok)

	cache.set(verification, now, 10*time.Second)
	stored, ok := cache.get(now.Add(5 * time.Second))
	assert.True(t, ok)
	assert.Equal(t, verification, stored)

	_, ok = cache.get(now.Add(10 * time.Second))
	assert.False(t, ok)

	cache.set(verification, now, 0)
	_, ok = cache.get(now)
	assert.False(t, ok)
}

func Test_backoffDelay(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		failures int
		expected time.Duration
	}{
		"first":  {failures: 1, expected: time.Second},
		"second": {failures: 2, expected: 2 * time.Second},
		"third":  {failures: 3, expected: 4 * time.Second},
		"capped": {failures: 10, expected: 8 * time.Second},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			delay := backoffDelay(time.Second, 8*time.Second, testCase.failures)
			assert.Equal(t, testCase.expected, delay)
		})
	}
}

func Test_backoffTracker(t *testing.T) {
	t.Parallel()

	tracker := newBackoffTracker()
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

	_, active := tracker.active("http:a", now)
	assert.False(t, active)

	tracker.failure("http:a", egress.ReasonBanned, now, time.Second, 8*time.Second)
	reason, active := tracker.active("http:a", now)
	assert.True(t, active)
	assert.Equal(t, egress.ReasonBanned, reason)

	_, active = tracker.active("http:a", now.Add(2*time.Second))
	assert.False(t, active)

	tracker.success("http:a")
	_, active = tracker.active("http:a", now)
	assert.False(t, active)
}
