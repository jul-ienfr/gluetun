package jobs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultIdempotencyWindow is the documented retention of request keys.
const DefaultIdempotencyWindow = 24 * time.Hour

const maxIdempotencyKeyLength = 128

// Idempotency errors.
var (
	ErrIdempotencyConflict   = errors.New("idempotency conflict")
	ErrInvalidIdempotencyKey = errors.New("invalid idempotency key")
)

type idempotencyEntry struct {
	hash     string
	jobID    string
	storedAt time.Time
}

// Idempotency maps request keys to job IDs for a bounded window.
type Idempotency struct {
	window  time.Duration
	now     func() time.Time
	mutex   sync.Mutex
	entries map[string]idempotencyEntry
}

// NewIdempotency creates an idempotency index.
func NewIdempotency(window time.Duration, now func() time.Time) *Idempotency {
	if window <= 0 {
		panic("idempotency window must be positive")
	}
	if now == nil {
		now = time.Now
	}
	return &Idempotency{
		window:  window,
		now:     now,
		entries: make(map[string]idempotencyEntry),
	}
}

// HashBody returns the SHA-256 hexadecimal digest of a request body.
func HashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Reserve records a key for a job or returns the job already recorded for the
// same key and body hash. A different body for the same key is a conflict.
func (i *Idempotency) Reserve(key, hash, jobID string) (existingJobID string,
	err error,
) {
	err = validateIdempotencyKey(key)
	if err != nil {
		return "", err
	}
	if hash == "" {
		return "", fmt.Errorf("%w: body hash is empty",
			ErrInvalidIdempotencyKey)
	}
	if jobID == "" {
		return "", fmt.Errorf("%w: job ID is empty", ErrInvalidIdempotencyKey)
	}

	i.mutex.Lock()
	defer i.mutex.Unlock()

	now := i.now().UTC()
	i.purgeLocked(now)

	entry, found := i.entries[key]
	if found {
		if entry.hash != hash {
			return "", fmt.Errorf("%w: key %q was used with another body",
				ErrIdempotencyConflict, key)
		}
		return entry.jobID, nil
	}

	i.entries[key] = idempotencyEntry{
		hash:     hash,
		jobID:    jobID,
		storedAt: now,
	}
	return "", nil
}

// LookupRequest returns the job recorded for a key and body hash. A key
// recorded with another body is a conflict.
func (i *Idempotency) LookupRequest(key, hash string) (jobID string,
	found bool, err error,
) {
	err = validateIdempotencyKey(key)
	if err != nil {
		return "", false, err
	}

	i.mutex.Lock()
	defer i.mutex.Unlock()

	i.purgeLocked(i.now().UTC())
	entry, found := i.entries[key]
	if !found {
		return "", false, nil
	}
	if entry.hash != hash {
		return "", false, fmt.Errorf("%w: key %q was used with another body",
			ErrIdempotencyConflict, key)
	}
	return entry.jobID, true, nil
}

// Lookup returns the job recorded for a key, if the entry is still alive.
func (i *Idempotency) Lookup(key string) (jobID string, found bool) {
	err := validateIdempotencyKey(key)
	if err != nil {
		return "", false
	}

	i.mutex.Lock()
	defer i.mutex.Unlock()

	i.purgeLocked(i.now().UTC())
	entry, found := i.entries[key]
	if !found {
		return "", false
	}
	return entry.jobID, true
}

// Forget removes a key, typically when the job could not be created.
func (i *Idempotency) Forget(key string) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	delete(i.entries, key)
}

// Len returns the number of live entries.
func (i *Idempotency) Len() int {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.purgeLocked(i.now().UTC())
	return len(i.entries)
}

func (i *Idempotency) purgeLocked(now time.Time) {
	for key, entry := range i.entries {
		if now.Sub(entry.storedAt) > i.window {
			delete(i.entries, key)
		}
	}
}

func validateIdempotencyKey(key string) error {
	switch {
	case key == "":
		return fmt.Errorf("%w: key is empty", ErrInvalidIdempotencyKey)
	case len(key) > maxIdempotencyKeyLength:
		return fmt.Errorf("%w: key exceeds %d characters",
			ErrInvalidIdempotencyKey, maxIdempotencyKeyLength)
	}
	return nil
}
