package jobs

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func Test_HashBody(t *testing.T) {
	t.Parallel()

	first := HashBody([]byte(`{"a":1}`))
	second := HashBody([]byte(`{"a":1}`))
	other := HashBody([]byte(`{"a":2}`))

	if first != second {
		t.Errorf("same body hashes differ: %q != %q", first, second)
	}
	if first == other {
		t.Errorf("different bodies share hash %q", first)
	}
	if len(first) != 64 {
		t.Errorf("hash length is %d, want 64", len(first))
	}
}

func Test_Idempotency_Reserve(t *testing.T) {
	t.Parallel()

	type reserveResult struct {
		existing string
		err      error
	}

	hash := HashBody([]byte("body"))

	testCases := map[string]struct {
		reserves []struct {
			key   string
			hash  string
			jobID string
		}
		expected []reserveResult
	}{
		"first reservation wins": {
			reserves: []struct {
				key   string
				hash  string
				jobID string
			}{
				{key: "switch-1", hash: hash, jobID: "job-1"},
			},
			expected: []reserveResult{{existing: "", err: nil}},
		},
		"same key same body replays": {
			reserves: []struct {
				key   string
				hash  string
				jobID string
			}{
				{key: "switch-1", hash: hash, jobID: "job-1"},
				{key: "switch-1", hash: hash, jobID: "job-2"},
			},
			expected: []reserveResult{
				{existing: "", err: nil},
				{existing: "job-1", err: nil},
			},
		},
		"same key different body conflicts": {
			reserves: []struct {
				key   string
				hash  string
				jobID string
			}{
				{key: "switch-1", hash: hash, jobID: "job-1"},
				{key: "switch-1", hash: HashBody([]byte("other")), jobID: "job-2"},
			},
			expected: []reserveResult{
				{existing: "", err: nil},
				{existing: "", err: ErrIdempotencyConflict},
			},
		},
		"distinct keys are independent": {
			reserves: []struct {
				key   string
				hash  string
				jobID string
			}{
				{key: "switch-1", hash: hash, jobID: "job-1"},
				{key: "switch-2", hash: hash, jobID: "job-2"},
			},
			expected: []reserveResult{
				{existing: "", err: nil},
				{existing: "", err: nil},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			index := NewIdempotency(time.Hour, nil)

			for reservationIndex, reservation := range testCase.reserves {
				existing, err := index.Reserve(reservation.key,
					reservation.hash, reservation.jobID)
				expected := testCase.expected[reservationIndex]

				if !errors.Is(err, expected.err) {
					t.Fatalf("reserve %d error = %v, want %v",
						reservationIndex, err, expected.err)
				}
				if existing != expected.existing {
					t.Errorf("reserve %d existing = %q, want %q",
						reservationIndex, existing, expected.existing)
				}
			}
		})
	}
}

func Test_Idempotency_Reserve_Invalid(t *testing.T) {
	t.Parallel()

	index := NewIdempotency(time.Hour, nil)
	hash := HashBody(nil)

	testCases := map[string]struct {
		key   string
		hash  string
		jobID string
	}{
		"empty key":           {key: "", hash: hash, jobID: "job-1"},
		"key too long":        {key: strings.Repeat("a", 129), hash: hash, jobID: "job-1"},
		"empty hash":          {key: "switch-1", hash: "", jobID: "job-1"},
		"empty job ID":        {key: "switch-1", hash: hash, jobID: ""},
		"key exactly maximum": {key: strings.Repeat("a", 128), hash: hash, jobID: "job-1"},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := index.Reserve(testCase.key, testCase.hash, testCase.jobID)
			if name == "key exactly maximum" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidIdempotencyKey) {
				t.Errorf("error = %v, want %v", err, ErrInvalidIdempotencyKey)
			}
		})
	}
}

func Test_Idempotency_Expiry(t *testing.T) {
	t.Parallel()

	currentTime := time.Date(2026, time.November, 12, 10, 0, 0, 0, time.UTC)
	now := func() time.Time { return currentTime }

	index := NewIdempotency(24*time.Hour, now)
	hash := HashBody([]byte("body"))

	_, err := index.Reserve("switch-1", hash, "job-1")
	if err != nil {
		t.Fatalf("reserving: %v", err)
	}

	currentTime = currentTime.Add(23 * time.Hour)
	if index.Len() != 1 {
		t.Fatalf("entry expired before window: len=%d", index.Len())
	}
	jobID, found := index.Lookup("switch-1")
	if !found {
		t.Fatalf("entry not found inside the window")
	}
	if jobID != "job-1" {
		t.Errorf("job ID = %q, want job-1", jobID)
	}

	currentTime = currentTime.Add(2 * time.Hour)
	if index.Len() != 0 {
		t.Fatalf("entry kept after window: len=%d", index.Len())
	}
	_, found = index.Lookup("switch-1")
	if found {
		t.Errorf("entry still found after the window")
	}

	existing, err := index.Reserve("switch-1", HashBody([]byte("other")), "job-2")
	if err != nil {
		t.Fatalf("reserving after expiry: %v", err)
	}
	if existing != "" {
		t.Errorf("expired key replayed job %q", existing)
	}
}

func Test_Idempotency_LookupRequest(t *testing.T) {
	t.Parallel()

	index := NewIdempotency(time.Hour, nil)
	firstHash := HashBody([]byte("body"))
	secondHash := HashBody([]byte("other"))

	_, err := index.Reserve("switch-1", firstHash, "job-1")
	if err != nil {
		t.Fatalf("reserving: %v", err)
	}

	jobID, found, err := index.LookupRequest("switch-1", firstHash)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !found || jobID != "job-1" {
		t.Errorf("job ID = %q found = %t", jobID, found)
	}

	_, _, err = index.LookupRequest("switch-1", secondHash)
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Errorf("error = %v, want %v", err, ErrIdempotencyConflict)
	}

	_, found, err = index.LookupRequest("missing", firstHash)
	if err != nil || found {
		t.Errorf("missing key: found=%t err=%v", found, err)
	}
}

func Test_Idempotency_Forget(t *testing.T) {
	t.Parallel()

	index := NewIdempotency(time.Hour, nil)
	hash := HashBody([]byte("body"))

	_, err := index.Reserve("switch-1", hash, "job-1")
	if err != nil {
		t.Fatalf("reserving: %v", err)
	}

	index.Forget("switch-1")

	if index.Len() != 0 {
		t.Errorf("forget left %d entries", index.Len())
	}
	_, found := index.Lookup("switch-1")
	if found {
		t.Errorf("forget left the entry visible")
	}

	existing, err := index.Reserve("switch-1", hash, "job-2")
	if err != nil {
		t.Fatalf("reserving after forget: %v", err)
	}
	if existing != "" {
		t.Errorf("forgotten key replayed job %q", existing)
	}
}

func Test_Idempotency_Concurrent(t *testing.T) {
	t.Parallel()

	index := NewIdempotency(time.Hour, nil)
	hash := HashBody([]byte("body"))

	const workers = 32
	jobIDs := make([]string, workers)
	waitGroup := sync.WaitGroup{}
	waitGroup.Add(workers)
	for worker := range workers {
		go func() {
			defer waitGroup.Done()
			existing, err := index.Reserve("switch-1", hash,
				"job-"+strings.Repeat("x", worker+1))
			if err != nil {
				t.Errorf("worker %d: %v", worker, err)
				return
			}
			jobIDs[worker] = existing
		}()
	}
	waitGroup.Wait()

	winners := 0
	for worker, existing := range jobIDs {
		if existing == "" {
			winners++
			continue
		}
		winner, found := index.Lookup("switch-1")
		if !found {
			t.Fatalf("worker %d replayed missing job", worker)
		}
		if existing != winner {
			t.Errorf("worker %d replayed %q, want %q",
				worker, existing, winner)
		}
	}
	if winners != 1 {
		t.Errorf("%d reservations won, want exactly 1", winners)
	}
}
