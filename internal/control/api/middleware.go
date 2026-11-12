package api

import (
	"bytes"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const switchRateWindow = time.Minute

// rateLimiter is a fixed-window limiter: at most limit events are allowed in
// any sliding window of the configured duration.
type rateLimiter struct {
	mutex  sync.Mutex
	hits   []time.Time
	limit  int
	window time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:  limit,
		window: window,
	}
}

// Allow records an event when the limit is not reached and reports how long the
// caller should wait otherwise.
func (l *rateLimiter) Allow(now time.Time) (allowed bool, retryAfter time.Duration) {
	if l == nil || l.limit <= 0 {
		return true, 0
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()

	cutoff := now.Add(-l.window)
	first := 0
	for first < len(l.hits) && !l.hits[first].After(cutoff) {
		first++
	}
	l.hits = l.hits[first:]

	if len(l.hits) >= l.limit {
		retryAfter = l.hits[0].Add(l.window).Sub(now)
		if retryAfter < 0 {
			retryAfter = 0
		}
		return false, retryAfter
	}

	l.hits = append(l.hits, now)
	return true, 0
}

// enforceLimits applies the request body and switch rate limits. It returns
// false when a response has already been written.
func (h *Handler) enforceLimits(w http.ResponseWriter, r *http.Request,
	path string,
) bool {
	if isSwitchRoute(r.Method, path) {
		allowed, retryAfter := h.switchLimiter.Allow(h.now())
		if !allowed {
			seconds := int(math.Ceil(retryAfter.Seconds()))
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			writeError(w, http.StatusTooManyRequests, CodeRateLimited,
				"switch rate limit exceeded",
				map[string]any{"retry_after_s": seconds}, nil)
			return false
		}
	}

	return enforceBodyLimit(w, r)
}

func isSwitchRoute(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	return path == "/vpn/switch" || path == "/vpn/rotate"
}

func enforceBodyLimit(w http.ResponseWriter, r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return true
	}
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}

	if r.ContentLength > maxBodyBytes {
		writePayloadTooLarge(w)
		return false
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"reading request body", nil, nil)
		return false
	}
	if len(body) > maxBodyBytes {
		writePayloadTooLarge(w)
		return false
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	return true
}

func writePayloadTooLarge(w http.ResponseWriter) {
	writeError(w, http.StatusRequestEntityTooLarge, CodePayloadTooLarge,
		"request body exceeds 1 MiB",
		map[string]any{"max_body_bytes": maxBodyBytes}, nil)
}
