package source

import "errors"

var (
	// ErrTimeout marks a source whose deadline expired.
	ErrTimeout = errors.New("source timed out")
	// ErrHTTPStatus marks an unexpected HTTP status.
	ErrHTTPStatus = errors.New("unexpected HTTP status")
	// ErrMalformed marks a response that cannot be parsed as an IP.
	ErrMalformed = errors.New("malformed source response")
	// ErrEmpty marks a source that returned no value.
	ErrEmpty = errors.New("empty source response")
	// ErrBanned marks a source asking us to back off.
	ErrBanned = errors.New("source is banned")
)
