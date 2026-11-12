// Package verify orchestrates parallel egress sources, consensus and cache.
package verify

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/canary"
	"github.com/qdm12/gluetun/internal/egress/consensus"
	"github.com/qdm12/gluetun/internal/egress/source"
	"golang.org/x/sync/singleflight"
)

// ErrTimeout marks a collection that exceeded its global deadline.
var ErrTimeout = errors.New("egress verification timed out")

// ErrCanaryDisabled marks a canary check when no canary endpoint is configured.
var ErrCanaryDisabled = errors.New("egress canary is not configured")

const (
	historyLimit   = 200
	defaultTimeout = 30 * time.Second
)

// Settings are the fixed verification settings.
type Settings struct {
	Sources          []source.Source
	Options          consensus.Options
	CacheTTL         time.Duration
	Timeout          time.Duration
	SourceBackoff    time.Duration
	SourceBackoffMax time.Duration
	Canary           *canary.Checker
	Now              func() time.Time
}

// Request overrides per call.
type Request struct {
	Fresh      bool
	Quorum     int
	MinSources int
	Canary     *bool
	Timeout    time.Duration
}

// Service collects egress observations with a shared cache and single-flight.
type Service struct {
	sources          []source.Source
	options          consensus.Options
	cacheTTL         time.Duration
	timeout          time.Duration
	sourceBackoff    time.Duration
	sourceBackoffMax time.Duration
	canary           *canary.Checker
	now              func() time.Time
	group            singleflight.Group
	cache            cache
	backoff          *backoffTracker
	historyMutex     sync.Mutex
	history          []egress.Verification
}

// New creates an egress verification service.
func New(settings Settings) *Service {
	if settings.Now == nil {
		settings.Now = time.Now
	}
	if settings.Timeout <= 0 {
		settings.Timeout = defaultTimeout
	}
	return &Service{
		sources:          settings.Sources,
		options:          settings.Options,
		cacheTTL:         settings.CacheTTL,
		timeout:          settings.Timeout,
		sourceBackoff:    settings.SourceBackoff,
		sourceBackoffMax: settings.SourceBackoffMax,
		canary:           settings.Canary,
		now:              settings.Now,
		backoff:          newBackoffTracker(),
	}
}

// Verify returns a cached or fresh egress verification.
func (s *Service) Verify(ctx context.Context, request Request) (
	verification egress.Verification, err error,
) {
	now := s.now()
	if !request.Fresh {
		cached, ok := s.cache.get(now)
		if ok {
			cached.Cached = true
			return cached, nil
		}
	}

	value, err, _ := s.group.Do("verify", func() (any, error) {
		if !request.Fresh {
			cached, ok := s.cache.get(s.now())
			if ok {
				cached.Cached = true
				return cached, nil
			}
		}

		options := s.options
		if request.Quorum > 0 {
			options.Quorum = request.Quorum
		}
		if request.MinSources > 0 {
			options.MinSources = request.MinSources
		}
		timeout := s.timeout
		if request.Timeout > 0 {
			timeout = request.Timeout
		}
		canaryEnabled := s.canary != nil && s.canary.Enabled()
		if request.Canary != nil {
			canaryEnabled = canaryEnabled && *request.Canary
		}

		collected, err := s.collect(ctx, options, canaryEnabled, timeout)
		if err != nil {
			return egress.Verification{}, err
		}

		at := s.now()
		if collected.VerifiedAt.IsZero() {
			collected.VerifiedAt = at.UTC()
		}
		collected.TTLS = s.cacheTTLSeconds()
		s.cache.set(collected, at, s.cacheTTL)
		s.addHistory(collected)
		return collected, nil
	})
	if err != nil {
		return egress.Verification{}, err
	}

	verification, ok := value.(egress.Verification)
	if !ok {
		panic("singleflight returned a non verification value")
	}
	return verification, nil
}

// CheckCanary runs the neutral canary once, without caching.
func (s *Service) CheckCanary(ctx context.Context) (
	result egress.CanaryResult, err error,
) {
	if s.canary == nil || !s.canary.Enabled() {
		return egress.CanaryResult{}, ErrCanaryDisabled
	}
	return s.canary.Check(ctx), nil
}

func (s *Service) cacheTTLSeconds() int {
	return int(s.cacheTTL / time.Second)
}

func (s *Service) collect(ctx context.Context, options consensus.Options,
	canaryEnabled bool, timeout time.Duration,
) (verification egress.Verification, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	now := s.now()
	type outcome struct {
		index       int
		observation egress.Observation
		err         error
	}
	outcomes := make(chan outcome, len(s.sources))

	for index, egressSource := range s.sources {
		reason, backingOff := s.backoff.active(egressSource.Name(), now)
		if backingOff {
			outcomes <- outcome{
				index: index,
				observation: egress.Observation{
					Source:     egressSource.Name(),
					Kind:       egressSource.Kind(),
					ObservedAt: now.UTC(),
					Error: &egress.SourceError{
						Reason:  reason,
						Message: "source in backoff",
					},
				},
			}
			continue
		}

		go func() {
			observation, fetchErr := egressSource.Fetch(ctx, options.Family)
			outcomes <- outcome{
				index:       index,
				observation: observation,
				err:         fetchErr,
			}
		}()
	}

	observations := make([]egress.Observation, len(s.sources))
	for range s.sources {
		result := <-outcomes
		observation := result.observation
		if result.err != nil {
			sourceErr := classify(result.err)
			observation = egress.Observation{
				Source:     s.sources[result.index].Name(),
				Kind:       s.sources[result.index].Kind(),
				ObservedAt: now.UTC(),
				Error:      &sourceErr,
			}
			s.backoff.failure(observation.Source, sourceErr.Reason, now,
				s.sourceBackoff, s.sourceBackoffMax)
		} else {
			s.backoff.success(observation.Source)
		}
		observations[result.index] = observation
	}

	if ctx.Err() != nil {
		return verification, ErrTimeout
	}

	verification = consensus.Evaluate(observations, options, now)
	if !verification.Verified || !canaryEnabled {
		return verification, nil
	}

	result := s.canary.Check(ctx)
	verification.Canary = &result
	if !result.OK {
		verification.Verified = false
		reason := egress.ReasonCanaryFailed
		verification.Reason = &reason
	}
	return verification, nil
}

// History returns stored verifications, newest first.
func (s *Service) History(limit int, since time.Time) (
	verifications []egress.Verification,
) {
	if limit <= 0 {
		limit = historyLimit
	}
	verifications = make([]egress.Verification, 0, limit)

	s.historyMutex.Lock()
	defer s.historyMutex.Unlock()

	for index := len(s.history) - 1; index >= 0 && len(verifications) < limit; index-- {
		verification := s.history[index]
		if !since.IsZero() && verification.VerifiedAt.Before(since) {
			continue
		}
		verifications = append(verifications, verification)
	}
	return verifications
}

func (s *Service) addHistory(verification egress.Verification) {
	s.historyMutex.Lock()
	defer s.historyMutex.Unlock()

	s.history = append(s.history, verification)
	if len(s.history) > historyLimit {
		s.history = s.history[len(s.history)-historyLimit:]
	}
}

func classify(err error) (sourceErr egress.SourceError) {
	sourceErr.Message = err.Error()
	switch {
	case errors.Is(err, source.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		sourceErr.Reason = egress.ReasonTimeout
	case errors.Is(err, source.ErrHTTPStatus):
		sourceErr.Reason = egress.ReasonHTTPStatus
	case errors.Is(err, source.ErrMalformed):
		sourceErr.Reason = egress.ReasonMalformed
	case errors.Is(err, source.ErrEmpty):
		sourceErr.Reason = egress.ReasonEmpty
	case errors.Is(err, source.ErrBanned):
		sourceErr.Reason = egress.ReasonBanned
	default:
		sourceErr.Reason = egress.ReasonTransport
	}
	return sourceErr
}
