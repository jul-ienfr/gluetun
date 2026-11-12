package ladder

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Errors returned by the DNS ladder.
var (
	ErrNoTierConfigured = errors.New("no DNS tier configured")
	ErrLadderExhausted  = errors.New("DNS ladder exhausted")
	ErrNoEndpoint       = errors.New("DNS tier has no endpoint")
)

const (
	defaultAttempts    = 1
	defaultTimeout     = 3 * time.Second
	defaultProbeDomain = "example.com"
)

// Exchanger sends one DNS request to one endpoint. tcp requests a TCP retry,
// used after a truncated UDP response.
type Exchanger interface {
	Exchange(ctx context.Context, tierType TierType, endpoint Endpoint,
		request *dns.Msg, tcp bool) (*dns.Msg, error)
}

// Settings configure the DNS ladder.
type Settings struct {
	Ladder      []TierType
	Endpoints   map[TierType][]Endpoint
	Listener    string
	Health      *Health
	Exchanger   Exchanger
	Timeout     time.Duration
	Attempts    int
	FailClosed  bool
	ProbeDomain string
	Now         func() time.Time
}

// Ladder resolves DNS requests through ordered tiers and endpoints.
type Ladder struct {
	mutex       sync.Mutex
	tiers       []Tier
	health      *Health
	exchanger   Exchanger
	timeout     time.Duration
	attempts    int
	failClosed  bool
	probeDomain string
	now         func() time.Time
}

// New validates the settings and builds the DNS ladder.
func New(settings Settings) (*Ladder, error) {
	if settings.Exchanger == nil {
		return nil, errors.New("DNS ladder exchanger is nil")
	}

	ladderTypes := make([]TierType, 0, len(settings.Ladder))
	for _, tierType := range settings.Ladder {
		if !tierType.Valid() {
			return nil, fmt.Errorf("unknown DNS tier %q", tierType)
		}
		if slices.Contains(ladderTypes, tierType) {
			continue
		}
		ladderTypes = append(ladderTypes, tierType)
	}
	if len(ladderTypes) == 0 {
		return nil, ErrNoTierConfigured
	}

	tiers := make([]Tier, 0, len(ladderTypes))
	for _, tierType := range ladderTypes {
		endpoints := settings.Endpoints[tierType]
		for index := range endpoints {
			if !endpoints[index].State.Valid() ||
				endpoints[index].State == StateStandby {
				endpoints[index].State = StateUp
			}
		}
		tier := NewTier(tierType, settings.Listener, endpoints)
		if len(tier.Endpoints) == 0 {
			tier.State = StateDown
		} else {
			tier.State = StateUp
		}
		tiers = append(tiers, tier)
	}

	health := settings.Health
	if health == nil {
		now := settings.Now
		health = NewHealth(HealthSettings{Now: now})
	}
	timeout := settings.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	attempts := settings.Attempts
	if attempts <= 0 {
		attempts = defaultAttempts
	}
	now := settings.Now
	if now == nil {
		now = time.Now
	}
	probeDomain := settings.ProbeDomain
	if probeDomain == "" {
		probeDomain = defaultProbeDomain
	}

	return &Ladder{
		tiers:       tiers,
		health:      health,
		exchanger:   settings.Exchanger,
		timeout:     timeout,
		attempts:    attempts,
		failClosed:  settings.FailClosed,
		probeDomain: probeDomain,
		now:         now,
	}, nil
}

type tierCandidate struct {
	tierIndex int
	endpoints []int
}

// Resolve answers one DNS request, falling back through the ladder. NXDOMAIN is
// a valid terminal answer and does not trigger a fallback.
func (l *Ladder) Resolve(ctx context.Context,
	request *dns.Msg,
) (response *dns.Msg, err error) {
	if request == nil {
		return nil, errors.New("DNS request is nil")
	}

	var lastErr error
	for _, candidate := range l.candidates() {
		for _, endpointIndex := range candidate.endpoints {
			endpoint := l.endpoint(candidate.tierIndex, endpointIndex)

			started := l.now()
			tierResponse, endpointErr := l.exchangeEndpoint(ctx,
				l.tierType(candidate.tierIndex), endpoint, request)
			latency := l.now().Sub(started)
			if endpointErr == nil {
				l.observeSuccess(candidate.tierIndex, endpointIndex, latency)
				return tierResponse, nil
			}
			l.observeFailure(candidate.tierIndex, endpointIndex, endpointErr)
			lastErr = endpointErr
		}
	}

	if lastErr == nil {
		lastErr = ErrLadderExhausted
	}
	return nil, fmt.Errorf("%w: %w", ErrLadderExhausted, lastErr)
}

func (l *Ladder) exchangeEndpoint(ctx context.Context, tierType TierType,
	endpoint Endpoint, request *dns.Msg,
) (*dns.Msg, error) {
	var lastErr error
	for attempt := 0; attempt < l.attempts; attempt++ {
		response, err := l.exchangeOnce(ctx, tierType, endpoint, request, false)
		if err != nil {
			lastErr = err
			continue
		}
		if !response.Truncated {
			return response, nil
		}

		response, err = l.exchangeOnce(ctx, tierType, endpoint, request, true)
		if err != nil {
			lastErr = err
			continue
		}
		return response, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no DNS response")
	}
	return nil, lastErr
}

func (l *Ladder) exchangeOnce(ctx context.Context, tierType TierType,
	endpoint Endpoint, request *dns.Msg, tcp bool,
) (*dns.Msg, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()

	response, err := l.exchanger.Exchange(attemptCtx, tierType, endpoint,
		request.Copy(), tcp)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("empty DNS response")
	}
	switch response.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		return response, nil
	default:
		code, ok := dns.RcodeToString[response.Rcode]
		if !ok {
			code = fmt.Sprint(response.Rcode)
		}
		return nil, fmt.Errorf("DNS response code %s", code)
	}
}

// candidates returns tier and endpoint indexes by decreasing preference: up,
// standby, then degraded. Down tiers are skipped until their cooldown expires.
func (l *Ladder) candidates() (candidates []tierCandidate) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	now := l.now()
	groups := [3][]tierCandidate{}
	for tierIndex := range l.tiers {
		tier := &l.tiers[tierIndex]
		l.health.Refresh(tier)

		endpoints := l.availableEndpoints(tier, now)
		if len(endpoints) == 0 {
			continue
		}
		candidate := tierCandidate{tierIndex: tierIndex, endpoints: endpoints}
		switch tier.State {
		case StateUp:
			groups[0] = append(groups[0], candidate)
		case StateStandby:
			groups[1] = append(groups[1], candidate)
		case StateDegraded:
			if tier.CooldownUntil == nil || !now.Before(*tier.CooldownUntil) {
				groups[2] = append(groups[2], candidate)
			}
		}
	}
	for _, group := range groups {
		candidates = append(candidates, group...)
	}
	return candidates
}

func (l *Ladder) availableEndpoints(tier *Tier, now time.Time) (indexes []int) {
	for index := range tier.Endpoints {
		if tier.Endpoints[index].Available(now) {
			indexes = append(indexes, index)
		}
	}
	return indexes
}

func (l *Ladder) endpoint(tierIndex, endpointIndex int) Endpoint {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.tiers[tierIndex].Endpoints[endpointIndex]
}

func (l *Ladder) tierType(tierIndex int) TierType {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.tiers[tierIndex].Type
}

func (l *Ladder) observeSuccess(tierIndex, endpointIndex int,
	latency time.Duration,
) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.health.Success(&l.tiers[tierIndex], endpointIndex, latency)
}

func (l *Ladder) observeFailure(tierIndex, endpointIndex int, cause error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.health.Failure(&l.tiers[tierIndex], endpointIndex, cause)
}

// Tiers returns a deep copy of the ladder tiers.
func (l *Ladder) Tiers() []Tier {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	tiers := make([]Tier, len(l.tiers))
	for index, tier := range l.tiers {
		tiers[index] = copyTier(tier)
	}
	return tiers
}

// ActiveTier returns the first up tier, or an empty type when none is up.
func (l *Ladder) ActiveTier() TierType {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	for index := range l.tiers {
		if l.tiers[index].State == StateUp {
			return l.tiers[index].Type
		}
	}
	return ""
}

// FailClosed reports whether every tier is down.
func (l *Ladder) FailClosed() bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	for index := range l.tiers {
		if l.tiers[index].State != StateDown {
			return false
		}
	}
	return true
}

func copyTier(tier Tier) Tier {
	copied := tier
	if tier.CooldownUntil != nil {
		cooldown := *tier.CooldownUntil
		copied.CooldownUntil = &cooldown
	}
	if tier.LastError != nil {
		message := *tier.LastError
		copied.LastError = &message
	}
	copied.Endpoints = make([]Endpoint, len(tier.Endpoints))
	for index, endpoint := range tier.Endpoints {
		copied.Endpoints[index] = endpoint
		if endpoint.CooldownUntil != nil {
			cooldown := *endpoint.CooldownUntil
			copied.Endpoints[index].CooldownUntil = &cooldown
		}
		if endpoint.LastError != nil {
			message := *endpoint.LastError
			copied.Endpoints[index].LastError = &message
		}
	}
	return copied
}
