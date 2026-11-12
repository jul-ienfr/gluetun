package ladder

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// ErrUnknownTier is returned when a probe targets a tier absent from the
// configured ladder.
var ErrUnknownTier = errors.New("unknown DNS tier")

// ProbeResult is the outcome of one explicit DNS probe.
type ProbeResult struct {
	Tier      TierType `json:"tier"`
	OK        bool     `json:"ok"`
	LatencyMS int64    `json:"latency_ms"`
	Rcode     string   `json:"rcode,omitempty"`
	Answers   int      `json:"answers"`
	Error     string   `json:"error,omitempty"`
}

// Probe sends one A query for the domain through the requested tier. When
// dryRun is true the health state is left untouched.
func (l *Ladder) Probe(ctx context.Context, tierType TierType, domain string,
	dryRun bool,
) (result ProbeResult, err error) {
	result.Tier = tierType

	if domain == "" {
		domain = l.probeDomain
	}
	if _, ok := dns.IsDomainName(domain); !ok {
		return result, fmt.Errorf("invalid probe domain %q", domain)
	}

	tierIndex := l.tierIndex(tierType)
	if tierIndex < 0 {
		return result, fmt.Errorf("%w: %s", ErrUnknownTier, tierType)
	}
	endpoints := l.endpoints(tierIndex)
	if len(endpoints) == 0 {
		return result, fmt.Errorf("%w: %s", ErrNoEndpoint, tierType)
	}

	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	var lastErr error
	for endpointIndex := range endpoints {
		endpoint := endpoints[endpointIndex]
		started := l.now()
		response, exchangeErr := l.exchangeEndpoint(ctx, tierType, endpoint,
			request)
		latency := l.now().Sub(started)
		if exchangeErr != nil {
			lastErr = exchangeErr
			if !dryRun {
				l.observeFailure(tierIndex, endpointIndex, exchangeErr)
			}
			continue
		}

		if !dryRun {
			l.observeSuccess(tierIndex, endpointIndex, latency)
		}
		result.OK = true
		result.LatencyMS = latency.Milliseconds()
		result.Rcode = dns.RcodeToString[response.Rcode]
		result.Answers = len(response.Answer)
		return result, nil
	}

	if lastErr == nil {
		lastErr = errors.New("probe failed")
	}
	result.Error = lastErr.Error()
	return result, nil
}

func (l *Ladder) tierIndex(tierType TierType) int {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	for index := range l.tiers {
		if l.tiers[index].Type == tierType {
			return index
		}
	}
	return -1
}

func (l *Ladder) endpoints(tierIndex int) []Endpoint {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	return append([]Endpoint(nil), l.tiers[tierIndex].Endpoints...)
}

// ProbeDomain returns the default probe domain.
func (l *Ladder) ProbeDomain() string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.probeDomain
}
