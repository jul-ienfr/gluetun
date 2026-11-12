package source

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
)

type dnsSource struct {
	name     string
	query    string
	resolver Resolver
	timeout  time.Duration
}

// newDNS creates a DNS whoami source. The query name must answer TXT records
// containing the IP observed by the tunnel resolver.
func newDNS(name, query string, resolver Resolver,
	timeout time.Duration,
) *dnsSource {
	return &dnsSource{
		name:     name,
		query:    query,
		resolver: resolver,
		timeout:  timeout,
	}
}

func (s *dnsSource) Name() string {
	return s.name
}

func (s *dnsSource) Kind() egress.Kind {
	return egress.KindDNS
}

func (s *dnsSource) Fetch(ctx context.Context, _ int) (
	observation egress.Observation, err error,
) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	start := time.Now()
	observation = egress.Observation{
		Source:     s.name,
		Kind:       egress.KindDNS,
		ObservedAt: start.UTC(),
	}

	records, err := s.resolver.LookupTXT(ctx, s.query)
	observation.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return observation, fmt.Errorf("%w: %w", ErrTimeout, err)
		}
		return observation, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(records) == 0 {
		return observation, ErrEmpty
	}

	for _, record := range records {
		ip, parseErr := parseIP(record)
		if parseErr == nil {
			observation.IP = ip
			return observation, nil
		}
	}
	return observation, fmt.Errorf("%w: no IP in TXT records %q",
		ErrMalformed, strings.Join(records, ","))
}
