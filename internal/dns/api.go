package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/dns/ladder"
)

// ErrDNSLadderDisabled is returned when the DNS ladder is disabled.
var ErrDNSLadderDisabled = errors.New("DNS ladder is disabled")

// DNSState returns the current ladder state.
func (l *Loop) DNSState() (snapshot ladder.Snapshot, available bool) {
	if l.resolver == nil {
		return ladder.Snapshot{}, false
	}
	return l.resolver.Snapshot(), true
}

// DNSProbe runs one explicit probe through the requested tier.
func (l *Loop) DNSProbe(ctx context.Context, tier, domain string,
	timeout time.Duration, dryRun bool,
) (result ladder.ProbeResult, err error) {
	if l.resolver == nil {
		return ladder.ProbeResult{}, ErrDNSLadderDisabled
	}

	tierType := ladder.TierType(strings.ToLower(strings.TrimSpace(tier)))
	if !tierType.Valid() {
		return ladder.ProbeResult{}, fmt.Errorf("%w: %s",
			ladder.ErrUnknownTier, tier)
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	return l.resolver.Probe(ctx, tierType, domain, dryRun)
}
