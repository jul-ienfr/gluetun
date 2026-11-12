package catalog

import "time"

// ServerStats are the consultative runtime statistics of a server.
type ServerStats struct {
	CooldownUntil *time.Time `json:"cooldown_until,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastFailureAt *time.Time `json:"last_failure_at,omitempty"`
	Successes     uint64     `json:"successes"`
	Failures      uint64     `json:"failures"`
}

// StatsProvider supplies consultative runtime statistics per hostname.
type StatsProvider interface {
	LookupStats(hostname string) ServerStats
}

// SetStatsProvider attaches an optional runtime statistics source.
func (c *Catalog) SetStatsProvider(provider StatsProvider) {
	c.stats = provider
}
