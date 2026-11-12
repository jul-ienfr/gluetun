package ladder

import "time"

// Snapshot is the public state of the DNS ladder.
type Snapshot struct {
	Ladder     []TierType `json:"ladder"`
	ActiveTier TierType   `json:"active_tier"`
	FailClosed bool       `json:"fail_closed"`
	Tiers      []Tier     `json:"tiers"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// Snapshot returns a consistent view of the ladder state.
func (l *Ladder) Snapshot() Snapshot {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	ladder := make([]TierType, len(l.tiers))
	tiers := make([]Tier, len(l.tiers))
	for index := range l.tiers {
		l.health.Refresh(&l.tiers[index])
		ladder[index] = l.tiers[index].Type
		tiers[index] = copyTier(l.tiers[index])
	}

	activeTier := TierType("")
	for index := range l.tiers {
		if l.tiers[index].State == StateUp {
			activeTier = l.tiers[index].Type
			break
		}
	}

	return Snapshot{
		Ladder:     ladder,
		ActiveTier: activeTier,
		FailClosed: l.failClosed,
		Tiers:      tiers,
		UpdatedAt:  l.now().UTC(),
	}
}
