// Package state persists the control plane desired state, its snapshots and
// its append-only journal.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/consensus"
)

// SchemaVersion is the current desired state schema version.
const SchemaVersion = 1

// Recovery modes.
const (
	ModeState = "state"
	ModeEnv   = "env"
	ModeMerge = "merge"
)

// Errors returned by state loading and validation.
var (
	ErrInvalidState     = errors.New("invalid desired state")
	ErrChecksumMismatch = errors.New("state checksum mismatch")
)

// TunnelSettings are the non-secret settings the control plane can change.
// Secret values are never persisted: Env carries environment references such
// as env:VPN_SERVICE_PROVIDER.
type TunnelSettings struct {
	Provider   string            `json:"provider,omitempty"`
	VPN        string            `json:"vpn,omitempty"`
	Countries  []string          `json:"countries,omitempty"`
	Regions    []string          `json:"regions,omitempty"`
	Cities     []string          `json:"cities,omitempty"`
	ISPs       []string          `json:"isps,omitempty"`
	Hostnames  []string          `json:"hostnames,omitempty"`
	Categories []string          `json:"categories,omitempty"`
	Tiers      []string          `json:"tiers,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
}

// JobIndex tracks the recent job identifiers and the pagination cursor.
type JobIndex struct {
	Recent []string `json:"recent,omitempty"`
	Cursor string   `json:"cursor,omitempty"`
}

// EventCursor is the last persisted control event sequence.
type EventCursor struct {
	LastSeq uint64 `json:"last_seq"`
}

// ObservationRing keeps a bounded number of recent egress observations.
type ObservationRing struct {
	Capacity int                  `json:"capacity"`
	Items    []egress.Observation `json:"items,omitempty"`
}

// ResolverTier is one DNS tier captured in a tunnel snapshot.
type ResolverTier struct {
	Type         string `json:"type"`
	State        string `json:"state"`
	LatencyEWMMS int64  `json:"latency_ewma_ms"`
}

// DNSState is the DNS state captured in a tunnel snapshot.
type DNSState struct {
	Ladder     []string       `json:"ladder,omitempty"`
	ActiveTier string         `json:"active_tier,omitempty"`
	FailClosed bool           `json:"fail_closed"`
	Tiers      []ResolverTier `json:"tiers,omitempty"`
	UpdatedAt  time.Time      `json:"updated_at,omitzero"`
}

// TunnelSnapshot is a complete, restorable picture of a station.
type TunnelSnapshot struct {
	SchemaVersion  int                  `json:"schema_version"`
	StationID      string               `json:"station_id"`
	TakenAt        time.Time            `json:"taken_at"`
	Trigger        string               `json:"trigger"`
	Settings       TunnelSettings       `json:"settings"`
	ServerHostname string               `json:"server_hostname,omitempty"`
	EndpointIP     netip.Addr           `json:"endpoint_ip,omitempty"`
	Transport      string               `json:"transport,omitempty"`
	Interface      string               `json:"interface,omitempty"`
	VPNStatus      string               `json:"vpn_status,omitempty"`
	Egress         *egress.Verification `json:"egress,omitempty"`
	DNS            *DNSState            `json:"dns,omitempty"`
	ProvenAt       *time.Time           `json:"proven_at,omitempty"`
}

// DesiredState is the persistent, versioned and checksummed control state.
type DesiredState struct {
	SchemaVersion int             `json:"schema_version"`
	StationID     string          `json:"station_id"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Checksum      string          `json:"checksum"`
	Mode          string          `json:"mode"`
	Desired       TunnelSettings  `json:"desired"`
	LastCommitted *TunnelSnapshot `json:"last_committed,omitempty"`
	Current       *TunnelSnapshot `json:"current,omitempty"`
	Jobs          JobIndex        `json:"jobs"`
	Events        EventCursor     `json:"events"`
	Observations  ObservationRing `json:"observations"`
}

// NewDesiredState builds and seals a state for a station.
func NewDesiredState(stationID, mode string, desired TunnelSettings,
	now time.Time,
) (state DesiredState, err error) {
	state = DesiredState{
		SchemaVersion: SchemaVersion,
		StationID:     stationID,
		UpdatedAt:     now.UTC(),
		Mode:          mode,
		Desired:       desired,
	}
	state.Checksum, err = checksum(state)
	if err != nil {
		return DesiredState{}, fmt.Errorf("computing checksum: %w", err)
	}
	err = state.validate()
	if err != nil {
		return DesiredState{}, err
	}
	return state, nil
}

// Seal recomputes the checksum after a modification.
func Seal(state DesiredState) (sealed DesiredState, err error) {
	state.Checksum, err = checksum(state)
	if err != nil {
		return DesiredState{}, fmt.Errorf("computing checksum: %w", err)
	}
	err = state.validate()
	if err != nil {
		return DesiredState{}, err
	}
	return state, nil
}

// Validate checks the schema, the settings and the checksum.
func (s DesiredState) Validate() error {
	return s.validate()
}

func (s DesiredState) validate() error {
	if s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schema version %d is not %d", ErrInvalidState,
			s.SchemaVersion, SchemaVersion)
	}
	if s.StationID == "" {
		return fmt.Errorf("%w: station ID is empty", ErrInvalidState)
	}
	if s.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: updated at is missing", ErrInvalidState)
	}
	if !slices.Contains([]string{ModeState, ModeEnv, ModeMerge}, s.Mode) {
		return fmt.Errorf("%w: unknown mode %q", ErrInvalidState, s.Mode)
	}
	if s.Checksum == "" {
		return fmt.Errorf("%w: checksum is missing", ErrInvalidState)
	}

	expected, err := checksum(s)
	if err != nil {
		return fmt.Errorf("computing checksum: %w", err)
	}
	if expected != s.Checksum {
		return fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch,
			expected, s.Checksum)
	}

	err = s.Desired.validate()
	if err != nil {
		return fmt.Errorf("%w: desired settings: %w", ErrInvalidState, err)
	}
	if s.LastCommitted != nil {
		err = s.LastCommitted.validate()
		if err != nil {
			return fmt.Errorf("%w: last committed snapshot: %w", ErrInvalidState, err)
		}
	}
	if s.Current != nil {
		err = s.Current.validate()
		if err != nil {
			return fmt.Errorf("%w: current snapshot: %w", ErrInvalidState, err)
		}
	}
	if s.Observations.Capacity < 0 {
		return fmt.Errorf("%w: observation capacity is negative", ErrInvalidState)
	}
	if len(s.Observations.Items) > s.Observations.Capacity {
		return fmt.Errorf("%w: observations exceed capacity", ErrInvalidState)
	}
	return nil
}

func (t TunnelSettings) validate() error {
	if !slices.Contains([]string{"", "openvpn", "wireguard"}, t.VPN) {
		return fmt.Errorf("unknown VPN %q", t.VPN)
	}
	lists := map[string][]string{
		"countries":  t.Countries,
		"regions":    t.Regions,
		"cities":     t.Cities,
		"isps":       t.ISPs,
		"hostnames":  t.Hostnames,
		"categories": t.Categories,
		"tiers":      t.Tiers,
	}
	for name, values := range lists {
		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s contains an empty value", name)
			}
		}
	}
	for key, reference := range t.Env {
		if strings.TrimSpace(key) == "" {
			return errors.New("environment reference key is empty")
		}
		if !strings.HasPrefix(reference, "env:") || len(reference) == len("env:") {
			return fmt.Errorf("environment reference %q is not in the env:NAME format",
				reference)
		}
	}
	return nil
}

func (s TunnelSnapshot) validate() error {
	if s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema version %d is not %d", s.SchemaVersion,
			SchemaVersion)
	}
	if s.StationID == "" {
		return errors.New("station ID is empty")
	}
	if s.TakenAt.IsZero() {
		return errors.New("taken at is missing")
	}
	if !slices.Contains([]string{"switch", "rotate", "rollback", "recovery"},
		s.Trigger) {
		return fmt.Errorf("unknown trigger %q", s.Trigger)
	}
	if !slices.Contains([]string{"", "openvpn", "wireguard"}, s.Transport) {
		return fmt.Errorf("unknown transport %q", s.Transport)
	}
	if !slices.Contains([]string{"", "running", "stopped", "unknown"}, s.VPNStatus) {
		return fmt.Errorf("unknown VPN status %q", s.VPNStatus)
	}
	if s.EndpointIP.IsValid() {
		reason := consensus.RejectionReason(s.EndpointIP,
			consensus.Options{AllowTestNets: true})
		if reason != "" {
			return fmt.Errorf("endpoint IP %s is not public: %s",
				s.EndpointIP, reason)
		}
	}
	err := s.Settings.validate()
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	return nil
}

// Equal reports whether both settings hold the same explicit values.
func (t TunnelSettings) Equal(other TunnelSettings) bool {
	switch {
	case t.Provider != other.Provider,
		t.VPN != other.VPN,
		!slices.Equal(t.Countries, other.Countries),
		!slices.Equal(t.Regions, other.Regions),
		!slices.Equal(t.Cities, other.Cities),
		!slices.Equal(t.ISPs, other.ISPs),
		!slices.Equal(t.Hostnames, other.Hostnames),
		!slices.Equal(t.Categories, other.Categories),
		!slices.Equal(t.Tiers, other.Tiers):
		return false
	}
	if len(t.Env) != len(other.Env) {
		return false
	}
	for key, value := range t.Env {
		otherValue, ok := other.Env[key]
		if !ok || otherValue != value {
			return false
		}
	}
	return true
}

// mergedWith keeps every value explicitly set by the state and fills the rest
// from the environment.
func (t TunnelSettings) mergedWith(environment TunnelSettings) TunnelSettings {
	merged := environment
	if t.Provider != "" {
		merged.Provider = t.Provider
	}
	if t.VPN != "" {
		merged.VPN = t.VPN
	}
	merged.Countries = mergeStrings(t.Countries, environment.Countries)
	merged.Regions = mergeStrings(t.Regions, environment.Regions)
	merged.Cities = mergeStrings(t.Cities, environment.Cities)
	merged.ISPs = mergeStrings(t.ISPs, environment.ISPs)
	merged.Hostnames = mergeStrings(t.Hostnames, environment.Hostnames)
	merged.Categories = mergeStrings(t.Categories, environment.Categories)
	merged.Tiers = mergeStrings(t.Tiers, environment.Tiers)
	merged.Env = mergeMap(t.Env, environment.Env)
	return merged
}

func mergeStrings(explicit, fallback []string) []string {
	if explicit != nil {
		return slices.Clone(explicit)
	}
	return slices.Clone(fallback)
}

func mergeMap(explicit, fallback map[string]string) map[string]string {
	if explicit == nil {
		return fallback
	}
	merged := make(map[string]string, len(explicit)+len(fallback))
	for key, value := range fallback {
		merged[key] = value
	}
	for key, value := range explicit {
		merged[key] = value
	}
	return merged
}

func checksum(state DesiredState) (string, error) {
	state.Checksum = ""
	encoded, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("encoding canonical JSON: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
