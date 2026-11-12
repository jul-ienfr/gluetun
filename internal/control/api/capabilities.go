package api

import (
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
)

// ControlPlaneVersion is the version of the control plane API.
const ControlPlaneVersion = "1.0.0"

// Default limits advertised by the capabilities endpoint.
const (
	maxBodyBytes           = 1 << 20
	maxCandidates          = 20
	maxAttempts            = 10
	maxSwitchPerMinute     = 6
	defaultTimeoutSeconds  = 45
	wireGuardTimeoutS      = 30
	openVPNUDPTimeoutS     = 30
	openVPNTCPTimeoutS     = 45
	transportMaxAttempts   = 2
	transportBackoffMaxS   = 300
	idempotencyWindowHours = 24
)

// DefaultTransportLadder is the ordered transport ladder used when no explicit
// policy is provided.
var DefaultTransportLadder = []string{ //nolint:gochecknoglobals
	"wireguard", "openvpn-udp", "openvpn-tcp",
}

// Capabilities is the response body of GET /v1/control/capabilities.
type Capabilities struct {
	ControlPlaneVersion string   `json:"control_plane_version"`
	UpstreamVersion     string   `json:"upstream_version"`
	StationID           string   `json:"station_id"`
	Features            Features `json:"features"`
	Limits              Limits   `json:"limits"`
	StateMode           string   `json:"state_mode"`
	DNSDefaultLadder    []string `json:"dns_default_ladder"`
	TransportDefault    []string `json:"transport_default_ladder"`
}

// Features advertises the control plane features which are implemented.
type Features struct {
	Switch           bool `json:"switch"`
	Rotate           bool `json:"rotate"`
	Rollback         bool `json:"rollback"`
	DryRun           bool `json:"dry_run"`
	Drain            bool `json:"drain"`
	DNSLadder        bool `json:"dns_ladder"`
	EgressConsensus  bool `json:"egress_consensus"`
	TransportLadder  bool `json:"transport_ladder"`
	EventsSSE        bool `json:"events_sse"`
	StatePersistence bool `json:"state_persistence"`
	SecretReveal     bool `json:"secret_reveal"`
}

// Limits contains the effective control plane limits.
type Limits struct {
	MaxBodyBytes            int            `json:"max_body_bytes"`
	MaxCandidates           int            `json:"max_candidates"`
	MaxAttempts             int            `json:"max_attempts"`
	MaxSwitchPerMinute      int            `json:"max_switch_per_minute"`
	DefaultTimeoutS         int            `json:"default_timeout_s"`
	Quorum                  uint           `json:"quorum"`
	MinSources              uint           `json:"min_sources"`
	EgressCacheTTLS         float64        `json:"egress_cache_ttl_s"`
	TransportAttemptTimeout map[string]int `json:"transport_attempt_timeout_s"`
	TransportMaxAttempts    int            `json:"transport_max_attempts"`
	TransportBackoffMaxS    int            `json:"transport_backoff_max_s"`
	IdempotencyWindowH      int            `json:"idempotency_window_h"`
}

// NewCapabilities builds the capabilities response from the effective
// settings. Feature flags only advertise what is implemented.
func NewCapabilities(control settings.Control,
	buildInfo models.BuildInformation, stationID string,
) Capabilities {
	stateMode := control.StateMode
	if stateMode == "" {
		stateMode = "state"
	}
	egressConsensus := control.Egress.Enabled == nil || *control.Egress.Enabled

	return Capabilities{
		ControlPlaneVersion: ControlPlaneVersion,
		UpstreamVersion:     buildInfo.Version,
		StationID:           stationID,
		Features: Features{
			Switch:           true,
			Rotate:           true,
			Rollback:         true,
			DryRun:           true,
			Drain:            true,
			DNSLadder:        false,
			EgressConsensus:  egressConsensus,
			TransportLadder:  false,
			EventsSSE:        false,
			StatePersistence: false,
			SecretReveal:     false,
		},
		Limits: Limits{
			MaxBodyBytes:       maxBodyBytes,
			MaxCandidates:      maxCandidates,
			MaxAttempts:        maxAttempts,
			MaxSwitchPerMinute: maxSwitchPerMinute,
			DefaultTimeoutS:    defaultTimeoutSeconds,
			Quorum:             control.Egress.Quorum,
			MinSources:         control.Egress.MinSources,
			EgressCacheTTLS:    control.Egress.CacheTTL.Seconds(),
			TransportAttemptTimeout: map[string]int{
				"wireguard":   wireGuardTimeoutS,
				"openvpn-udp": openVPNUDPTimeoutS,
				"openvpn-tcp": openVPNTCPTimeoutS,
			},
			TransportMaxAttempts: transportMaxAttempts,
			TransportBackoffMaxS: transportBackoffMaxS,
			IdempotencyWindowH:   idempotencyWindowHours,
		},
		StateMode:        stateMode,
		DNSDefaultLadder: control.DNS.Ladder,
		TransportDefault: DefaultTransportLadder,
	}
}
