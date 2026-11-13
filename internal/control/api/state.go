package api

import (
	"net/http"
	"net/netip"
	"time"
)

// VPNServerState is the public view of the connected provider server.
type VPNServerState struct {
	Hostname string `json:"hostname"`
	Country  string `json:"country,omitempty"`
	City     string `json:"city,omitempty"`
}

// VPNEgressState is the public view of the last egress verification.
type VPNEgressState struct {
	Verified   bool       `json:"verified"`
	IP         netip.Addr `json:"ip,omitzero"`
	Quorum     int        `json:"quorum,omitempty"`
	VerifiedAt time.Time  `json:"verified_at,omitzero"`
}

// VPNDNSState is the public view of the DNS ladder.
type VPNDNSState struct {
	Ladder     []string `json:"ladder"`
	ActiveTier string   `json:"active_tier,omitempty"`
	FailClosed bool     `json:"fail_closed"`
}

// VPNDesiredState is the control plane target currently applied.
type VPNDesiredState struct {
	Hostname  string `json:"hostname,omitempty"`
	Transport string `json:"transport,omitempty"`
}

// VPNCommittedState identifies the last committed job.
type VPNCommittedState struct {
	JobID string    `json:"job_id,omitempty"`
	At    time.Time `json:"at,omitzero"`
}

// VPNState is the response body of GET /v1/vpn/state. It is served from
// memory and never reads the disk.
type VPNState struct {
	StationID     string             `json:"station_id"`
	VPNStatus     string             `json:"vpn_status"`
	Transport     string             `json:"transport,omitempty"`
	Server        *VPNServerState    `json:"server,omitempty"`
	EndpointIP    netip.Addr         `json:"endpoint_ip,omitzero"`
	Egress        *VPNEgressState    `json:"egress,omitempty"`
	DNS           *VPNDNSState       `json:"dns,omitempty"`
	Desired       *VPNDesiredState   `json:"desired,omitempty"`
	LastCommitted *VPNCommittedState `json:"last_committed,omitempty"`
	ActiveJobID   *string            `json:"active_job_id"`
	StateMode     string             `json:"state_mode"`
	UpdatedAt     time.Time          `json:"updated_at,omitzero"`
}

func (h *Handler) getVPNState(w http.ResponseWriter, _ *http.Request) {
	if h.state == nil {
		writeNotReady(w)
		return
	}
	writeJSON(w, h.state.VPNState())
}
