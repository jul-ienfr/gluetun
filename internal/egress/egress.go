// Package egress defines the egress verification model shared by the control
// plane sources, consensus, canary and HTTP API.
package egress

import (
	"net/netip"
	"time"
)

// Kind is the kind of an egress source.
type Kind string

const (
	KindHTTP     Kind = "http"
	KindDNS      Kind = "dns"
	KindPublicIP Kind = "publicip"
	KindCanary   Kind = "canary"
)

// Reason is a typed source failure or observation rejection reason.
type Reason string

const (
	// Source failures.
	ReasonTimeout    Reason = "timeout"
	ReasonHTTPStatus Reason = "http_status"
	ReasonMalformed  Reason = "malformed"
	ReasonEmpty      Reason = "empty"
	ReasonBanned     Reason = "banned"

	// Hard observation rejections.
	ReasonPrivate     Reason = "private"
	ReasonLoopback    Reason = "loopback"
	ReasonLinkLocal   Reason = "link_local"
	ReasonCGNAT       Reason = "cgnat"
	ReasonMulticast   Reason = "multicast"
	ReasonUnspecified Reason = "unspecified"
	ReasonHostIP      Reason = "host_ip"
	ReasonForbiddenIP Reason = "forbidden_ip"
	ReasonWrongFamily Reason = "wrong_family"
	ReasonDocumenting Reason = "documentation"

	// Verification results.
	ReasonInsufficientSources Reason = "insufficient_sources"
	ReasonNoQuorum            Reason = "no_quorum"
	ReasonCanaryFailed        Reason = "canary_failed"

	// Canary failures.
	ReasonEmptyBody    Reason = "empty_body"
	ReasonBodyTooSmall Reason = "body_too_small"
	ReasonHashMismatch Reason = "hash_mismatch"
	ReasonTLS          Reason = "tls"
	ReasonTransport    Reason = "transport"
)

// Confidence qualifies a verified result.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// SourceError describes a failed source fetch.
type SourceError struct {
	Reason  Reason `json:"reason"`
	Message string `json:"message,omitempty"`
}

// Observation is a single source answer, accepted or rejected.
type Observation struct {
	Source          string       `json:"source"`
	Kind            Kind         `json:"kind"`
	IP              netip.Addr   `json:"ip,omitzero"`
	Country         string       `json:"country,omitempty"`
	Region          string       `json:"region,omitempty"`
	City            string       `json:"city,omitempty"`
	ASN             uint         `json:"asn,omitempty"`
	Organization    string       `json:"organization,omitempty"`
	LatencyMS       int64        `json:"latency_ms"`
	ObservedAt      time.Time    `json:"observed_at"`
	Accepted        bool         `json:"accepted"`
	RejectionReason *Reason      `json:"rejection_reason"`
	Error           *SourceError `json:"error,omitempty"`
}

// CanaryResult is the outcome of the neutral HTTP canary.
type CanaryResult struct {
	URL        string    `json:"url"`
	Status     int       `json:"status"`
	BodyBytes  int64     `json:"body_bytes"`
	BodySHA256 string    `json:"body_sha256,omitempty"`
	LatencyMS  int64     `json:"latency_ms"`
	OK         bool      `json:"ok"`
	Failure    *Reason   `json:"failure"`
	CheckedAt  time.Time `json:"checked_at,omitzero"`
}

// Verification is the provable egress result returned by the control plane.
type Verification struct {
	Verified     bool          `json:"verified"`
	IP           netip.Addr    `json:"ip,omitzero"`
	Family       int           `json:"family"`
	Quorum       int           `json:"quorum"`
	SourceCount  int           `json:"source_count"`
	Confidence   Confidence    `json:"confidence"`
	Dissenters   []string      `json:"dissenters"`
	Observations []Observation `json:"observations"`
	Canary       *CanaryResult `json:"canary,omitempty"`
	Cached       bool          `json:"cached"`
	VerifiedAt   time.Time     `json:"verified_at"`
	TTLS         int           `json:"ttl_s"`
	Reason       *Reason       `json:"reason,omitempty"`
	SingleSource bool          `json:"single_source,omitempty"`
}
