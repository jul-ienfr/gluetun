package api

import (
	"context"
	"time"

	"github.com/qdm12/gluetun/internal/control/catalog"
	"github.com/qdm12/gluetun/internal/control/jobs"
	"github.com/qdm12/gluetun/internal/dns/ladder"
	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/verify"
	transportpkg "github.com/qdm12/gluetun/internal/vpn/transport"
)

// EgressService is the egress verification surface exposed by the API.
type EgressService interface {
	Verify(ctx context.Context, request verify.Request) (egress.Verification, error)
	History(limit int, since time.Time) (verifications []egress.Verification)
	CheckCanary(ctx context.Context) (result egress.CanaryResult, err error)
}

// JobsService is the switch, rotate, rollback and job surface exposed by the
// API.
type JobsService interface {
	Submit(ctx context.Context, request jobs.SwitchRequest) (
		submission jobs.Submission, err error)
	Plan(ctx context.Context, request jobs.SwitchRequest) (
		result jobs.PlanResult, err error)
	SubmitRotation(ctx context.Context, request jobs.RotationRequest) (
		submission jobs.Submission, err error)
	SubmitRollback(ctx context.Context, request jobs.RollbackRequest) (
		submission jobs.Submission, err error)
	Get(id string) (job jobs.Job, found bool)
	List(filter jobs.Filter) (page jobs.Page, err error)
	Cancel(id string) (job jobs.Job, err error)
	Wait(ctx context.Context, id string) (job jobs.Job, err error)
}

// CatalogService is the read-only server catalogue surface exposed by the API.
type CatalogService interface {
	Query(query catalog.Query) (page catalog.Page, err error)
	Facets() (facets catalog.Facets, err error)
	Detail(hostname string) (detail catalog.ServerDetail, found bool,
		err error)
	Refresh(ctx context.Context) (result catalog.RefreshResult, err error)
}

// DNSService is the DNS ladder surface exposed by the API.
type DNSService interface {
	DNSState() (snapshot ladder.Snapshot, available bool)
	DNSProbe(ctx context.Context, tier, domain string, timeout time.Duration,
		dryRun bool) (result ladder.ProbeResult, err error)
}

// TransportService is the transport ladder surface exposed by the API.
type TransportService interface {
	TransportState() (state transportpkg.State, available bool)
	TransportPolicy() transportpkg.Policy
	ResetTransport(target *transportpkg.Transport) error
}

// StateService serves the in-memory station state.
type StateService interface {
	VPNState() VPNState
}
