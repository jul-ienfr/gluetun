package integration

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/control/jobs"
	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rotationOldIP = "198.51.100.7"
	rotationNewIP = "198.51.100.8"
)

type rotationCatalog struct {
	servers map[string]jobs.Server
}

func (c rotationCatalog) Lookup(_ context.Context, hostname string,
) (server jobs.Server, found bool, err error) {
	server, found = c.servers[hostname]
	return server, found, nil
}

type rotationResolver struct{}

func (rotationResolver) LookupNetIP(_ context.Context, _, _ string,
) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
}

type rotationProber struct{}

func (rotationProber) Probe(_ context.Context, _ jobs.Transport, _ string) error {
	return nil
}

type rotationTunnel struct {
	applied []state.TunnelSnapshot
}

func (t *rotationTunnel) ApplySnapshot(_ context.Context,
	snapshot state.TunnelSnapshot,
) error {
	t.applied = append(t.applied, snapshot)
	return nil
}

func (t *rotationTunnel) AwaitSnapshot(_ context.Context,
	_ state.TunnelSnapshot,
) error {
	return nil
}

func (t *rotationTunnel) appliedHostnames() (hostnames []string) {
	hostnames = make([]string, len(t.applied))
	for index, snapshot := range t.applied {
		hostnames[index] = snapshot.ServerHostname
	}
	return hostnames
}

type rotationSnapshotter struct{}

func (rotationSnapshotter) Capture(context.Context, string) (
	state.TunnelSnapshot, error,
) {
	egressState := egress.Verification{
		Verified: true,
		IP:       netip.MustParseAddr(rotationOldIP),
	}
	return state.TunnelSnapshot{
		SchemaVersion:  state.SchemaVersion,
		StationID:      "station-1",
		ServerHostname: "old.example.com",
		EndpointIP:     netip.MustParseAddr("203.0.113.10"),
		Egress:         &egressState,
	}, nil
}

type rotationVerifier struct {
	results []egress.Verification
}

func (v *rotationVerifier) Verify(_ context.Context, _ verify.Request) (
	egress.Verification, error,
) {
	if len(v.results) == 0 {
		return egress.Verification{}, errors.New("no verification left")
	}
	result := v.results[0]
	v.results = v.results[1:]
	return result, nil
}

func newRotationExecutor(t *testing.T, tunnel *rotationTunnel,
	verifier *rotationVerifier, servers map[string]jobs.Server,
) *jobs.Executor {
	t.Helper()

	preflight := jobs.NewPreflight(jobs.PreflightSettings{
		Catalog:     rotationCatalog{servers: servers},
		Resolver:    rotationResolver{},
		Prober:      rotationProber{},
		Credentials: jobs.Credentials{OpenVPN: true, WireGuard: true},
		Timeout:     2 * time.Second,
	})
	return jobs.NewExecutor(jobs.ExecutorSettings{
		StationID:   "station-1",
		Provider:    "nordvpn",
		Tunnel:      tunnel,
		Snapshotter: rotationSnapshotter{},
		Verifier:    verifier,
		Preflight:   preflight,
	})
}

func newRotationManager(t *testing.T, executor *jobs.Executor) *jobs.Manager {
	t.Helper()
	return jobs.NewManager(jobs.ManagerSettings{Executor: executor})
}

func waitRotation(t *testing.T, manager *jobs.Manager, id string) jobs.Job {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	job, err := manager.Wait(ctx, id)
	require.NoError(t, err)
	return job
}

func rotationRequest(hostnames ...string) jobs.RotationRequest {
	candidates := make([]jobs.RotationTarget, len(hostnames))
	for index, hostname := range hostnames {
		candidates[index] = jobs.RotationTarget{Hostname: hostname}
	}
	return jobs.RotationRequest{
		Candidates: candidates,
		Constraints: jobs.RotationConstraints{
			RequireNewIP: true,
		},
		Options: jobs.SwitchOptions{Timeout: 5 * time.Second},
	}
}

func Test_Rotation_ThreeCandidates(t *testing.T) {
	t.Parallel()

	tunnel := &rotationTunnel{}
	verifier := &rotationVerifier{results: []egress.Verification{
		{Verified: true, IP: netip.MustParseAddr(rotationOldIP)},
		{Verified: true, IP: netip.MustParseAddr(rotationNewIP)},
	}}
	servers := map[string]jobs.Server{
		"b.example.com": {
			Hostname:  "b.example.com",
			IPs:       []netip.Addr{netip.MustParseAddr("203.0.113.10")},
			Protocols: []string{"wireguard", "openvpn"},
		},
		"c.example.com": {
			Hostname:  "c.example.com",
			IPs:       []netip.Addr{netip.MustParseAddr("203.0.113.10")},
			Protocols: []string{"wireguard", "openvpn"},
		},
	}
	manager := newRotationManager(t, newRotationExecutor(t, tunnel,
		verifier, servers))

	submission, err := manager.SubmitRotation(t.Context(),
		rotationRequest("a.example.com", "b.example.com", "c.example.com"))
	require.NoError(t, err)

	job := waitRotation(t, manager, submission.Job.ID)
	assert.Equal(t, jobs.StateCommitted, job.State)
	assert.Equal(t, "c.example.com", job.Target.Hostname)
	require.Len(t, job.Attempts, 3)
	assert.Equal(t, "preflight_failed", job.Attempts[0].Reason)
	assert.Equal(t, "same_ip", job.Attempts[1].Reason)
	assert.Equal(t, "committed", job.Attempts[2].Result)

	assert.Equal(t, []string{
		"b.example.com", "old.example.com", "c.example.com",
	}, tunnel.appliedHostnames())
}

func Test_Rotation_ThreeFailuresExhaust(t *testing.T) {
	t.Parallel()

	tunnel := &rotationTunnel{}
	verifier := &rotationVerifier{results: []egress.Verification{
		{Verified: true, IP: netip.MustParseAddr(rotationOldIP)},
		{Verified: true, IP: netip.MustParseAddr(rotationOldIP)},
		{Verified: true, IP: netip.MustParseAddr(rotationOldIP)},
	}}
	server := jobs.Server{
		Hostname:  "a.example.com",
		IPs:       []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		Protocols: []string{"wireguard", "openvpn"},
	}
	manager := newRotationManager(t, newRotationExecutor(t, tunnel,
		verifier, map[string]jobs.Server{
			"a.example.com": server,
			"b.example.com": server,
			"c.example.com": server,
		}))

	submission, err := manager.SubmitRotation(t.Context(),
		rotationRequest("a.example.com", "b.example.com", "c.example.com"))
	require.NoError(t, err)

	job := waitRotation(t, manager, submission.Job.ID)
	assert.Equal(t, jobs.StateExhausted, job.State)
	require.NotNil(t, job.StationPreserved)
	assert.True(t, *job.StationPreserved)
	require.NotNil(t, job.GlobalStateWritten)
	assert.False(t, *job.GlobalStateWritten)
	require.Len(t, job.Attempts, 3)
	for _, attempt := range job.Attempts {
		assert.Equal(t, "same_ip", attempt.Reason)
	}

	assert.Equal(t, []string{
		"a.example.com", "old.example.com",
		"b.example.com", "old.example.com",
		"c.example.com", "old.example.com",
	}, tunnel.appliedHostnames())
}
