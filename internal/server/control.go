package server

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/control/api"
	"github.com/qdm12/gluetun/internal/control/catalog"
	"github.com/qdm12/gluetun/internal/control/events"
	"github.com/qdm12/gluetun/internal/control/jobs"
	"github.com/qdm12/gluetun/internal/control/observability"
	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress/verify"
	"github.com/qdm12/gluetun/internal/models"
	transportpkg "github.com/qdm12/gluetun/internal/vpn/transport"
)

const (
	defaultControlAwaitInterval = 500 * time.Millisecond
	controlJobsRetention        = 200
)

// newControlHandler builds the control plane HTTP handler and every service it
// depends on. Egress verification is the prerequisite of the switch jobs: when
// it is disabled the switch surface stays unavailable.
func newControlHandler(logger Logger, control settings.Control,
	buildInfo models.BuildInformation, stationID string, vpnLooper VPNLooper,
	dnsLooper DNSLoop, storage Storage,
	metrics *observability.Metrics, egress *verify.Service,
	transportService *transportpkg.Service,
) *api.Handler {
	egressService := egress
	var egressAPI api.EgressService
	if egressService != nil {
		egressAPI = egressService
	}

	var store *state.Store
	var persisted state.DesiredState
	var persistedFound bool
	if control.StateDir != "" {
		store = state.New(control.StateDir)
		loaded, found, err := store.Load()
		switch {
		case err != nil:
			logger.Warn("loading control plane state: " + err.Error())
		case found:
			persisted = loaded
			persistedFound = true
		}
	}

	eventBus, eventLog := newEventBus(control, logger)
	if metrics == nil {
		metrics = observability.NewMetrics()
	}

	var manager *jobs.Manager
	catalogService := newCatalog(storage, vpnLooper.GetSettings().Provider.Name)
	if egressService != nil {
		runtimeState := &controlRuntimeState{
			store:     store,
			stationID: stationID,
			mode:      control.StateMode,
			now:       time.Now,
			lastSeq:   eventBus.LastSeq,
			logger:    logger,
		}
		if persistedFound {
			runtimeState.desired = persisted
			runtimeState.found = true
		}

		manager = newJobsManager(vpnLooper, storage, egressService,
			catalogService, eventBus, eventLog, metrics, logger, persisted,
			persistedFound, runtimeState)
	}

	handler := api.New(control, buildInfo, stationID, egressAPI, manager)
	handler.SetCatalog(catalogService)
	if dnsService, ok := dnsLooper.(api.DNSService); ok {
		handler.SetDNS(dnsService)
	}
	handler.SetEvents(eventBus)
	if transportService != nil {
		handler.SetTransport(transportService)
		transportService.SetEventSink(
			events.NewTransportSink(eventBus, eventLog, logger.Warn))
	}
	handler.SetState(&vpnStateService{
		stationID: stationID,
		stateMode: control.StateMode,
		vpnLooper: vpnLooper,
		catalog:   catalogService,
		jobs:      manager,
		egress:    egressService,
		dns:       dnsForAPI(dnsLooper),
		now:       time.Now,
	})

	return handler
}

func dnsForAPI(looper DNSLoop) api.DNSService {
	service, _ := looper.(api.DNSService)
	return service
}

func newEventBus(control settings.Control, logger Logger) (
	bus *events.Bus, log *events.FileLog,
) {
	bus = events.New(events.Options{})
	if control.StateDir == "" {
		return bus, nil
	}

	log = events.NewFileLog(control.StateDir, events.DefaultLogMaxBytes,
		events.DefaultLogMaxFiles)
	history, _, err := log.Load(events.DefaultBuffer)
	if err != nil {
		logger.Warn("loading control plane events: " + err.Error())
		return bus, log
	}
	bus.Restore(history)
	return bus, log
}

func newJobsManager(vpnLooper VPNLooper, storage Storage, egress *verify.Service,
	catalogService *catalog.Catalog, bus *events.Bus, eventLog *events.FileLog,
	metrics *observability.Metrics, logger Logger, persisted state.DesiredState,
	persistedFound bool, runtimeState *controlRuntimeState,
) *jobs.Manager {
	vpnSettings := vpnLooper.GetSettings()
	preflight := jobs.NewPreflight(jobs.PreflightSettings{
		Catalog: storagePreflightCatalog{
			storage:  storage,
			provider: vpnSettings.Provider.Name,
		},
		Credentials: credentialsFor(vpnSettings),
	})

	cooldown := catalog.NewCooldown(catalog.CooldownOptions{})
	executor := jobs.NewExecutor(jobs.ExecutorSettings{
		StationID: runtimeState.stationID,
		Provider:  vpnSettings.Provider.Name,
		Tunnel:    tunnelAdapter{loop: vpnLooper},
		Snapshotter: tunnelSnapshotter{
			loop:      vpnLooper,
			stationID: runtimeState.stationID,
			egress:    egress,
			now:       time.Now,
		},
		Verifier:  egress,
		Preflight: preflight,
		Events:    eventSink(bus, eventLog, metrics, logger),
		Cooldown:  cooldown,
	})

	var lastCommitted *state.TunnelSnapshot
	if persistedFound {
		lastCommitted = persisted.LastCommitted
	}

	return jobs.NewManager(jobs.ManagerSettings{
		Executor:      executor,
		Catalog:       catalogService,
		LastCommitted: lastCommitted,
		OnCommit:      runtimeState.recordCommit,
		Retention:     controlJobsRetention,
	})
}

func credentialsFor(vpnSettings settings.VPN) jobs.Credentials {
	hasOpenVPN := vpnSettings.OpenVPN.User != nil &&
		vpnSettings.OpenVPN.Password != nil &&
		(*vpnSettings.OpenVPN.User != "" ||
			*vpnSettings.OpenVPN.Password != "" ||
			(vpnSettings.OpenVPN.ConfFile != nil &&
				*vpnSettings.OpenVPN.ConfFile != ""))
	hasWireGuard := vpnSettings.Wireguard.PrivateKey != nil &&
		*vpnSettings.Wireguard.PrivateKey != ""

	// The active connection proves its own transport works.
	switch vpnSettings.Type {
	case vpn.OpenVPN:
		hasOpenVPN = true
	case vpn.Wireguard:
		hasWireGuard = true
	}
	return jobs.Credentials{OpenVPN: hasOpenVPN, WireGuard: hasWireGuard}
}

// storagePreflightCatalog merges every catalogue entry sharing a hostname so a
// server advertising both WireGuard and OpenVPN is usable by the ladder.
type storagePreflightCatalog struct {
	storage  Storage
	provider string
}

func (c storagePreflightCatalog) Lookup(_ context.Context, hostname string,
) (server jobs.Server, found bool, err error) {
	server.Hostname = hostname
	seenIPs := make(map[netip.Addr]struct{})
	seenProtocols := make(map[string]struct{})
	for _, candidate := range c.storage.GetServers(c.provider) {
		if !strings.EqualFold(candidate.Hostname, hostname) {
			continue
		}
		found = true
		for _, address := range candidate.IPs {
			if _, ok := seenIPs[address]; ok {
				continue
			}
			seenIPs[address] = struct{}{}
			server.IPs = append(server.IPs, address)
		}
		protocol := candidate.VPN
		switch protocol {
		case vpn.OpenVPN, vpn.Wireguard:
		default:
			continue
		}
		if _, ok := seenProtocols[protocol]; ok {
			continue
		}
		seenProtocols[protocol] = struct{}{}
		server.Protocols = append(server.Protocols, protocol)
	}
	return server, found, nil
}

// tunnelAdapter applies a snapshot by replacing the settings of the VPN loop.
// The loop stop/start sequence is executed from the job goroutine, never from
// the loop itself.
type tunnelAdapter struct {
	loop VPNLooper
}

func (t tunnelAdapter) ApplySnapshot(ctx context.Context,
	snapshot state.TunnelSnapshot,
) error {
	current := t.loop.GetSettings()
	updated, err := applySnapshotToSettings(current, snapshot)
	if err != nil {
		return err
	}
	outcome := t.loop.SetSettings(ctx, updated)
	status := t.loop.GetStatus()
	if status != constants.Running && status != constants.Starting {
		return fmt.Errorf("vpn loop is %s after applying settings: %s",
			status, outcome)
	}
	return nil
}

func (t tunnelAdapter) AwaitSnapshot(ctx context.Context,
	snapshot state.TunnelSnapshot,
) error {
	ticker := time.NewTicker(defaultControlAwaitInterval)
	defer ticker.Stop()

	for {
		if snapshotApplied(t.loop.GetSettings(), snapshot) &&
			t.loop.GetStatus() == constants.Running {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("awaiting tunnel readiness: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func applySnapshotToSettings(current settings.VPN,
	snapshot state.TunnelSnapshot,
) (updated settings.VPN, err error) {
	if snapshot.Settings.Provider != "" {
		current.Provider.Name = snapshot.Settings.Provider
	}
	hostnames := snapshotHostnames(snapshot)

	transport := snapshot.TransportDetail
	if transport == "" {
		transport = snapshot.Transport
	}
	switch transport {
	case vpn.Wireguard:
		current.Type = vpn.Wireguard
		current.Provider.ServerSelection.VPN = vpn.Wireguard
		current.Provider.ServerSelection.Hostnames = hostnames
		current.Provider.ServerSelection.Wireguard.EndpointIP =
			endpointOrUnspecified(snapshot.EndpointIP)
	case vpn.OpenVPN, "openvpn-udp", "openvpn-tcp":
		current.Type = vpn.OpenVPN
		current.Provider.ServerSelection.VPN = vpn.OpenVPN
		current.Provider.ServerSelection.Hostnames = hostnames
		protocol := constants.UDP
		if transport == "openvpn-tcp" {
			protocol = constants.TCP
		}
		current.Provider.ServerSelection.OpenVPN.Protocol = protocol
		current.Provider.ServerSelection.OpenVPN.EndpointIP =
			endpointOrUnspecified(snapshot.EndpointIP)
	default:
		return settings.VPN{}, fmt.Errorf("unknown snapshot transport %q", transport)
	}
	return current, nil
}

func endpointOrUnspecified(address netip.Addr) netip.Addr {
	if !address.IsValid() {
		return netip.IPv4Unspecified()
	}
	return address
}

func snapshotHostnames(snapshot state.TunnelSnapshot) []string {
	if snapshot.ServerHostname != "" {
		return []string{snapshot.ServerHostname}
	}
	if len(snapshot.Settings.Hostnames) > 0 {
		return append([]string(nil), snapshot.Settings.Hostnames...)
	}
	return nil
}

func snapshotApplied(current settings.VPN, snapshot state.TunnelSnapshot) bool {
	transport := snapshot.TransportDetail
	if transport == "" {
		transport = snapshot.Transport
	}
	switch transport {
	case vpn.Wireguard:
		if current.Type != vpn.Wireguard {
			return false
		}
	case vpn.OpenVPN, "openvpn-udp", "openvpn-tcp":
		if current.Type != vpn.OpenVPN {
			return false
		}
		if transport == "openvpn-tcp" &&
			current.Provider.ServerSelection.OpenVPN.Protocol != constants.TCP {
			return false
		}
		if transport == "openvpn-udp" &&
			current.Provider.ServerSelection.OpenVPN.Protocol != constants.UDP {
			return false
		}
	default:
		return false
	}

	hostnames := snapshotHostnames(snapshot)
	if len(hostnames) > 0 {
		selected := current.Provider.ServerSelection.Hostnames
		if len(selected) == 0 || !strings.EqualFold(selected[0], hostnames[0]) {
			return false
		}
	}
	if snapshot.EndpointIP.IsValid() {
		if currentEndpoint(current) != snapshot.EndpointIP {
			return false
		}
	}
	return true
}

func currentEndpoint(current settings.VPN) netip.Addr {
	switch current.Type {
	case vpn.Wireguard:
		return current.Provider.ServerSelection.Wireguard.EndpointIP
	case vpn.OpenVPN:
		return current.Provider.ServerSelection.OpenVPN.EndpointIP
	}
	return netip.Addr{}
}

// tunnelSnapshotter builds a restorable snapshot from the live loop settings.
type tunnelSnapshotter struct {
	loop      VPNLooper
	stationID string
	egress    *verify.Service
	now       func() time.Time
}

func (s tunnelSnapshotter) Capture(_ context.Context, trigger string) (
	snapshot state.TunnelSnapshot, err error,
) {
	current := s.loop.GetSettings()
	hostnames := append([]string(nil),
		current.Provider.ServerSelection.Hostnames...)

	snapshot = state.TunnelSnapshot{
		SchemaVersion: state.SchemaVersion,
		StationID:     s.stationID,
		TakenAt:       s.now().UTC(),
		Trigger:       trigger,
		Settings: state.TunnelSettings{
			Provider:  current.Provider.Name,
			VPN:       current.Type,
			Hostnames: hostnames,
		},
		Transport:       current.Type,
		TransportDetail: transportDetail(current),
		VPNStatus:       normalizeVPNStatus(s.loop.GetStatus()),
	}
	if len(hostnames) > 0 {
		snapshot.ServerHostname = hostnames[0]
	}
	snapshot.EndpointIP = currentEndpoint(current)
	switch current.Type {
	case vpn.Wireguard:
		snapshot.Interface = current.Wireguard.Interface
	case vpn.OpenVPN:
		snapshot.Interface = current.OpenVPN.Interface
	}

	if s.egress != nil {
		history := s.egress.History(1, time.Time{})
		if len(history) > 0 {
			verification := history[0]
			snapshot.Egress = &verification
			if !verification.VerifiedAt.IsZero() {
				provenAt := verification.VerifiedAt
				snapshot.ProvenAt = &provenAt
			}
		}
	}
	return snapshot, nil
}

func transportDetail(current settings.VPN) string {
	if current.Type != vpn.OpenVPN {
		return current.Type
	}
	protocol := current.Provider.ServerSelection.OpenVPN.Protocol
	if protocol == constants.TCP {
		return "openvpn-tcp"
	}
	return "openvpn-udp"
}

func normalizeVPNStatus(status models.LoopStatus) string {
	switch status {
	case constants.Running:
		return "running"
	case constants.Stopped:
		return "stopped"
	default:
		return "unknown"
	}
}

func eventSink(bus *events.Bus, log *events.FileLog,
	metrics *observability.Metrics, logger Logger,
) jobs.EventSink {
	return func(event string, job jobs.Job) {
		observeJob(metrics, event, job)
		published := bus.Publish(events.Event{
			Type:     event,
			Severity: eventSeverity(event),
			JobID:    job.ID,
			Data: map[string]any{
				"kind":     string(job.Kind),
				"state":    string(job.State),
				"hostname": job.Target.Hostname,
			},
		})
		if published.Seq == 0 {
			logger.Warn("control plane event bus is closed")
			return
		}
		if log != nil {
			err := log.Append(published)
			if err != nil {
				logger.Warn("persisting control plane event: " + err.Error())
			}
		}
	}
}

// observeJob feeds the job metrics only for terminal events. Intermediate
// events such as drain.timeout are skipped so a single job is counted once.
func observeJob(metrics *observability.Metrics, event string, job jobs.Job) {
	if metrics == nil {
		return
	}
	switch event {
	case jobs.EventJobCommitted, jobs.EventJobRejected,
		jobs.EventJobCanceled, jobs.EventRolledBack,
		jobs.EventFailedDegraded, jobs.EventSwitchNoop:
	default:
		return
	}

	observation := observability.JobObservation{
		Kind:  string(job.Kind),
		State: string(job.State),
	}
	if job.FinishedAt != nil {
		start := job.CreatedAt
		if job.StartedAt != nil {
			start = *job.StartedAt
		}
		if job.FinishedAt.After(start) {
			observation.Duration = job.FinishedAt.Sub(start)
		}
	}

	phases := map[string]time.Duration{
		"validating":       time.Duration(job.Timings.Validating) * time.Millisecond,
		"preflight":        time.Duration(job.Timings.Preflight) * time.Millisecond,
		"draining":         time.Duration(job.Timings.Draining) * time.Millisecond,
		"applying":         time.Duration(job.Timings.Applying) * time.Millisecond,
		"awaiting_tunnel":  time.Duration(job.Timings.AwaitingTunnel) * time.Millisecond,
		"verifying_egress": time.Duration(job.Timings.VerifyingEgress) * time.Millisecond,
		"rolling_back":     time.Duration(job.Timings.RollingBack) * time.Millisecond,
	}
	observation.PhaseDurations = make(map[string]time.Duration, len(phases))
	for phase, duration := range phases {
		if duration > 0 {
			observation.PhaseDurations[phase] = duration
		}
	}

	observation.AttemptResults = make([]string, 0, len(job.Attempts))
	for _, attempt := range job.Attempts {
		observation.AttemptResults = append(observation.AttemptResults, attempt.Result)
	}

	metrics.ObserveJob(observation)
}

func eventSeverity(event string) string {
	switch event {
	case jobs.EventJobRejected, jobs.EventJobCanceled,
		jobs.EventRolledBack, jobs.EventFailedDegraded,
		jobs.EventDrainTimeout:
		return events.SeverityWarning
	}
	return events.SeverityInfo
}

// controlRuntimeState persists committed snapshots while keeping the last
// desired state in memory for GET /v1/vpn/state.
type controlRuntimeState struct {
	mutex     sync.Mutex
	store     *state.Store
	desired   state.DesiredState
	found     bool
	stationID string
	mode      string
	now       func() time.Time
	lastSeq   func() uint64
	logger    Logger
}

func (s *controlRuntimeState) recordCommit(job jobs.Job,
	snapshot state.TunnelSnapshot,
) {
	if s == nil || s.store == nil {
		return
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	desired := s.desired
	if !s.found {
		desired = state.DesiredState{
			SchemaVersion: state.SchemaVersion,
			StationID:     s.stationID,
			Mode:          stateModeOrDefault(s.mode),
			Desired: state.TunnelSettings{
				Provider:  snapshot.Settings.Provider,
				VPN:       snapshot.Settings.VPN,
				Hostnames: snapshotHostnames(snapshot),
			},
		}
	}
	now := s.now().UTC()
	desired.UpdatedAt = now
	desired.LastCommitted = &snapshot
	desired.Current = &snapshot
	desired.Jobs.Recent = appendRecentJob(desired.Jobs.Recent, job.ID)
	if s.lastSeq != nil {
		desired.Events.LastSeq = s.lastSeq()
	}

	err := s.store.Save(desired)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("persisting control plane state: " + err.Error())
		}
		return
	}
	s.desired = desired
	s.found = true
}

func stateModeOrDefault(mode string) string {
	switch mode {
	case state.ModeState, state.ModeEnv, state.ModeMerge:
		return mode
	default:
		return state.ModeState
	}
}

func appendRecentJob(recent []string, id string) []string {
	const maxRecentJobs = 50
	recent = append(recent, id)
	if len(recent) > maxRecentJobs {
		recent = recent[len(recent)-maxRecentJobs:]
	}
	return recent
}

// vpnStateService serves the in-memory view of the station.
type vpnStateService struct {
	stationID string
	stateMode string
	vpnLooper VPNLooper
	catalog   *catalog.Catalog
	jobs      *jobs.Manager
	egress    *verify.Service
	dns       api.DNSService
	now       func() time.Time
}

func (s *vpnStateService) VPNState() api.VPNState {
	current := s.vpnLooper.GetSettings()
	view := api.VPNState{
		StationID: s.stationID,
		VPNStatus: string(s.vpnLooper.GetStatus()),
		Transport: transportDetail(current),
		StateMode: stateModeOrDefault(s.stateMode),
		UpdatedAt: s.now().UTC(),
	}
	view.EndpointIP = currentEndpoint(current)

	hostname := ""
	if len(current.Provider.ServerSelection.Hostnames) > 0 {
		hostname = current.Provider.ServerSelection.Hostnames[0]
	}
	if hostname != "" {
		view.Server = &api.VPNServerState{Hostname: hostname}
		candidate, found, err := s.catalog.Get(hostname)
		if err == nil && found {
			view.Server.Country = candidate.Country
			view.Server.City = candidate.City
		}
		view.Desired = &api.VPNDesiredState{
			Hostname:  hostname,
			Transport: view.Transport,
		}
	}

	if s.egress != nil {
		history := s.egress.History(1, time.Time{})
		if len(history) > 0 {
			verification := history[0]
			view.Egress = &api.VPNEgressState{
				Verified:   verification.Verified,
				IP:         verification.IP,
				Quorum:     verification.Quorum,
				VerifiedAt: verification.VerifiedAt,
			}
		}
	}

	if s.dns != nil {
		snapshot, available := s.dns.DNSState()
		if available {
			ladder := make([]string, len(snapshot.Ladder))
			for index, tier := range snapshot.Ladder {
				ladder[index] = string(tier)
			}
			view.DNS = &api.VPNDNSState{
				Ladder:     ladder,
				ActiveTier: string(snapshot.ActiveTier),
				FailClosed: snapshot.FailClosed,
			}
		}
	}

	if s.jobs != nil {
		if id := s.jobs.ActiveJobID(); id != "" {
			view.ActiveJobID = &id
		}
		snapshot, jobID, found := s.jobs.LastCommitted()
		if found {
			view.LastCommitted = &api.VPNCommittedState{
				JobID: jobID,
				At:    snapshot.TakenAt,
			}
			if snapshot.ServerHostname != "" {
				view.Desired = &api.VPNDesiredState{
					Hostname:  snapshot.ServerHostname,
					Transport: snapshotTransport(snapshot),
				}
			}
			if snapshot.Egress != nil {
				verification := snapshot.Egress
				view.Egress = &api.VPNEgressState{
					Verified:   verification.Verified,
					IP:         verification.IP,
					Quorum:     verification.Quorum,
					VerifiedAt: verification.VerifiedAt,
				}
			}
		}
	}
	return view
}

func snapshotTransport(snapshot state.TunnelSnapshot) string {
	if snapshot.TransportDetail != "" {
		return snapshot.TransportDetail
	}
	return snapshot.Transport
}
