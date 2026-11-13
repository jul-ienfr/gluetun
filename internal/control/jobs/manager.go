package jobs

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/control/state"
)

// Manager errors.
var ErrJobNotFound = errors.New("job not found")

// ActiveJobError reports that the station already runs a job.
type ActiveJobError struct {
	ID string
}

func (e *ActiveJobError) Error() string {
	return "job " + e.ID + " is already active"
}

// Submission is the outcome of a switch or rotate request.
type Submission struct {
	Job      Job
	Noop     bool
	Replayed bool
}

// PlanResult is the outcome of a dry-run request.
type PlanResult struct {
	Plan           Plan
	Noop           bool
	WouldCutTunnel bool
}

// RollbackRequest is a standalone rollback to the last committed snapshot.
type RollbackRequest struct {
	RequestHash    string
	IdempotencyKey string
	RequestedBy    string
}

// Filter selects jobs in a list request.
type Filter struct {
	State  State
	Kind   Kind
	Since  time.Time
	Limit  int
	Cursor string
}

// Page is one page of jobs, newest first.
type Page struct {
	Jobs       []Job
	NextCursor string
}

// ManagerSettings configure the job manager.
type ManagerSettings struct {
	Executor *Executor
	Catalog  CandidateSource
	// LastCommitted restores the committed snapshot from the persisted state so
	// a rollback remains possible after a restart.
	LastCommitted *state.TunnelSnapshot
	// OnCommit receives every committed snapshot. It is optional and must not
	// block for long.
	OnCommit          func(job Job, snapshot state.TunnelSnapshot)
	Retention         int
	IdempotencyWindow time.Duration
	Now               func() time.Time
}

const (
	defaultRetention    = 500
	maxManagerListLimit = 200
)

// Manager owns the jobs of one station.
type Manager struct {
	executor    *Executor
	catalog     CandidateSource
	retention   int
	now         func() time.Time
	idempotency *Idempotency

	mutex           sync.Mutex
	entries         map[string]*jobEntry
	order           []string
	activeJobID     string
	lastCommitted   *state.TunnelSnapshot
	lastCommittedID string
	onCommit        func(job Job, snapshot state.TunnelSnapshot)
	sequence        uint64
}

type jobEntry struct {
	machine  *Machine
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

func (e *jobEntry) requestStop() {
	e.stopOnce.Do(func() {
		close(e.stop)
	})
}

// NewManager creates a job manager.
func NewManager(settings ManagerSettings) *Manager {
	if settings.Executor == nil {
		panic("manager executor is nil")
	}
	now := settings.Now
	if now == nil {
		now = time.Now
	}
	retention := settings.Retention
	if retention <= 0 {
		retention = defaultRetention
	}
	window := settings.IdempotencyWindow
	if window <= 0 {
		window = DefaultIdempotencyWindow
	}
	return &Manager{
		executor:      settings.Executor,
		catalog:       settings.Catalog,
		retention:     retention,
		now:           now,
		idempotency:   NewIdempotency(window, now),
		entries:       make(map[string]*jobEntry),
		lastCommitted: cloneSnapshot(settings.LastCommitted),
		onCommit:      settings.OnCommit,
	}
}

func cloneSnapshot(snapshot *state.TunnelSnapshot) *state.TunnelSnapshot {
	if snapshot == nil {
		return nil
	}
	cloned := *snapshot
	return &cloned
}

// Submit validates and queues a switch or rotate job.
func (m *Manager) Submit(ctx context.Context,
	request SwitchRequest,
) (submission Submission, err error) {
	hash := requestHash(request)

	replayed, found, err := m.replay(request.IdempotencyKey, hash)
	if err != nil {
		return Submission{}, err
	}
	if found {
		return Submission{Job: replayed, Replayed: true}, nil
	}

	active := m.activeError()
	if active != nil {
		return Submission{}, active
	}

	inspection, err := m.executor.Inspect(ctx, request)
	if err != nil {
		return Submission{}, err
	}
	if inspection.Noop {
		return Submission{Noop: true}, nil
	}

	m.mutex.Lock()
	if m.activeJobID != "" {
		id := m.activeJobID
		m.mutex.Unlock()
		return Submission{}, &ActiveJobError{ID: id}
	}
	entry, job := m.newEntryLocked(request, inspection)
	if request.IdempotencyKey != "" {
		existing, reserveErr := m.idempotency.Reserve(
			request.IdempotencyKey, hash, job.ID)
		if reserveErr != nil {
			m.removeLocked(job.ID)
			m.mutex.Unlock()
			return Submission{}, reserveErr
		}
		if existing != "" {
			replayedEntry, ok := m.entries[existing]
			m.mutex.Unlock()
			if !ok {
				return Submission{}, ErrJobNotFound
			}
			return Submission{
				Job:      replayedEntry.machine.Job(),
				Replayed: true,
			}, nil
		}
	}
	m.mutex.Unlock()

	//nolint:gosec // jobs outlive the HTTP request that created them
	go m.run(entry, request, inspection)
	return Submission{Job: job}, nil
}

// SubmitRotation validates and queues a rotation job against ordered
// candidates. Candidates are never re-scored or re-sorted.
func (m *Manager) SubmitRotation(ctx context.Context,
	request RotationRequest,
) (submission Submission, err error) {
	hash := request.RequestHash
	if hash == "" {
		hash = HashBody([]byte(fmt.Sprintf("%#v", request)))
	}

	replayed, found, err := m.replay(request.IdempotencyKey, hash)
	if err != nil {
		return Submission{}, err
	}
	if found {
		return Submission{Job: replayed, Replayed: true}, nil
	}

	active := m.activeError()
	if active != nil {
		return Submission{}, active
	}

	err = m.executor.ValidateTransportPolicy(request.Options.TransportPolicy)
	if err != nil {
		return Submission{}, err
	}

	candidates, err := resolveRotationCandidates(request, m.catalog)
	if err != nil {
		return Submission{}, err
	}
	request.Candidates = candidates

	m.mutex.Lock()
	if m.activeJobID != "" {
		id := m.activeJobID
		m.mutex.Unlock()
		return Submission{}, &ActiveJobError{ID: id}
	}
	entry, job := m.newRotationEntryLocked(request)
	if request.IdempotencyKey != "" {
		existing, reserveErr := m.idempotency.Reserve(
			request.IdempotencyKey, hash, job.ID)
		if reserveErr != nil {
			m.removeLocked(job.ID)
			m.mutex.Unlock()
			return Submission{}, reserveErr
		}
		if existing != "" {
			replayedEntry, ok := m.entries[existing]
			m.mutex.Unlock()
			if !ok {
				return Submission{}, ErrJobNotFound
			}
			return Submission{
				Job:      replayedEntry.machine.Job(),
				Replayed: true,
			}, nil
		}
	}
	m.mutex.Unlock()

	//nolint:gosec // jobs outlive the HTTP request that created them
	go m.runRotation(entry, request)
	return Submission{Job: job}, nil
}

// Plan validates a switch request without creating a job.
func (m *Manager) Plan(ctx context.Context,
	request SwitchRequest,
) (result PlanResult, err error) {
	inspection, err := m.executor.Inspect(ctx, request)
	if err != nil {
		return PlanResult{}, err
	}
	return PlanResult{
		Plan:           inspection.Plan,
		Noop:           inspection.Noop,
		WouldCutTunnel: inspection.WouldCutTunnel,
	}, nil
}

// SubmitRollback queues a rollback to the last committed snapshot.
func (m *Manager) SubmitRollback(_ context.Context,
	request RollbackRequest,
) (submission Submission, err error) {
	hash := request.RequestHash
	if hash == "" {
		hash = HashBody(nil)
	}
	replayed, found, err := m.replay(request.IdempotencyKey, hash)
	if err != nil {
		return Submission{}, err
	}
	if found {
		return Submission{Job: replayed, Replayed: true}, nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.activeJobID != "" {
		return Submission{}, &ActiveJobError{ID: m.activeJobID}
	}
	if m.lastCommitted == nil {
		return Submission{}, ErrNoSnapshot
	}
	snapshot := *m.lastCommitted
	entry, job := m.newRollbackEntryLocked(snapshot, request)
	if request.IdempotencyKey != "" {
		existing, reserveErr := m.idempotency.Reserve(
			request.IdempotencyKey, hash, job.ID)
		if reserveErr != nil {
			m.removeLocked(job.ID)
			return Submission{}, reserveErr
		}
		if existing != "" {
			replayedEntry, ok := m.entries[existing]
			if !ok {
				return Submission{}, ErrJobNotFound
			}
			return Submission{
				Job:      replayedEntry.machine.Job(),
				Replayed: true,
			}, nil
		}
	}

	//nolint:gosec // jobs outlive the HTTP request that created them
	go m.runRollback(entry)
	return Submission{Job: job}, nil
}

// Get returns one job.
func (m *Manager) Get(id string) (Job, bool) {
	m.mutex.Lock()
	entry, ok := m.entries[id]
	m.mutex.Unlock()
	if !ok {
		return Job{}, false
	}
	return entry.machine.Job(), true
}

// List returns a page of jobs, newest first.
func (m *Manager) List(filter Filter) (page Page, err error) {
	limit := filter.Limit
	switch {
	case limit <= 0:
		limit = 50
	case limit > maxManagerListLimit:
		limit = maxManagerListLimit
	}
	if filter.State != "" && !isKnownState(filter.State) {
		return Page{}, fmt.Errorf("%w: unknown state %q", ErrInvalidTarget,
			filter.State)
	}
	if filter.Kind != "" && !isKnownKind(filter.Kind) {
		return Page{}, fmt.Errorf("%w: unknown kind %q", ErrInvalidTarget,
			filter.Kind)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	jobs := make([]Job, 0, len(m.order))
	for index := len(m.order) - 1; index >= 0; index-- {
		entry, ok := m.entries[m.order[index]]
		if !ok {
			continue
		}
		job := entry.machine.Job()
		if !jobMatchesFilter(job, filter) {
			continue
		}
		jobs = append(jobs, job)
	}

	start := 0
	if filter.Cursor != "" {
		start = len(jobs)
		for index, job := range jobs {
			if job.ID == filter.Cursor {
				start = index + 1
				break
			}
		}
	}
	jobs = jobs[start:]

	page.Jobs = make([]Job, 0, limit)
	if len(jobs) > limit {
		page.Jobs = jobs[:limit]
		page.NextCursor = jobs[limit-1].ID
		return page, nil
	}
	page.Jobs = jobs
	return page, nil
}

// Cancel cancels a job. Before the tunnel is applied the job stops at once;
// afterwards the request is recorded and the rollback keeps running.
func (m *Manager) Cancel(id string) (Job, error) {
	m.mutex.Lock()
	entry, ok := m.entries[id]
	m.mutex.Unlock()
	if !ok {
		return Job{}, ErrJobNotFound
	}

	canceled, err := entry.machine.Cancel()
	if err != nil {
		return entry.machine.Job(), err
	}
	if canceled {
		entry.requestStop()
	}
	return entry.machine.Job(), nil
}

// Wait blocks until the job reaches a terminal state or the context ends.
func (m *Manager) Wait(ctx context.Context, id string) (Job, error) {
	m.mutex.Lock()
	entry, ok := m.entries[id]
	m.mutex.Unlock()
	if !ok {
		return Job{}, ErrJobNotFound
	}

	select {
	case <-entry.done:
		return entry.machine.Job(), nil
	case <-ctx.Done():
		return entry.machine.Job(), ctx.Err()
	}
}

func (m *Manager) run(entry *jobEntry, request SwitchRequest,
	inspection Inspection,
) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-entry.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	_, _ = m.executor.Execute(ctx, entry.machine, request, inspection)
	m.finish(entry)
}

func (m *Manager) runRotation(entry *jobEntry, request RotationRequest) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-entry.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	_, _ = m.executor.ExecuteRotation(ctx, entry.machine, request)
	m.finish(entry)
}

func (m *Manager) runRollback(entry *jobEntry) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-entry.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	_, _ = m.executor.ExecuteRollback(ctx, entry.machine)
	m.finish(entry)
}

func (m *Manager) finish(entry *jobEntry) {
	job := entry.machine.Job()

	m.mutex.Lock()

	if m.activeJobID == job.ID {
		m.activeJobID = ""
	}
	var committed *state.TunnelSnapshot
	if job.State == StateCommitted {
		committed = m.committedSnapshot(job)
		if committed != nil {
			m.lastCommitted = committed
			m.lastCommittedID = job.ID
		}
	}
	m.pruneLocked()
	onCommit := m.onCommit
	m.mutex.Unlock()

	if committed != nil && onCommit != nil {
		onCommit(job, *committed)
	}

	m.mutex.Lock()
	select {
	case <-entry.done:
	default:
		close(entry.done)
	}
	m.mutex.Unlock()
}

// ActiveJobID returns the identifier of the running job, or an empty string.
func (m *Manager) ActiveJobID() string {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.activeJobID
}

// LastCommitted returns the last committed snapshot and the job which produced
// it.
func (m *Manager) LastCommitted() (snapshot state.TunnelSnapshot, jobID string,
	found bool,
) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.lastCommitted == nil {
		return state.TunnelSnapshot{}, "", false
	}
	return *m.lastCommitted, m.lastCommittedID, true
}

func (m *Manager) committedSnapshot(job Job) *state.TunnelSnapshot {
	if job.SnapshotAfter != nil {
		snapshot := *job.SnapshotAfter
		return &snapshot
	}
	if job.Verification == nil {
		return nil
	}
	now := m.now().UTC()
	return &state.TunnelSnapshot{
		SchemaVersion: state.SchemaVersion,
		StationID:     job.StationID,
		TakenAt:       now,
		Trigger:       string(KindSwitch),
		Settings: state.TunnelSettings{
			Provider:  job.Target.Provider,
			VPN:       job.Target.VPN,
			Hostnames: []string{job.Target.Hostname},
		},
		ServerHostname:  job.Target.Hostname,
		EndpointIP:      job.Target.EndpointIP,
		Transport:       job.Target.VPN,
		TransportDetail: job.Target.TransportDetail,
		Egress:          job.Verification,
		ProvenAt:        &now,
	}
}

func (m *Manager) activeError() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.activeJobID == "" {
		return nil
	}
	return &ActiveJobError{ID: m.activeJobID}
}

func (m *Manager) replay(key, hash string) (job Job, found bool, err error) {
	if key == "" {
		return Job{}, false, nil
	}
	id, found, err := m.idempotency.LookupRequest(key, hash)
	if err != nil {
		return Job{}, false, err
	}
	if !found {
		return Job{}, false, nil
	}
	m.mutex.Lock()
	entry, exists := m.entries[id]
	m.mutex.Unlock()
	if !exists {
		m.idempotency.Forget(key)
		return Job{}, false, nil
	}
	return entry.machine.Job(), true, nil
}

func (m *Manager) newEntryLocked(request SwitchRequest,
	inspection Inspection,
) (entry *jobEntry, job Job) {
	now := m.now().UTC()
	job = Job{
		ID:        m.newIDLocked(now),
		Kind:      request.Kind,
		State:     StateQueued,
		StationID: m.executor.stationID,
		CreatedAt: now,
		UpdatedAt: now,
		Target: Target{
			Provider:        inspection.Preflight.Provider,
			VPN:             transportVPNType(inspection.Preflight.Transport),
			TransportDetail: string(inspection.Preflight.Transport),
			Hostname:        inspection.Preflight.Hostname,
			EndpointIP:      inspection.Preflight.EndpointIP,
			Port:            inspection.Preflight.Port,
		},
		Candidates:     slices.Clone(request.Candidates),
		IdempotencyKey: request.IdempotencyKey,
	}
	return m.registerLocked(job), job
}

func (m *Manager) newRotationEntryLocked(request RotationRequest) (
	entry *jobEntry, job Job,
) {
	now := m.now().UTC()
	hostnames := make([]string, len(request.Candidates))
	for index, candidate := range request.Candidates {
		hostnames[index] = candidate.Hostname
	}
	first := request.Candidates[0]
	job = Job{
		ID:        m.newIDLocked(now),
		Kind:      KindRotate,
		State:     StateQueued,
		StationID: m.executor.stationID,
		CreatedAt: now,
		UpdatedAt: now,
		Target: Target{
			Hostname:   first.Hostname,
			EndpointIP: first.EndpointIP,
		},
		Candidates:     hostnames,
		IdempotencyKey: request.IdempotencyKey,
		RequestedBy:    request.RequestedBy,
	}
	return m.registerLocked(job), job
}

func (m *Manager) newRollbackEntryLocked(snapshot state.TunnelSnapshot,
	request RollbackRequest,
) (entry *jobEntry, job Job) {
	now := m.now().UTC()
	job = Job{
		ID:        m.newIDLocked(now),
		Kind:      KindRollback,
		State:     StateQueued,
		StationID: m.executor.stationID,
		CreatedAt: now,
		UpdatedAt: now,
		Target: Target{
			Provider:        snapshot.Settings.Provider,
			VPN:             snapshot.Transport,
			TransportDetail: snapshot.TransportDetail,
			Hostname:        snapshot.ServerHostname,
			EndpointIP:      snapshot.EndpointIP,
		},
		SnapshotBefore: &snapshot,
		IdempotencyKey: request.IdempotencyKey,
		RequestedBy:    request.RequestedBy,
	}
	return m.registerLocked(job), job
}

func (m *Manager) registerLocked(job Job) *jobEntry {
	machine := NewMachine(job, m.now)
	entry := &jobEntry{
		machine: machine,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	m.entries[job.ID] = entry
	m.order = append(m.order, job.ID)
	m.activeJobID = job.ID
	return entry
}

func (m *Manager) newIDLocked(now time.Time) string {
	m.sequence++
	return fmt.Sprintf("job-%d-%06d", now.UnixNano(), m.sequence)
}

func (m *Manager) removeLocked(id string) {
	delete(m.entries, id)
	for index, candidate := range m.order {
		if candidate == id {
			m.order = append(m.order[:index], m.order[index+1:]...)
			break
		}
	}
	if m.activeJobID == id {
		m.activeJobID = ""
	}
}

func (m *Manager) pruneLocked() {
	if len(m.order) <= m.retention {
		return
	}
	keep := make(map[string]struct{}, m.retention)
	kept := make([]string, 0, m.retention)
	for index := len(m.order) - 1; index >= 0; index-- {
		id := m.order[index]
		if len(kept) < m.retention || id == m.activeJobID {
			kept = append(kept, id)
			keep[id] = struct{}{}
		}
	}
	for id := range m.entries {
		if _, ok := keep[id]; !ok {
			delete(m.entries, id)
		}
	}
	slices.Reverse(kept)
	m.order = kept
}

func jobMatchesFilter(job Job, filter Filter) bool {
	if filter.State != "" && job.State != filter.State {
		return false
	}
	if filter.Kind != "" && job.Kind != filter.Kind {
		return false
	}
	if !filter.Since.IsZero() && job.CreatedAt.Before(filter.Since) {
		return false
	}
	return true
}

func isKnownState(state State) bool {
	switch state {
	case StateQueued, StateValidating, StatePreflight, StateDraining,
		StateApplying, StateAwaitingTunnel, StateVerifyingEgress,
		StateRollingBack, StateCommitted, StateRejected, StateRolledBack,
		StateFailedDegraded, StateExhausted, StateCanceled, StateInterrupted:
		return true
	}
	return false
}

func isKnownKind(kind Kind) bool {
	switch kind {
	case KindSwitch, KindRotate, KindRollback, KindRecover:
		return true
	}
	return false
}

func requestHash(request SwitchRequest) string {
	if request.RequestHash != "" {
		return request.RequestHash
	}
	return HashBody([]byte(fmt.Sprintf("%#v", request)))
}
