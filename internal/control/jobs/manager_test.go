package jobs

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress"
)

func newTestManager(t *testing.T, tunnel *fakeTunnel,
	verifier *fakeVerifier, settings ManagerSettings,
) *Manager {
	t.Helper()

	executor, _ := newTestExecutor(t, tunnel, verifier, switchProber{})
	settings.Executor = executor
	if settings.Now == nil {
		settings.Now = testTime
	}
	return NewManager(settings)
}

func waitJob(t *testing.T, manager *Manager, id string) Job {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	job, err := manager.Wait(ctx, id)
	if err != nil {
		t.Fatalf("waiting for job %s: %v", id, err)
	}
	return job
}

func Test_Manager_SubmitAndRollback(t *testing.T) {
	t.Parallel()

	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.8"),
		verifiedIP("198.51.100.7"),
	}}
	manager := newTestManager(t, &fakeTunnel{}, verifier, ManagerSettings{})

	request := testSwitchRequest()
	request.RequestHash = "hash-1"
	submission, err := manager.Submit(t.Context(), request)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if submission.Job.State != StateQueued {
		t.Errorf("state = %q, want queued", submission.Job.State)
	}

	job := waitJob(t, manager, submission.Job.ID)
	if job.State != StateCommitted {
		t.Fatalf("state = %q, want committed", job.State)
	}

	rollbackRequest := RollbackRequest{RequestHash: "hash-rollback"}
	rollback, err := manager.SubmitRollback(t.Context(), rollbackRequest)
	if err != nil {
		t.Fatalf("submit rollback: %v", err)
	}
	rollbackJob := waitJob(t, manager, rollback.Job.ID)
	if rollbackJob.State != StateRolledBack {
		t.Fatalf("rollback state = %q, want rolled_back",
			rollbackJob.State)
	}
}

func Test_Manager_RestoresLastCommittedAndNotifiesOnCommit(t *testing.T) {
	t.Parallel()

	restored := state.TunnelSnapshot{
		SchemaVersion:   state.SchemaVersion,
		StationID:       "station-1",
		ServerHostname:  "old.example.com",
		TransportDetail: "openvpn-udp",
	}
	committed := make(chan Job, 1)
	snapshots := make(chan state.TunnelSnapshot, 1)
	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.8"),
	}}
	manager := newTestManager(t, &fakeTunnel{}, verifier, ManagerSettings{
		LastCommitted: &restored,
		OnCommit: func(job Job, snapshot state.TunnelSnapshot) {
			committed <- job
			snapshots <- snapshot
		},
	})

	snapshot, jobID, found := manager.LastCommitted()
	if !found {
		t.Fatal("restored snapshot was not found")
	}
	if jobID != "" {
		t.Errorf("restored job id = %q, want empty", jobID)
	}
	if snapshot.ServerHostname != restored.ServerHostname {
		t.Errorf("restored hostname = %q, want %q",
			snapshot.ServerHostname, restored.ServerHostname)
	}

	submission, err := manager.Submit(t.Context(), testSwitchRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	job := waitJob(t, manager, submission.Job.ID)
	if job.State != StateCommitted {
		t.Fatalf("state = %q, want committed", job.State)
	}

	var notified Job
	select {
	case notified = <-committed:
	case <-time.After(5 * time.Second):
		t.Fatal("OnCommit was not called")
	}
	if notified.ID != job.ID {
		t.Errorf("notified job = %q, want %q", notified.ID, job.ID)
	}
	var committedSnapshot state.TunnelSnapshot
	select {
	case committedSnapshot = <-snapshots:
	case <-time.After(5 * time.Second):
		t.Fatal("OnCommit snapshot was not received")
	}
	if committedSnapshot.Egress == nil || !committedSnapshot.Egress.Verified {
		t.Fatal("committed snapshot has no verified egress")
	}

	last, lastID, found := manager.LastCommitted()
	if !found {
		t.Fatal("committed snapshot was not found")
	}
	if lastID != job.ID {
		t.Errorf("last committed job = %q, want %q", lastID, job.ID)
	}
	if last.Egress == nil || last.Egress.IP != committedSnapshot.Egress.IP {
		t.Errorf("last committed egress = %v, want %v",
			last.Egress, committedSnapshot.Egress)
	}
}

func Test_Manager_Idempotency(t *testing.T) {
	t.Parallel()

	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.8"),
	}}
	manager := newTestManager(t, &fakeTunnel{}, verifier, ManagerSettings{})

	request := testSwitchRequest()
	request.IdempotencyKey = "switch-1"
	request.RequestHash = "hash-1"

	submission, err := manager.Submit(t.Context(), request)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitJob(t, manager, submission.Job.ID)

	replayed, err := manager.Submit(t.Context(), request)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replayed.Replayed {
		t.Error("replay was not flagged")
	}
	if replayed.Job.ID != submission.Job.ID {
		t.Errorf("replayed job %q, want %q", replayed.Job.ID,
			submission.Job.ID)
	}

	request.RequestHash = "hash-2"
	_, err = manager.Submit(t.Context(), request)
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("error = %v, want %v", err, ErrIdempotencyConflict)
	}
}

func Test_Manager_ActiveJob(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	tunnel := &fakeTunnel{
		notify:  make(chan struct{}, 1),
		release: release,
	}
	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.8"),
	}}
	manager := newTestManager(t, tunnel, verifier, ManagerSettings{})

	submission, err := manager.Submit(t.Context(), testSwitchRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-tunnel.notify:
	case <-time.After(5 * time.Second):
		t.Fatal("job never reached applying")
	}

	_, err = manager.Submit(t.Context(), testSwitchRequest())
	var active *ActiveJobError
	if !errors.As(err, &active) {
		t.Fatalf("error = %v, want ActiveJobError", err)
	}
	if active.ID != submission.Job.ID {
		t.Errorf("active job = %q, want %q", active.ID, submission.Job.ID)
	}

	close(release)
	job := waitJob(t, manager, submission.Job.ID)
	if job.State != StateCommitted {
		t.Fatalf("state = %q, want committed", job.State)
	}
}

func Test_Manager_CancelDuringApplyingRollsBack(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	tunnel := &fakeTunnel{
		notify:  make(chan struct{}, 1),
		release: release,
	}
	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.7"),
	}}
	manager := newTestManager(t, tunnel, verifier, ManagerSettings{})

	submission, err := manager.Submit(t.Context(), testSwitchRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-tunnel.notify:
	case <-time.After(5 * time.Second):
		t.Fatal("job never reached applying")
	}

	job, err := manager.Cancel(submission.Job.ID)
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if !job.CancelRequested {
		t.Error("cancel request was not recorded")
	}

	close(release)
	job = waitJob(t, manager, submission.Job.ID)
	if job.State != StateRolledBack {
		t.Fatalf("state = %q, want rolled_back", job.State)
	}
}

func Test_Manager_Noop(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, &fakeTunnel{}, &fakeVerifier{},
		ManagerSettings{})
	request := SwitchRequest{
		Kind: KindSwitch,
		Target: SwitchTarget{
			Hostname:   "old.example.com",
			EndpointIP: netip.MustParseAddr("203.0.113.10"),
		},
		Options: SwitchOptions{Timeout: 5 * time.Second},
	}

	submission, err := manager.Submit(t.Context(), request)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if !submission.Noop {
		t.Error("submission was not a noop")
	}
	if submission.Job.ID != "" {
		t.Errorf("noop job ID = %q", submission.Job.ID)
	}
}

func Test_Manager_RollbackWithoutSnapshot(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, &fakeTunnel{}, &fakeVerifier{},
		ManagerSettings{})
	_, err := manager.SubmitRollback(t.Context(), RollbackRequest{})
	if !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("error = %v, want %v", err, ErrNoSnapshot)
	}
}

func Test_Manager_List(t *testing.T) {
	t.Parallel()

	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.8"),
		verifiedIP("198.51.100.9"),
	}}
	manager := newTestManager(t, &fakeTunnel{}, verifier, ManagerSettings{})

	first, err := manager.Submit(t.Context(), testSwitchRequest())
	if err != nil {
		t.Fatalf("submit first: %v", err)
	}
	waitJob(t, manager, first.Job.ID)

	request := testSwitchRequest()
	second, err := manager.Submit(t.Context(), request)
	if err != nil {
		t.Fatalf("submit second: %v", err)
	}
	waitJob(t, manager, second.Job.ID)

	page, err := manager.List(Filter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Jobs) != 2 {
		t.Fatalf("jobs = %d, want 2", len(page.Jobs))
	}
	if page.Jobs[0].ID != second.Job.ID {
		t.Errorf("first listed job = %q, want %q", page.Jobs[0].ID,
			second.Job.ID)
	}

	page, err = manager.List(Filter{Limit: 1})
	if err != nil {
		t.Fatalf("list limit: %v", err)
	}
	if len(page.Jobs) != 1 || page.NextCursor == "" {
		t.Errorf("page = %+v", page)
	}
}

func Test_Manager_Retention(t *testing.T) {
	t.Parallel()

	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.8"),
		verifiedIP("198.51.100.9"),
	}}
	manager := newTestManager(t, &fakeTunnel{}, verifier,
		ManagerSettings{Retention: 1})

	first, err := manager.Submit(t.Context(), testSwitchRequest())
	if err != nil {
		t.Fatalf("submit first: %v", err)
	}
	waitJob(t, manager, first.Job.ID)
	second, err := manager.Submit(t.Context(), testSwitchRequest())
	if err != nil {
		t.Fatalf("submit second: %v", err)
	}
	waitJob(t, manager, second.Job.ID)

	if _, found := manager.Get(first.Job.ID); found {
		t.Error("oldest job was not pruned")
	}
	if _, found := manager.Get(second.Job.ID); !found {
		t.Error("newest job was pruned")
	}
}
