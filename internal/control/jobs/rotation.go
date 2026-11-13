package jobs

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/control/catalog"
	"github.com/qdm12/gluetun/internal/control/state"
)

// Rotation errors.
var (
	ErrNoCandidates      = errors.New("no rotation candidate")
	ErrExcludedCandidate = errors.New("rotation candidate is excluded")
	ErrCandidateCooldown = errors.New("rotation candidate is cooling down")
	ErrExhausted         = errors.New("rotation candidates exhausted")
)

// CooldownSource tracks per-hostname cooldowns between rotation attempts.
type CooldownSource interface {
	Available(hostname string, now time.Time) bool
	RecordFailure(hostname string, now time.Time) time.Time
	RecordSuccess(hostname string)
}

const (
	DefaultMaxRotationCandidates = 20
	DefaultMaxRotationAttempts   = 10
)

// RotationTarget is one ordered rotation candidate.
type RotationTarget struct {
	Hostname         string
	EndpointIP       netip.Addr
	ExpectedEgressIP netip.Addr
}

// RotationPolicy selects candidates from the catalogue without re-scoring
// them. The catalogue order is preserved.
type RotationPolicy struct {
	Countries  []string
	Regions    []string
	Cities     []string
	Categories []string
	Tiers      []string
	FreeOnly   bool
	Mode       string
}

// RotationConstraints restrict which candidates may be attempted.
type RotationConstraints struct {
	RequireNewIP     bool
	RequireNewSubnet bool
	ExcludeHostnames []string
	ExcludeIPs       []netip.Addr
	ExcludeSubnets   []netip.Prefix
	ForbiddenIPs     []netip.Addr
	MaxCandidates    int
	MaxAttempts      int
}

// RotationRequest is the normalized rotate request executed by a rotate job.
type RotationRequest struct {
	Candidates     []RotationTarget
	Policy         *RotationPolicy
	Constraints    RotationConstraints
	Options        SwitchOptions
	IdempotencyKey string
	RequestHash    string
	RequestedBy    string
}

// CandidateSource resolves a rotation policy against the read-only catalogue.
type CandidateSource interface {
	Query(query catalog.Query) (catalog.Page, error)
}

func (r RotationRequest) attemptBudget() int {
	budget := r.Constraints.MaxAttempts
	if budget <= 0 {
		budget = DefaultMaxRotationAttempts
	}
	if budget > len(r.Candidates) {
		budget = len(r.Candidates)
	}
	return budget
}

func (c RotationConstraints) maxCandidates() int {
	maxCandidates := c.MaxCandidates
	if maxCandidates <= 0 {
		maxCandidates = DefaultMaxRotationCandidates
	}
	return maxCandidates
}

func (c RotationConstraints) excludesHostname(hostname string) bool {
	for _, excluded := range c.ExcludeHostnames {
		if strings.EqualFold(strings.TrimSpace(excluded), hostname) {
			return true
		}
	}
	return false
}

func (c RotationConstraints) excludesAddress(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	address = address.Unmap()
	if slices.Contains(c.ExcludeIPs, address) ||
		slices.Contains(c.ForbiddenIPs, address) {
		return true
	}
	for _, prefix := range c.ExcludeSubnets {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (r RotationRequest) single(target RotationTarget) SwitchRequest {
	return SwitchRequest{
		Kind: KindRotate,
		Target: SwitchTarget{
			Hostname:         target.Hostname,
			EndpointIP:       target.EndpointIP,
			ExpectedEgressIP: target.ExpectedEgressIP,
		},
		Constraints: SwitchConstraints{
			RequireNewIP:     r.Constraints.RequireNewIP,
			RequireNewSubnet: r.Constraints.RequireNewSubnet,
			ExcludeIPs:       r.Constraints.ExcludeIPs,
			ExcludeSubnets:   r.Constraints.ExcludeSubnets,
			ForbiddenIPs:     r.Constraints.ForbiddenIPs,
		},
		Options: r.Options,
	}
}

func resolveRotationCandidates(request RotationRequest,
	source CandidateSource,
) (candidates []RotationTarget, err error) {
	hasCandidates := len(request.Candidates) > 0
	hasPolicy := request.Policy != nil
	switch {
	case hasCandidates && hasPolicy:
		return nil, fmt.Errorf("%w: candidates and policy are exclusive",
			ErrInvalidTarget)
	case !hasCandidates && !hasPolicy:
		return nil, fmt.Errorf("%w: candidates or policy is required",
			ErrInvalidTarget)
	}

	maxCandidates := request.Constraints.maxCandidates()
	if hasCandidates {
		candidates = make([]RotationTarget, 0, len(request.Candidates))
		for _, candidate := range request.Candidates {
			candidate.Hostname = strings.TrimSpace(candidate.Hostname)
			if candidate.Hostname == "" {
				return nil, fmt.Errorf("%w: candidate hostname is empty",
					ErrInvalidTarget)
			}
			candidates = append(candidates, candidate)
		}
	} else {
		if source == nil {
			return nil, fmt.Errorf("%w: catalogue is not available",
				ErrInvalidTarget)
		}
		candidates, err = queryRotationCandidates(*request.Policy, maxCandidates,
			source)
		if err != nil {
			return nil, err
		}
	}

	deduplicated := make([]RotationTarget, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		key := strings.ToLower(candidate.Hostname)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduplicated = append(deduplicated, candidate)
		if len(deduplicated) == maxCandidates {
			break
		}
	}

	kept := make([]RotationTarget, 0, len(deduplicated))
	for _, candidate := range deduplicated {
		if request.Constraints.excludesHostname(candidate.Hostname) {
			continue
		}
		if request.Constraints.excludesAddress(candidate.EndpointIP) {
			continue
		}
		if request.Constraints.excludesAddress(candidate.ExpectedEgressIP) {
			continue
		}
		kept = append(kept, candidate)
	}
	if len(kept) == 0 {
		return nil, ErrNoCandidates
	}
	return kept, nil
}

func queryRotationCandidates(policy RotationPolicy, limit int,
	source CandidateSource,
) (candidates []RotationTarget, err error) {
	candidates = make([]RotationTarget, 0, limit)
	cursor := ""
	for len(candidates) < limit {
		pageLimit := limit - len(candidates)
		if pageLimit > catalog.MaxLimit {
			pageLimit = catalog.MaxLimit
		}
		page, err := source.Query(catalog.Query{
			Countries:  policy.Countries,
			Regions:    policy.Regions,
			Cities:     policy.Cities,
			Categories: policy.Categories,
			Tiers:      policy.Tiers,
			FreeOnly:   policy.FreeOnly,
			Limit:      pageLimit,
			Cursor:     cursor,
		})
		if err != nil {
			return nil, fmt.Errorf("querying rotation candidates: %w", err)
		}
		for _, item := range page.Items {
			hostname := strings.TrimSpace(item.Hostname)
			if hostname == "" {
				continue
			}
			candidates = append(candidates, RotationTarget{Hostname: hostname})
			if len(candidates) == limit {
				break
			}
		}
		if page.NextCursor == nil || *page.NextCursor == "" {
			break
		}
		cursor = *page.NextCursor
	}
	return candidates, nil
}

func (e *Executor) ExecuteRotation(ctx context.Context, machine *Machine,
	request RotationRequest,
) (result ExecutionResult, err error) {
	timeout := request.Options.Timeout
	if timeout <= 0 {
		timeout = defaultSwitchTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err = machine.Transition(StateValidating)
	if err != nil {
		return result, err
	}

	snapshot, err := e.snapshotter.Capture(ctx, triggerFor(KindRotate))
	if err != nil {
		machine.SetError(err.Error())
		_ = machine.Transition(StateRejected)
		result.Job = machine.Job()
		return result, fmt.Errorf("capturing tunnel snapshot: %w", err)
	}
	machine.SetSnapshotBefore(snapshot)
	result.WouldCutTunnel = true

	budget := request.attemptBudget()
	var lastErr error
	for index := 0; index < budget; index++ {
		candidate := request.Candidates[index]

		if machine.Job().CancelRequested {
			return e.cancelRotation(machine, ctx, snapshot)
		}
		if ctx.Err() != nil {
			return e.cancelRotation(machine, ctx, snapshot)
		}

		if err = machine.Transition(StatePreflight); err != nil {
			return result, err
		}

		if e.rotationCooldownActive(candidate.Hostname) {
			machine.AddAttempt(Attempt{
				Hostname:   candidate.Hostname,
				Phase:      StatePreflight,
				Result:     "skipped",
				Reason:     "cooldown",
				ExpectedIP: candidate.ExpectedEgressIP,
			})
			lastErr = fmt.Errorf("%w: hostname %q",
				ErrCandidateCooldown, candidate.Hostname)
			continue
		}

		if request.Constraints.excludesHostname(candidate.Hostname) {
			machine.AddAttempt(Attempt{
				Hostname: candidate.Hostname,
				Phase:    StatePreflight,
				Result:   "rejected",
				Reason:   "excluded",
			})
			lastErr = fmt.Errorf("%w: hostname %q",
				ErrExcludedCandidate, candidate.Hostname)
			continue
		}

		single := request.single(candidate)
		proven, _, preflightErr := e.inspectPreflight(ctx, single)
		if preflightErr != nil {
			machine.AddAttempt(Attempt{
				Hostname:   candidate.Hostname,
				Phase:      StatePreflight,
				Result:     "rejected",
				Reason:     reasonFor(preflightErr),
				ExpectedIP: candidate.ExpectedEgressIP,
			})
			e.recordRotationFailure(candidate.Hostname)
			lastErr = preflightErr
			continue
		}

		machine.SetTarget(Target{
			Provider:        proven.Provider,
			VPN:             transportVPNType(proven.Transport),
			TransportDetail: string(proven.Transport),
			Hostname:        proven.Hostname,
			EndpointIP:      proven.EndpointIP,
			Port:            proven.Port,
		})

		err = machine.Transition(StateDraining)
		if err != nil {
			return result, err
		}
		err = e.drain(ctx, request.Options.Drain, machine)
		if err != nil {
			return e.cancelBeforeApply(machine, err)
		}

		target := e.targetSnapshot(single, proven)
		err = machine.Transition(StateApplying)
		if err != nil {
			return result, err
		}
		applyCtx, cancelApply := context.WithTimeout(ctx, e.applyTimeout)
		err = e.tunnel.ApplySnapshot(applyCtx, target)
		cancelApply()
		if err != nil {
			lastErr = fmt.Errorf("applying rotation candidate: %w", err)
			if restoreErr := e.restoreCandidate(ctx, machine, snapshot); restoreErr != nil {
				result.Job = machine.Job()
				return result, errors.Join(lastErr, restoreErr)
			}
			machine.AddAttempt(Attempt{
				Hostname:   candidate.Hostname,
				Phase:      StateApplying,
				Result:     "rejected",
				Reason:     rotationReason(StateApplying, err),
				ExpectedIP: candidate.ExpectedEgressIP,
			})
			e.recordRotationFailure(candidate.Hostname)
			continue
		}

		err = machine.Transition(StateAwaitingTunnel)
		if err != nil {
			return result, err
		}
		awaitCtx, cancelAwait := context.WithTimeout(ctx, e.awaitTimeout)
		err = e.tunnel.AwaitSnapshot(awaitCtx, target)
		cancelAwait()
		if err != nil {
			lastErr = fmt.Errorf("awaiting rotation candidate: %w", err)
			if restoreErr := e.restoreCandidate(ctx, machine, snapshot); restoreErr != nil {
				result.Job = machine.Job()
				return result, errors.Join(lastErr, restoreErr)
			}
			machine.AddAttempt(Attempt{
				Hostname:   candidate.Hostname,
				Phase:      StateAwaitingTunnel,
				Result:     "rejected",
				Reason:     rotationReason(StateAwaitingTunnel, err),
				ExpectedIP: candidate.ExpectedEgressIP,
			})
			e.recordRotationFailure(candidate.Hostname)
			continue
		}

		err = machine.Transition(StateVerifyingEgress)
		if err != nil {
			return result, err
		}
		verifyRequest := request.Options.Verify
		verifyRequest.Fresh = true
		verifyCtx, cancelVerify := context.WithTimeout(ctx, e.verifyTimeout)
		verification, verifyErr := e.verifier.Verify(verifyCtx, verifyRequest)
		cancelVerify()
		if verifyErr != nil {
			lastErr = fmt.Errorf("verifying rotation candidate: %w", verifyErr)
			if restoreErr := e.restoreCandidate(ctx, machine, snapshot); restoreErr != nil {
				result.Job = machine.Job()
				return result, errors.Join(lastErr, restoreErr)
			}
			machine.AddAttempt(Attempt{
				Hostname:   candidate.Hostname,
				Phase:      StateVerifyingEgress,
				Result:     "rejected",
				Reason:     rotationReason(StateVerifyingEgress, verifyErr),
				ExpectedIP: candidate.ExpectedEgressIP,
			})
			e.recordRotationFailure(candidate.Hostname)
			continue
		}

		gateErr := checkSwitchGates(single, snapshot, verification)
		if gateErr != nil {
			lastErr = gateErr
			if restoreErr := e.restoreCandidate(ctx, machine, snapshot); restoreErr != nil {
				result.Job = machine.Job()
				return result, errors.Join(lastErr, restoreErr)
			}
			machine.AddAttempt(Attempt{
				Hostname:   candidate.Hostname,
				Phase:      StateVerifyingEgress,
				Result:     "rejected",
				Reason:     reasonFor(gateErr),
				ObservedIP: verification.IP,
				ExpectedIP: candidate.ExpectedEgressIP,
			})
			e.recordRotationFailure(candidate.Hostname)
			continue
		}

		machine.SetVerification(verification)
		err = machine.Transition(StateCommitted)
		if err != nil {
			return result, err
		}
		machine.AddAttempt(Attempt{
			Hostname:   proven.Hostname,
			Phase:      StateCommitted,
			Result:     "committed",
			ObservedIP: verification.IP,
			ExpectedIP: candidate.ExpectedEgressIP,
		})
		e.recordRotationSuccess(candidate.Hostname)
		e.captureAfter(ctx, machine, KindRotate)
		e.emit(EventJobCommitted, machine.Job())
		result.Job = machine.Job()
		return result, nil
	}

	if lastErr == nil {
		lastErr = ErrNoCandidates
	}
	machine.SetError(lastErr.Error())
	err = machine.Transition(StateExhausted)
	if err != nil {
		result.Job = machine.Job()
		return result, err
	}
	machine.SetStationPreserved(true)
	machine.SetGlobalStateWritten(false)
	e.emit(EventJobRejected, machine.Job())
	result.Job = machine.Job()
	return result, fmt.Errorf("%w: %d candidates: %w", ErrExhausted, budget,
		lastErr)
}

func (e *Executor) cancelRotation(machine *Machine, ctx context.Context,
	snapshot state.TunnelSnapshot,
) (result ExecutionResult, err error) {
	if restoreErr := e.restoreCandidate(ctx, machine, snapshot); restoreErr != nil {
		result.Job = machine.Job()
		return result, errors.Join(ErrCanceled, restoreErr)
	}
	transitionErr := machine.Transition(StateCanceled)
	if transitionErr != nil {
		result.Job = machine.Job()
		return result, errors.Join(ErrCanceled, transitionErr)
	}
	machine.SetError(ErrCanceled.Error())
	e.emit(EventJobCanceled, machine.Job())
	result.Job = machine.Job()
	return result, ErrCanceled
}

// restoreCandidate re-applies the station snapshot captured before the
// rotation so the next candidate starts from a preserved station.
func (e *Executor) restoreCandidate(ctx context.Context, machine *Machine,
	snapshot state.TunnelSnapshot,
) error {
	switch machine.Job().State {
	case StateValidating, StatePreflight:
		return nil
	}
	err := machine.Transition(StateRollingBack)
	if err != nil {
		return err
	}
	if snapshot.ServerHostname == "" {
		return machine.Transition(StatePreflight)
	}

	restoreCtx := context.WithoutCancel(ctx)
	applyCtx, cancelApply := context.WithTimeout(restoreCtx, e.applyTimeout)
	err = e.tunnel.ApplySnapshot(applyCtx, snapshot)
	cancelApply()
	if err != nil {
		_ = machine.Transition(StateFailedDegraded)
		return fmt.Errorf("restoring previous tunnel: %w", err)
	}
	awaitCtx, cancelAwait := context.WithTimeout(restoreCtx, e.awaitTimeout)
	err = e.tunnel.AwaitSnapshot(awaitCtx, snapshot)
	cancelAwait()
	if err != nil {
		_ = machine.Transition(StateFailedDegraded)
		return fmt.Errorf("awaiting previous tunnel: %w", err)
	}
	return machine.Transition(StatePreflight)
}

func (e *Executor) rotationCooldownActive(hostname string) bool {
	if e.cooldown == nil {
		return false
	}
	return !e.cooldown.Available(hostname, e.now().UTC())
}

func (e *Executor) recordRotationFailure(hostname string) {
	if e.cooldown == nil {
		return
	}
	e.cooldown.RecordFailure(hostname, e.now().UTC())
}

func (e *Executor) recordRotationSuccess(hostname string) {
	if e.cooldown == nil {
		return
	}
	e.cooldown.RecordSuccess(hostname)
}

func rotationReason(phase State, err error) string {
	reason := reasonFor(err)
	if reason != "failed" {
		return reason
	}
	switch phase {
	case StateApplying:
		return "apply_failed"
	case StateAwaitingTunnel:
		return "tunnel_failed"
	case StateVerifyingEgress:
		return "egress_unverified"
	}
	return reason
}
