package jobs

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress/consensus"
	"github.com/qdm12/gluetun/internal/egress/verify"
)

// Switch events.
const (
	EventSwitchNoop   = "switch.noop"
	EventJobCommitted = "job.committed"
	EventJobRejected  = "job.rejected"
	EventJobCanceled  = "job.cancelled"
)

// Switch gate errors.
var (
	ErrEgressUnverified     = errors.New("egress is not verified")
	ErrEgressMismatch       = errors.New("egress IP mismatch")
	ErrSameIP               = errors.New("egress IP is unchanged")
	ErrSameSubnet           = errors.New("egress subnet is unchanged")
	ErrTargetExcluded       = errors.New("target is excluded")
	ErrInvalidSwitchRequest = errors.New("invalid switch request")
	ErrCanceled             = errors.New("job canceled")
)

const (
	defaultSwitchTimeout = 45 * time.Second
	defaultApplyTimeout  = 30 * time.Second
	defaultAwaitTimeout  = 30 * time.Second
	defaultVerifyTimeout = 30 * time.Second
	defaultDrainTimeout  = 5 * time.Second

	estimatedValidatingMS = 20
	estimatedPreflightMS  = 250
	estimatedApplyingMS   = 4000
)

// EventSink receives control plane events. It must not block.
type EventSink func(event string, job Job)

// Snapshotter captures the current tunnel state without changing it.
type Snapshotter interface {
	Capture(ctx context.Context, trigger string) (
		snapshot state.TunnelSnapshot, err error)
}

// SwitchTarget is the requested switch destination.
type SwitchTarget struct {
	Hostname         string
	EndpointIP       netip.Addr
	ExpectedEgressIP netip.Addr
}

// SwitchConstraints are the post-switch gates.
type SwitchConstraints struct {
	RequireNewIP     bool
	RequireNewSubnet bool
	ExcludeIPs       []netip.Addr
	ExcludeSubnets   []netip.Prefix
	ForbiddenIPs     []netip.Addr
}

// DrainOption configures the pre-switch connection drain.
type DrainOption struct {
	Enabled bool
	Timeout time.Duration
}

// SwitchOptions configure one switch execution.
type SwitchOptions struct {
	DryRun          bool
	Wait            bool
	Timeout         time.Duration
	TransportPolicy []Transport
	Drain           DrainOption
	Verify          verify.Request
}

// SwitchRequest is the normalized request executed by a switch or rotate job.
type SwitchRequest struct {
	Kind        Kind
	Provider    string
	VPN         string
	Target      SwitchTarget
	Constraints SwitchConstraints
	Options     SwitchOptions
	Candidates  []string
	// IdempotencyKey replays an identical request instead of creating a job.
	IdempotencyKey string
	// RequestHash is the SHA-256 of the raw HTTP body used by the idempotency
	// index. It is optional outside the API.
	RequestHash string
}

// ExecutorSettings configure the switch executor.
type ExecutorSettings struct {
	StationID   string
	Provider    string
	VPN         string
	Tunnel      Tunnel
	Snapshotter Snapshotter
	Verifier    EgressVerifier
	Preflight   *Preflight
	// DrainActive returns the number of active proxy connections. A nil
	// counter disables the drain even when the request enables it.
	DrainActive func() int
	// Events receives control plane events. It is optional.
	Events EventSink
	// Cooldown tracks per-hostname rotation cooldowns. It is optional.
	Cooldown CooldownSource
	// Now overrides the clock. It is optional.
	Now func() time.Time

	ApplyTimeout  time.Duration
	AwaitTimeout  time.Duration
	VerifyTimeout time.Duration
}

// Executor runs switch transactions against one station.
type Executor struct {
	stationID   string
	provider    string
	vpn         string
	tunnel      Tunnel
	snapshotter Snapshotter
	verifier    EgressVerifier
	preflight   *Preflight
	rollback    *Rollback
	drainActive func() int
	events      EventSink
	cooldown    CooldownSource
	now         func() time.Time

	applyTimeout  time.Duration
	awaitTimeout  time.Duration
	verifyTimeout time.Duration
}

// NewExecutor creates a switch executor.
func NewExecutor(settings ExecutorSettings) *Executor {
	if settings.Tunnel == nil {
		panic("executor tunnel is nil")
	}
	if settings.Snapshotter == nil {
		panic("executor snapshotter is nil")
	}
	if settings.Verifier == nil {
		panic("executor verifier is nil")
	}
	if settings.Preflight == nil {
		panic("executor preflight is nil")
	}

	now := settings.Now
	if now == nil {
		now = time.Now
	}
	applyTimeout := settings.ApplyTimeout
	if applyTimeout <= 0 {
		applyTimeout = defaultApplyTimeout
	}
	awaitTimeout := settings.AwaitTimeout
	if awaitTimeout <= 0 {
		awaitTimeout = defaultAwaitTimeout
	}
	verifyTimeout := settings.VerifyTimeout
	if verifyTimeout <= 0 {
		verifyTimeout = defaultVerifyTimeout
	}

	return &Executor{
		stationID:     settings.StationID,
		provider:      settings.Provider,
		vpn:           settings.VPN,
		tunnel:        settings.Tunnel,
		snapshotter:   settings.Snapshotter,
		verifier:      settings.Verifier,
		preflight:     settings.Preflight,
		drainActive:   settings.DrainActive,
		events:        settings.Events,
		cooldown:      settings.Cooldown,
		now:           now,
		applyTimeout:  applyTimeout,
		awaitTimeout:  awaitTimeout,
		verifyTimeout: verifyTimeout,
		rollback: NewRollback(RollbackSettings{
			Tunnel:        settings.Tunnel,
			Verifier:      settings.Verifier,
			ApplyTimeout:  applyTimeout,
			AwaitTimeout:  awaitTimeout,
			VerifyTimeout: verifyTimeout,
		}),
	}
}

// Plan is the dry-run description of one switch.
type Plan struct {
	Target            PlanTarget       `json:"target"`
	ResolvedIPs       []netip.Addr     `json:"resolved_ips"`
	Transport         Transport        `json:"transport"`
	TransportPolicy   string           `json:"transport_policy"`
	EstimatedPhasesMS map[string]int64 `json:"estimated_phases_ms"`
	Warnings          []string         `json:"warnings"`
}

// PlanTarget is the resolved plan target.
type PlanTarget struct {
	Hostname   string     `json:"hostname"`
	EndpointIP netip.Addr `json:"endpoint_ip"`
}

// Inspection is the result of the read-only preflight phase.
type Inspection struct {
	Preflight      PreflightResult
	SnapshotBefore state.TunnelSnapshot
	Plan           Plan
	Noop           bool
	WouldCutTunnel bool
}

// ExecutionResult is the outcome of one switch execution.
type ExecutionResult struct {
	Job            Job
	Plan           Plan
	Noop           bool
	WouldCutTunnel bool
}

// Inspect validates the target, resolves the transport and captures the
// current tunnel state without changing anything.
func (e *Executor) Inspect(ctx context.Context,
	request SwitchRequest,
) (inspection Inspection, err error) {
	err = validateSwitchRequest(request)
	if err != nil {
		return Inspection{}, err
	}

	timeout := request.Options.Timeout
	if timeout <= 0 {
		timeout = defaultSwitchTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, warnings, err := e.inspectPreflight(ctx, request)
	if err != nil {
		return Inspection{}, err
	}

	snapshot, err := e.snapshotter.Capture(ctx, triggerFor(request.Kind))
	if err != nil {
		return Inspection{}, fmt.Errorf("capturing tunnel snapshot: %w", err)
	}

	plan := Plan{
		Target: PlanTarget{
			Hostname:   result.Hostname,
			EndpointIP: result.EndpointIP,
		},
		ResolvedIPs:     result.ResolvedIPs,
		Transport:       result.Transport,
		TransportPolicy: transportPolicyLabel(request.Options.TransportPolicy),
		EstimatedPhasesMS: map[string]int64{
			"validating": estimatedValidatingMS,
			"preflight":  estimatedPreflightMS,
			"applying":   estimatedApplyingMS,
		},
		Warnings: warnings,
	}

	noop := isNoop(request, snapshot, result)
	return Inspection{
		Preflight:      result,
		SnapshotBefore: snapshot,
		Plan:           plan,
		Noop:           noop,
		WouldCutTunnel: !noop,
	}, nil
}

// inspectPreflight validates one target and resolves its transport ladder
// without capturing a snapshot or changing the tunnel.
func (e *Executor) inspectPreflight(ctx context.Context, request SwitchRequest) (
	result PreflightResult, warnings []string, err error,
) {
	target := e.normalizeTarget(request)
	err = request.Constraints.check(target, request.Target.ExpectedEgressIP)
	if err != nil {
		return PreflightResult{}, nil, err
	}

	ladder, err := e.transportLadder(request.Options.TransportPolicy)
	if err != nil {
		return PreflightResult{}, nil, err
	}

	warnings = make([]string, 0, len(ladder))
	for _, transport := range ladder {
		attemptTarget := target
		attemptTarget.VPN = transportVPNType(transport)
		result, err = e.preflight.Check(ctx, PreflightRequest{
			Target:    attemptTarget,
			Transport: transport,
		})
		if err == nil {
			break
		}
		if !transportRetryable(err) {
			return PreflightResult{}, nil, err
		}
		warnings = append(warnings, err.Error())
	}
	if err != nil {
		return PreflightResult{}, nil, err
	}
	warnings = append(warnings,
		preflightWarnings(ladder, result.Transport)...)
	return result, warnings, nil
}

// Execute runs the switch transaction described by the inspection.
func (e *Executor) Execute(ctx context.Context, machine *Machine,
	request SwitchRequest, inspection Inspection,
) (result ExecutionResult, err error) {
	timeout := request.Options.Timeout
	if timeout <= 0 {
		timeout = defaultSwitchTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result.Plan = inspection.Plan
	result.WouldCutTunnel = inspection.WouldCutTunnel

	err = machine.Transition(StateValidating)
	if err != nil {
		return result, err
	}
	machine.SetTarget(Target{
		Provider:        inspection.Preflight.Provider,
		VPN:             transportVPNType(inspection.Preflight.Transport),
		TransportDetail: string(inspection.Preflight.Transport),
		Hostname:        inspection.Preflight.Hostname,
		EndpointIP:      inspection.Preflight.EndpointIP,
		Port:            inspection.Preflight.Port,
	})
	machine.SetSnapshotBefore(inspection.SnapshotBefore)

	err = machine.Transition(StatePreflight)
	if err != nil {
		return result, err
	}

	if inspection.Noop {
		err = machine.Transition(StateRejected)
		if err != nil {
			return result, err
		}
		e.emit(EventSwitchNoop, machine.Job())
		result.Job = machine.Job()
		return result, nil
	}

	err = machine.Transition(StateDraining)
	if err != nil {
		return result, err
	}
	err = e.drain(ctx, request.Options.Drain, machine)
	if err != nil {
		return e.cancelBeforeApply(machine, err)
	}

	target := e.targetSnapshot(request, inspection.Preflight)
	err = machine.Transition(StateApplying)
	if err != nil {
		return result, err
	}
	applyCtx, cancelApply := context.WithTimeout(ctx, e.applyTimeout)
	err = e.tunnel.ApplySnapshot(applyCtx, target)
	cancelApply()
	if err != nil {
		return e.failAfterApply(ctx, machine, request,
			fmt.Errorf("applying switch target: %w", err))
	}

	err = machine.Transition(StateAwaitingTunnel)
	if err != nil {
		return result, err
	}
	awaitCtx, cancelAwait := context.WithTimeout(ctx, e.awaitTimeout)
	err = e.tunnel.AwaitSnapshot(awaitCtx, target)
	cancelAwait()
	if err != nil {
		return e.failAfterApply(ctx, machine, request,
			fmt.Errorf("awaiting tunnel: %w", err))
	}
	if machine.Job().CancelRequested {
		return e.failAfterApply(ctx, machine, request, ErrCanceled)
	}

	err = machine.Transition(StateVerifyingEgress)
	if err != nil {
		return result, err
	}
	verifyRequest := request.Options.Verify
	verifyRequest.Fresh = true
	verifyCtx, cancelVerify := context.WithTimeout(ctx, e.verifyTimeout)
	verification, err := verifyEgressUntilVerified(verifyCtx, e.verifier,
		verifyRequest)
	cancelVerify()
	if err != nil {
		return e.failAfterApply(ctx, machine, request,
			fmt.Errorf("verifying egress: %w", err))
	}
	result.Job = machine.Job()

	err = checkSwitchGates(request, inspection.SnapshotBefore, verification)
	if err != nil {
		return e.failAfterApply(ctx, machine, request, err)
	}
	if machine.Job().CancelRequested {
		return e.failAfterApply(ctx, machine, request, ErrCanceled)
	}

	machine.SetVerification(verification)
	err = machine.Transition(StateCommitted)
	if err != nil {
		return result, err
	}
	machine.AddAttempt(Attempt{
		Hostname:   inspection.Preflight.Hostname,
		Phase:      StateCommitted,
		StartedAt:  machine.Job().CreatedAt,
		Result:     "committed",
		ObservedIP: verification.IP,
		ExpectedIP: request.Target.ExpectedEgressIP,
	})
	e.captureAfter(ctx, machine, request.Kind)
	e.emit(EventJobCommitted, machine.Job())

	result.Job = machine.Job()
	return result, nil
}

// ExecuteRollback runs a standalone rollback job against the snapshot recorded
// as the last committed state.
func (e *Executor) ExecuteRollback(ctx context.Context, machine *Machine,
) (result ExecutionResult, err error) {
	err = machine.Transition(StateValidating)
	if err != nil {
		return result, err
	}
	job := machine.Job()
	if job.SnapshotBefore == nil {
		err = machine.Transition(StateRejected)
		if err != nil {
			return result, err
		}
		machine.SetError(ErrNoSnapshot.Error())
		result.Job = machine.Job()
		e.emit(EventJobRejected, result.Job)
		return result, ErrNoSnapshot
	}

	err = machine.Transition(StatePreflight)
	if err != nil {
		return result, err
	}
	err = machine.Transition(StateDraining)
	if err != nil {
		return result, err
	}
	err = machine.Transition(StateApplying)
	if err != nil {
		return result, err
	}

	rollbackResult, rollbackErr := e.rollback.Run(ctx, machine)
	if rollbackResult.Event != "" {
		e.emit(rollbackResult.Event, machine.Job())
	}
	if rollbackErr != nil {
		machine.SetError(rollbackErr.Error())
	}
	result.Job = machine.Job()
	return result, rollbackErr
}

func (e *Executor) drain(ctx context.Context, option DrainOption,
	machine *Machine,
) error {
	if !option.Enabled || e.drainActive == nil {
		return nil
	}
	timeout := option.Timeout
	if timeout <= 0 {
		timeout = defaultDrainTimeout
	}
	drain := NewDrain(e.drainActive, timeout)
	err := drain.Wait(ctx)
	if errors.Is(err, ErrDrainTimeout) {
		e.emit(EventDrainTimeout, machine.Job())
		return nil
	}
	return err
}

func (e *Executor) cancelBeforeApply(machine *Machine, cause error) (
	result ExecutionResult, err error,
) {
	job := machine.Job()
	if IsActive(job.State) {
		transitionErr := machine.Transition(StateCanceled)
		if transitionErr != nil {
			return result, errors.Join(cause, transitionErr)
		}
	}
	machine.SetError(cause.Error())
	e.emit(EventJobCanceled, machine.Job())
	result.Job = machine.Job()
	return result, cause
}

func (e *Executor) failAfterApply(ctx context.Context, machine *Machine,
	request SwitchRequest, cause error,
) (result ExecutionResult, err error) {
	machine.SetError(cause.Error())
	machine.AddAttempt(Attempt{
		Hostname:   request.Target.Hostname,
		Phase:      machine.Job().State,
		StartedAt:  machine.Job().CreatedAt,
		Result:     "rejected",
		Reason:     reasonFor(cause),
		ExpectedIP: request.Target.ExpectedEgressIP,
	})

	rollbackCtx := context.WithoutCancel(ctx)
	rollbackResult, rollbackErr := e.rollback.Run(rollbackCtx, machine)
	if rollbackResult.Event != "" {
		e.emit(rollbackResult.Event, machine.Job())
	}
	if rollbackErr != nil {
		machine.SetError(errors.Join(cause, rollbackErr).Error())
	}
	result.Job = machine.Job()
	return result, errors.Join(cause, rollbackErr)
}

func (e *Executor) captureAfter(ctx context.Context, machine *Machine,
	kind Kind,
) {
	snapshot, err := e.snapshotter.Capture(ctx, triggerFor(kind))
	if err != nil {
		return
	}
	machine.SetSnapshotAfter(snapshot)
}

func (e *Executor) emit(event string, job Job) {
	if e.events == nil {
		return
	}
	e.events(event, job)
}

func (e *Executor) normalizeTarget(request SwitchRequest) Target {
	provider := request.Provider
	if provider == "" {
		provider = e.provider
	}
	vpn := request.VPN
	if vpn == "" {
		vpn = e.vpn
	}
	return Target{
		Provider:   provider,
		VPN:        vpn,
		Hostname:   request.Target.Hostname,
		EndpointIP: request.Target.EndpointIP,
	}
}

// ValidateTransportPolicy normalizes and validates a transport policy without
// probing any endpoint.
func (e *Executor) ValidateTransportPolicy(policy []Transport) error {
	_, err := e.transportLadder(policy)
	return err
}

func (e *Executor) transportLadder(policy []Transport) ([]Transport,
	error,
) {
	if len(policy) > 0 {
		ladder := make([]Transport, 0, len(policy))
		for _, transport := range policy {
			if !isKnownTransport(transport) {
				return nil, fmt.Errorf("%w: unknown transport %q",
					ErrInvalidTarget, transport)
			}
			if e.vpn != "" && transportVPNType(transport) != e.vpn {
				return nil, fmt.Errorf(
					"%w: transport %q does not match VPN %q",
					ErrInvalidTarget, transport, e.vpn)
			}
			if !slices.Contains(ladder, transport) {
				ladder = append(ladder, transport)
			}
		}
		return ladder, nil
	}

	switch e.vpn {
	case VPNWireGuard:
		return []Transport{TransportWireGuard}, nil
	case VPNOpenVPN:
		return []Transport{TransportOpenVPNUDP, TransportOpenVPNTCP}, nil
	}
	return []Transport{
		TransportWireGuard, TransportOpenVPNUDP, TransportOpenVPNTCP,
	}, nil
}

func (e *Executor) targetSnapshot(request SwitchRequest,
	result PreflightResult,
) state.TunnelSnapshot {
	return state.TunnelSnapshot{
		SchemaVersion: state.SchemaVersion,
		StationID:     e.stationID,
		TakenAt:       e.now().UTC(),
		Trigger:       triggerFor(request.Kind),
		Settings: state.TunnelSettings{
			Provider:  result.Provider,
			VPN:       transportVPNType(result.Transport),
			Hostnames: []string{result.Hostname},
		},
		ServerHostname:  result.Hostname,
		EndpointIP:      result.EndpointIP,
		Transport:       transportVPNType(result.Transport),
		TransportDetail: string(result.Transport),
	}
}

func validateSwitchRequest(request SwitchRequest) error {
	switch request.Kind {
	case KindSwitch, KindRotate:
	case KindRollback, KindRecover:
		return fmt.Errorf("%w: kind %q is not a switch", ErrInvalidSwitchRequest,
			request.Kind)
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidSwitchRequest,
			request.Kind)
	}
	if strings.TrimSpace(request.Target.Hostname) == "" {
		return fmt.Errorf("%w: hostname is empty", ErrInvalidTarget)
	}
	if request.Target.EndpointIP.IsValid() {
		err := checkPublicAddr(request.Target.EndpointIP)
		if err != nil {
			return err
		}
	}
	if request.Target.ExpectedEgressIP.IsValid() {
		err := checkPublicAddr(request.Target.ExpectedEgressIP)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkPublicAddr(address netip.Addr) error {
	reason := consensus.RejectionReason(address,
		consensus.Options{AllowTestNets: true})
	if reason != "" {
		return fmt.Errorf("%w: %s is not public: %s", ErrInvalidTarget,
			address, reason)
	}
	return nil
}

func transportRetryable(err error) bool {
	return errors.Is(err, ErrMissingCredentials) ||
		errors.Is(err, ErrTransportUnsupported) ||
		errors.Is(err, ErrEndpointUnreachable)
}

func preflightWarnings(ladder []Transport, chosen Transport) []string {
	warnings := make([]string, 0, len(ladder))
	for _, transport := range ladder {
		if transport == chosen {
			return warnings
		}
		warnings = append(warnings,
			fmt.Sprintf("transport %s is not available", transport))
	}
	return warnings
}

func transportPolicyLabel(policy []Transport) string {
	if len(policy) == 0 {
		return "auto"
	}
	values := make([]string, len(policy))
	for i, transport := range policy {
		values[i] = string(transport)
	}
	return strings.Join(values, ",")
}

func isKnownTransport(transport Transport) bool {
	switch transport {
	case TransportWireGuard, TransportOpenVPNUDP, TransportOpenVPNTCP:
		return true
	}
	return false
}

func transportVPNType(transport Transport) string {
	switch transport {
	case TransportWireGuard:
		return VPNWireGuard
	case TransportOpenVPNUDP, TransportOpenVPNTCP:
		return VPNOpenVPN
	}
	return VPNOpenVPN
}

func triggerFor(kind Kind) string {
	switch kind {
	case KindSwitch:
		return string(KindSwitch)
	case KindRotate:
		return "rotate"
	case KindRollback:
		return "rollback"
	case KindRecover:
		return "recovery"
	}
	return string(KindSwitch)
}

func reasonFor(err error) string {
	return Reason(err)
}

// Reason returns the machine-readable reason of a switch failure.
func Reason(err error) string {
	switch {
	case errors.Is(err, ErrEgressUnverified):
		return "egress_unverified"
	case errors.Is(err, ErrEgressMismatch):
		return "egress_mismatch"
	case errors.Is(err, ErrSameIP):
		return "same_ip"
	case errors.Is(err, ErrSameSubnet):
		return "same_subnet"
	case errors.Is(err, ErrTargetExcluded):
		return "forbidden_ip"
	case errors.Is(err, ErrEndpointUnreachable):
		return "preflight_failed"
	case errors.Is(err, ErrUnknownTarget), errors.Is(err, ErrInvalidTarget):
		return "preflight_failed"
	case errors.Is(err, ErrResolutionFailed):
		return "resolution_failed"
	case errors.Is(err, ErrMissingCredentials):
		return "missing_credentials"
	case errors.Is(err, ErrTransportUnsupported):
		return "unsupported_transport"
	case errors.Is(err, ErrCanceled):
		return "cancel_requested"
	}
	return "failed"
}
