package transport

import (
	"context"
	"errors"
)

// Driver executes transport attempts against the live VPN loop and provides
// the health and reconnect hooks used by the same-server watchdog.
type Driver interface {
	Runner
	HealthProbe
	Reconnector
}

// IntegrationSettings configures the runtime ladder.
type IntegrationSettings struct {
	Policy   Policy
	Driver   Driver
	Metrics  *Metrics
	Watchdog WatchdogSettings
	Events   EventSink
}

// Integration owns the runtime ladder, its service surface and the same-server
// watchdog. The VPN loop calls Run for every tunnel settings change.
type Integration struct {
	ladder   *Ladder
	service  *Service
	watchdog *Watchdog
	driver   Driver
}

// NewIntegration builds a runtime transport ladder.
func NewIntegration(settings IntegrationSettings) (*Integration, error) {
	ladder, err := NewLadder(settings.Policy, settings.Driver,
		WithMetrics(settings.Metrics), WithEventSink(settings.Events))
	if err != nil {
		return nil, err
	}
	return &Integration{
		ladder:   ladder,
		service:  NewService(ladder),
		watchdog: NewWatchdog(settings.Watchdog),
		driver:   settings.Driver,
	}, nil
}

// Service exposes the read-only and reset surface used by the control API.
func (i *Integration) Service() *Service {
	if i == nil {
		return nil
	}
	return i.service
}

// SetEventSink attaches or replaces the control plane event sink.
func (i *Integration) SetEventSink(sink EventSink) {
	if i == nil || i.ladder == nil {
		return
	}
	i.ladder.SetEventSink(sink)
}

// Policy returns the normalized policy.
func (i *Integration) Policy() Policy {
	if i == nil || i.ladder == nil {
		return Policy{}
	}
	return i.ladder.Policy()
}

// Run executes the ladder and then monitors the committed transport until the
// context ends or the watchdog needs a repair. onCommit is called exactly once
// per committed transport, before the watchdog starts.
func (i *Integration) Run(ctx context.Context, target Target,
	onCommit func(Result),
) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var lastResult Result
	for {
		result, err := i.ladder.Run(ctx, target)
		if err != nil {
			return result, err
		}
		lastResult = result
		if onCommit != nil {
			onCommit(result)
		}

		i.watchdog.Reset()
		err = i.watchdog.Run(ctx, i.driver, i.driver, result.Transport, target)
		switch {
		case ctx.Err() != nil:
			return lastResult, ctx.Err()
		case err == nil:
			return lastResult, nil
		case errors.Is(err, ErrRepairNeeded):
			i.ladder.ReportFailure(result.Transport, ReasonInterfaceDown)
		default:
			return lastResult, err
		}
	}
}
