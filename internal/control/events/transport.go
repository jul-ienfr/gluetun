package events

import (
	transportpkg "github.com/qdm12/gluetun/internal/vpn/transport"
)

// NewTransportSink maps transport ladder events onto the control plane bus.
// Every ladder event produces exactly one bus event.
func NewTransportSink(bus *Bus, log *FileLog, warn func(string),
) transportpkg.EventSink {
	return func(event transportpkg.Event) {
		if event.Type == "" {
			return
		}
		data := make(map[string]any, 8)
		if event.Transport != "" {
			data["transport"] = string(event.Transport)
		}
		if event.Server != "" {
			data["server"] = event.Server
		}
		if event.Attempt > 0 {
			data["attempt"] = event.Attempt
		}
		if event.Result != "" {
			data["result"] = string(event.Result)
		}
		if event.Reason != "" {
			data["reason"] = string(event.Reason)
		}
		if event.LatencyMS > 0 {
			data["latency_ms"] = event.LatencyMS
		}
		if event.Cycle > 0 {
			data["cycle"] = event.Cycle
		}
		if len(event.Ladder) > 0 {
			ladder := make([]string, len(event.Ladder))
			for i, transport := range event.Ladder {
				ladder[i] = string(transport)
			}
			data["ladder"] = ladder
		}
		if len(event.Reasons) > 0 {
			reasons := make([]string, len(event.Reasons))
			for i, reason := range event.Reasons {
				reasons[i] = string(reason)
			}
			data["reasons"] = reasons
		}
		if event.EgressIP.IsValid() {
			data["egress_ip"] = event.EgressIP.String()
		}
		if event.Failures > 0 {
			data["failures"] = event.Failures
		}
		if !event.RetryAt.IsZero() {
			data["retry_at"] = event.RetryAt
		}
		if event.Cycles > 0 {
			data["cycles"] = event.Cycles
		}

		published := bus.Publish(Event{
			Type:     event.Type,
			Severity: transportSeverity(event.Type),
			Data:     data,
		})
		if published.Seq == 0 {
			if warn != nil {
				warn("control plane event bus is closed")
			}
			return
		}
		if log == nil {
			return
		}
		err := log.Append(published)
		if err != nil && warn != nil {
			warn("persisting control plane event: " + err.Error())
		}
	}
}

func transportSeverity(eventType string) string {
	switch eventType {
	case transportpkg.EventFailed, transportpkg.EventBreakerOpen,
		transportpkg.EventCycleExhausted, transportpkg.EventRepairNeeded:
		return SeverityWarning
	default:
		return SeverityInfo
	}
}
