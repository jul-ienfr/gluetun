package server

import (
	"net"
	"net/http"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/egress/canary"
	"github.com/qdm12/gluetun/internal/egress/consensus"
	"github.com/qdm12/gluetun/internal/egress/source"
	"github.com/qdm12/gluetun/internal/egress/verify"
)

const (
	defaultEgressSourceTimeout = 1500 * time.Millisecond
	defaultEgressSourceBackoff = 30 * time.Second
	defaultEgressBackoffMax    = 300 * time.Second
	defaultEgressCanaryTimeout = 2 * time.Second
)

func newEgressService(control settings.Control, publicIPLooper PublicIPLoop,
	logger Logger,
) *verify.Service {
	egressSettings := control.Egress
	if egressSettings.Enabled != nil && !*egressSettings.Enabled {
		return nil
	}

	sourceTimeout := egressSettings.SourceTimeout
	if sourceTimeout <= 0 {
		sourceTimeout = defaultEgressSourceTimeout
	}

	canaryTimeout := control.Canary.Timeout
	if canaryTimeout <= 0 {
		canaryTimeout = defaultEgressCanaryTimeout
	}

	dependencies := source.Dependencies{
		HTTPClient: &http.Client{Timeout: sourceTimeout},
		Resolver:   net.DefaultResolver,
		PublicIP:   publicIPLooper,
		Timeout:    sourceTimeout,
	}
	sources, err := source.Build(egressSettings.Sources, dependencies)
	if err != nil {
		logger.Error("building egress sources: " + err.Error())
		return nil
	}

	hostIPs, err := source.HostIPs(hostIPAuto(egressSettings), egressSettings.HostIP)
	if err != nil {
		logger.Warn("capturing host IPs for egress verification: " + err.Error())
	}

	sourceBackoff := egressSettings.SourceBackoff
	if sourceBackoff <= 0 {
		sourceBackoff = defaultEgressSourceBackoff
	}
	sourceBackoffMax := egressSettings.SourceBackoffMax
	if sourceBackoffMax < sourceBackoff {
		sourceBackoffMax = defaultEgressBackoffMax
	}

	return verify.New(verify.Settings{
		Sources: sources,
		Options: consensus.Options{
			Quorum:        int(egressSettings.Quorum),
			MinSources:    int(egressSettings.MinSources),
			AllowSingle:   egressSettings.AllowSingle != nil && *egressSettings.AllowSingle,
			Family:        egressFamily(egressSettings.Family),
			HostIPs:       hostIPs,
			ForbiddenIPs:  egressSettings.ForbiddenIPs,
			AllowTestNets: egressSettings.AllowTestNets != nil && *egressSettings.AllowTestNets,
		},
		CacheTTL:         egressSettings.CacheTTL,
		SourceBackoff:    sourceBackoff,
		SourceBackoffMax: sourceBackoffMax,
		Canary:           canary.New(newCanarySettings(control.Canary), &http.Client{Timeout: canaryTimeout}),
	})
}

func hostIPAuto(egressSettings settings.Egress) bool {
	return egressSettings.HostIPAuto == nil || *egressSettings.HostIPAuto
}

func egressFamily(value string) int {
	const (
		familyIPv4 = 4
		familyIPv6 = 6
		familyBoth = 0
	)
	switch value {
	case "6":
		return familyIPv6
	case "both":
		return familyBoth
	default:
		return familyIPv4
	}
}

func newCanarySettings(settings settings.Canary) canary.Settings {
	return canary.Settings{
		URL:          settings.URL,
		Method:       settings.Method,
		ExpectStatus: int(settings.ExpectStatus),
		MinBodyBytes: int64(settings.MinBodyBytes), //nolint:gosec // body size is a small operator setting
		ExpectSHA256: settings.ExpectSHA256,
		Timeout:      settings.Timeout,
	}
}
