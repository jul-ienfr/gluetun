package catalog

import (
	"slices"
	"strings"

	"github.com/qdm12/gluetun/internal/models"
)

// candidatesFromServers merges the provider entries sharing a hostname. Providers such as
// NordVPN store one entry per VPN type, so the raw catalogue exposes the same
// server twice and each entry only advertises its own protocol.
func candidatesFromServers(servers []models.Server) []ServerCandidate {
	indexes := make(map[string]int, len(servers))
	merged := make([]ServerCandidate, 0, len(servers))
	for _, server := range servers {
		key := strings.ToLower(server.Hostname)
		index, found := indexes[key]
		if !found {
			indexes[key] = len(merged)
			merged = append(merged, Candidate(server))
			continue
		}
		merged[index] = mergeCandidate(merged[index], Candidate(server))
	}
	return merged
}

func mergeCandidate(base, other ServerCandidate) ServerCandidate {
	base.Protocols = appendUnique(base.Protocols, other.Protocols...)
	base.IPs = appendUnique(base.IPs, other.IPs...)
	base.Categories = appendUnique(base.Categories, other.Categories...)
	base.Name = firstNonEmpty(base.Name, other.Name)
	base.Country = firstNonEmpty(base.Country, other.Country)
	base.Region = firstNonEmpty(base.Region, other.Region)
	base.City = firstNonEmpty(base.City, other.City)
	base.ISP = firstNonEmpty(base.ISP, other.ISP)
	base.WGPublicKey = firstNonEmpty(base.WGPublicKey, other.WGPublicKey)
	if base.Number == 0 {
		base.Number = other.Number
	}
	base.Owned = base.Owned || other.Owned
	base.Free = base.Free || other.Free
	base.Premium = base.Premium || other.Premium
	base.Stream = base.Stream || other.Stream
	base.PortForward = base.PortForward || other.PortForward
	return base
}

func appendUnique(values []string, additions ...string) []string {
	for _, addition := range additions {
		if addition == "" || slices.Contains(values, addition) {
			continue
		}
		values = append(values, addition)
	}
	return values
}

func firstNonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
