package catalog

import (
	"sort"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

// ServerCandidate is the public, secret-free view of a provider server.
type ServerCandidate struct {
	Hostname    string   `json:"hostname"`
	Name        string   `json:"name,omitempty"`
	Number      uint16   `json:"number,omitempty"`
	Country     string   `json:"country,omitempty"`
	Region      string   `json:"region,omitempty"`
	City        string   `json:"city,omitempty"`
	ISP         string   `json:"isp,omitempty"`
	Categories  []string `json:"categories,omitempty"`
	Tier        string   `json:"tier"`
	Owned       bool     `json:"owned"`
	Free        bool     `json:"free"`
	Premium     bool     `json:"premium"`
	Stream      bool     `json:"stream,omitempty"`
	PortForward bool     `json:"port_forward,omitempty"`
	Protocols   []string `json:"protocols"`
	IPs         []string `json:"ips,omitempty"`
	WGPublicKey string   `json:"wg_public_key,omitempty"`
}

// FacetValue is one bucket of a catalogue facet.
type FacetValue struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// Facets are the distinct values of the catalogue with their counts.
type Facets struct {
	Countries  []FacetValue `json:"countries"`
	Regions    []FacetValue `json:"regions"`
	Cities     []FacetValue `json:"cities"`
	ISPs       []FacetValue `json:"isps"`
	Categories []FacetValue `json:"categories"`
	Tiers      []FacetValue `json:"tiers"`
}

const (
	tierFree     = "free"
	tierPremium  = "premium"
	tierStandard = "standard"
)

// Candidate converts a provider server to its public representation.
func Candidate(server models.Server) ServerCandidate {
	candidate := ServerCandidate{
		Hostname:    server.Hostname,
		Name:        server.ServerName,
		Number:      server.Number,
		Country:     server.Country,
		Region:      server.Region,
		City:        server.City,
		ISP:         server.ISP,
		Categories:  append([]string(nil), server.Categories...),
		Tier:        serverTier(server),
		Owned:       server.Owned,
		Free:        server.Free,
		Premium:     server.Premium,
		Stream:      server.Stream,
		PortForward: server.PortForward,
		Protocols:   serverProtocols(server),
		WGPublicKey: server.WgPubKey,
	}

	if len(server.IPs) > 0 {
		candidate.IPs = make([]string, len(server.IPs))
		for index, address := range server.IPs {
			candidate.IPs[index] = address.String()
		}
	}

	return candidate
}

func serverTier(server models.Server) string {
	switch {
	case server.Free:
		return tierFree
	case server.Premium:
		return tierPremium
	default:
		return tierStandard
	}
}

func serverProtocols(server models.Server) []string {
	switch server.VPN {
	case vpn.Wireguard:
		return []string{"wireguard"}
	case vpn.AmneziaWg:
		return []string{"amneziawg"}
	case vpn.OpenVPN:
		protocols := make([]string, 0, 2)
		if server.UDP {
			protocols = append(protocols, "openvpn-udp")
		}
		if server.TCP {
			protocols = append(protocols, "openvpn-tcp")
		}
		return protocols
	default:
		if server.VPN == "" {
			return nil
		}
		return []string{server.VPN}
	}
}

func buildFacets(servers []models.Server) Facets {
	countries := map[string]int{}
	regions := map[string]int{}
	cities := map[string]int{}
	isps := map[string]int{}
	categories := map[string]int{}
	tiers := map[string]int{}

	for _, server := range servers {
		increment(countries, server.Country)
		increment(regions, server.Region)
		increment(cities, server.City)
		increment(isps, server.ISP)
		for _, category := range server.Categories {
			increment(categories, category)
		}
		increment(tiers, serverTier(server))
	}

	return Facets{
		Countries:  sortedFacet(countries),
		Regions:    sortedFacet(regions),
		Cities:     sortedFacet(cities),
		ISPs:       sortedFacet(isps),
		Categories: sortedFacet(categories),
		Tiers:      sortedFacet(tiers),
	}
}

func increment(counter map[string]int, value string) {
	if value == "" {
		return
	}
	counter[value]++
}

func sortedFacet(counter map[string]int) []FacetValue {
	values := make([]FacetValue, 0, len(counter))
	for value, count := range counter {
		values = append(values, FacetValue{Value: value, Count: count})
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Count != values[j].Count {
			return values[i].Count > values[j].Count
		}
		return values[i].Value < values[j].Value
	})
	return values
}
