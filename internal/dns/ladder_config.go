package dns

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/qdm12/dns/v2/pkg/provider"
	"github.com/qdm12/gluetun/internal/dns/ladder"
)

// LadderOptions configure the DNS ladder used as upstream resolver.
type LadderOptions struct {
	Enabled            bool
	Ladder             []string
	FailClosed         bool
	ProbeDomain        string
	TierProviders      map[string][]string
	DefaultProviders   []string
	PlainAddresses     []netip.AddrPort
	IPv6               bool
	Timeout            time.Duration
	Attempts           int
	FailuresToDown     int
	SuccessesToRecover int
	BaseCooldown       time.Duration
	MaxCooldown        time.Duration
}

func (o LadderOptions) applicable() bool {
	return o.Enabled && len(o.Ladder) > 0
}

func buildLadder(options LadderOptions) (resolver *ladder.Ladder, err error) {
	tierTypes := make([]ladder.TierType, 0, len(options.Ladder))
	endpoints := make(map[ladder.TierType][]ladder.Endpoint,
		len(options.Ladder))
	for _, name := range options.Ladder {
		tierType := ladder.TierType(strings.ToLower(strings.TrimSpace(name)))
		if !tierType.Valid() {
			return nil, fmt.Errorf("unknown DNS tier %q", name)
		}
		tierTypes = append(tierTypes, tierType)

		providerNames := options.providersFor(tierType)
		providers, err := lookupProviders(providerNames, tierType)
		if err != nil {
			return nil, err
		}
		endpoints[tierType] = buildEndpoints(tierType, providers,
			options.PlainAddresses, options.IPv6)
	}

	return ladder.New(ladder.Settings{
		Ladder:    tierTypes,
		Endpoints: endpoints,
		Health: ladder.NewHealth(ladder.HealthSettings{
			FailuresToDown:     options.FailuresToDown,
			SuccessesToRecover: options.SuccessesToRecover,
			BaseCooldown:       options.BaseCooldown,
			MaxCooldown:        options.MaxCooldown,
		}),
		Exchanger:   ladder.NewNetExchanger(),
		Timeout:     options.Timeout,
		Attempts:    options.Attempts,
		FailClosed:  options.FailClosed,
		ProbeDomain: options.ProbeDomain,
	})
}

func (o LadderOptions) providersFor(tierType ladder.TierType) []string {
	names := o.TierProviders[string(tierType)]
	if len(names) > 0 {
		return names
	}
	if tierType == ladder.TierDoH {
		names = o.TierProviders[string(ladder.TierDoT)]
		if len(names) > 0 {
			return names
		}
	}
	return o.DefaultProviders
}

func lookupProviders(names []string, tierType ladder.TierType) (
	providers []provider.Provider, err error,
) {
	providersData := provider.NewProviders()
	providers = make([]provider.Provider, 0, len(names))
	for _, name := range names {
		upstream, err := providersData.Get(name)
		if err != nil {
			return nil, fmt.Errorf("DNS tier %s provider %q: %w",
				tierType, name, err)
		}
		providers = append(providers, upstream)
	}
	return providers, nil
}

func buildEndpoints(tierType ladder.TierType,
	providers []provider.Provider, plainAddresses []netip.AddrPort,
	ipv6 bool,
) []ladder.Endpoint {
	var endpoints []ladder.Endpoint

	if tierType == ladder.TierPlain && len(plainAddresses) > 0 {
		for _, address := range plainAddresses {
			endpoints = append(endpoints, ladder.Endpoint{
				Address:  address.String(),
				Provider: address.Addr().String(),
			})
		}
		return endpoints
	}

	for _, upstream := range providers {
		switch tierType {
		case ladder.TierDoT:
			for _, address := range upstream.DoT.IPv4 {
				endpoints = append(endpoints, ladder.Endpoint{
					Address:  address.String(),
					Provider: upstream.Name,
					TLSName:  upstream.DoT.Name,
				})
			}
			if ipv6 {
				for _, address := range upstream.DoT.IPv6 {
					endpoints = append(endpoints, ladder.Endpoint{
						Address:  address.String(),
						Provider: upstream.Name,
						TLSName:  upstream.DoT.Name,
					})
				}
			}
		case ladder.TierDoH:
			for _, address := range upstream.DoH.IPv4 {
				endpoints = append(endpoints, ladder.Endpoint{
					Address:  netip.AddrPortFrom(address, 443).String(),
					Provider: upstream.Name,
					URL:      upstream.DoH.URL,
				})
			}
			if ipv6 {
				for _, address := range upstream.DoH.IPv6 {
					endpoints = append(endpoints, ladder.Endpoint{
						Address:  netip.AddrPortFrom(address, 443).String(),
						Provider: upstream.Name,
						URL:      upstream.DoH.URL,
					})
				}
			}
		case ladder.TierPlain:
			for _, address := range upstream.Plain.IPv4 {
				endpoints = append(endpoints, ladder.Endpoint{
					Address:  address.String(),
					Provider: upstream.Name,
				})
			}
			if ipv6 {
				for _, address := range upstream.Plain.IPv6 {
					endpoints = append(endpoints, ladder.Endpoint{
						Address:  address.String(),
						Provider: upstream.Name,
					})
				}
			}
		}
	}

	return endpoints
}
