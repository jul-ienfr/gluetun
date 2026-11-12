package source

import (
	"context"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
)

type publicIPSource struct {
	name     string
	provider PublicIPProvider
}

// newPublicIP creates a source reading the fork public IP data.
func newPublicIP(name string, provider PublicIPProvider) *publicIPSource {
	return &publicIPSource{
		name:     name,
		provider: provider,
	}
}

func (s *publicIPSource) Name() string {
	return s.name
}

func (s *publicIPSource) Kind() egress.Kind {
	return egress.KindPublicIP
}

func (s *publicIPSource) Fetch(_ context.Context, _ int) (
	observation egress.Observation, err error,
) {
	start := time.Now()
	data := s.provider.GetData()

	observation = egress.Observation{
		Source:       s.name,
		Kind:         egress.KindPublicIP,
		IP:           data.IP.Unmap(),
		Country:      data.Country,
		Region:       data.Region,
		City:         data.City,
		Organization: data.Organization,
		ObservedAt:   start.UTC(),
	}
	if !observation.IP.IsValid() {
		return observation, ErrEmpty
	}
	return observation, nil
}
