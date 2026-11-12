package source

import (
	"context"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/models"
)

// Source observes the egress IP through one independent path.
type Source interface {
	Name() string
	Kind() egress.Kind
	Fetch(ctx context.Context, family int) (egress.Observation, error)
}

// Resolver is the tunnel resolver used by the DNS source.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// PublicIPProvider exposes the public IP data already fetched by the fork.
type PublicIPProvider interface {
	GetData() models.PublicIP
}
