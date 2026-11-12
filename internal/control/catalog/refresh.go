package catalog

import (
	"context"
	"errors"
	"fmt"
)

// ErrRefreshUnsupported is returned when the catalogue source cannot refresh.
var ErrRefreshUnsupported = errors.New("catalogue source does not support refresh")

// Refresher is an optional catalogue source able to reload its servers.
type Refresher interface {
	Refresh(ctx context.Context) error
}

// RefreshResult is the outcome of a catalogue refresh.
type RefreshResult struct {
	Refreshed bool `json:"refreshed"`
	Servers   int  `json:"servers"`
}

// Refresh reloads the catalogue from its source.
func (c *Catalog) Refresh(ctx context.Context) (RefreshResult, error) {
	if c == nil || c.source == nil {
		return RefreshResult{}, ErrRefreshUnsupported
	}
	refresher, ok := c.source.(Refresher)
	if !ok {
		return RefreshResult{}, ErrRefreshUnsupported
	}

	err := refresher.Refresh(ctx)
	if err != nil {
		return RefreshResult{}, fmt.Errorf("refreshing catalogue: %w", err)
	}

	servers, err := c.servers()
	if err != nil {
		return RefreshResult{}, err
	}
	return RefreshResult{Refreshed: true, Servers: len(servers)}, nil
}
