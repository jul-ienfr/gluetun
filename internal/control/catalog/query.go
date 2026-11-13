package catalog

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/qdm12/gluetun/internal/models"
)

// DefaultLimit is the number of servers returned when no limit is given.
const DefaultLimit = 50

// MaxLimit is the maximum number of servers returned per page.
const MaxLimit = 500

// ErrInvalidCursor is returned when a pagination cursor cannot be decoded.
var ErrInvalidCursor = errors.New("invalid cursor")

// Source provides a snapshot of the provider servers.
type Source interface {
	Servers() ([]models.Server, error)
}

// Query filters the catalogue and selects a page of results.
type Query struct {
	Countries  []string
	Regions    []string
	Cities     []string
	ISPs       []string
	Categories []string
	Tiers      []string
	Protocols  []string
	Search     string
	FreeOnly   bool
	OwnedOnly  bool
	StreamOnly bool
	Limit      int
	Cursor     string
}

// Page is one page of catalogue candidates.
type Page struct {
	Items         []ServerCandidate `json:"items"`
	NextCursor    *string           `json:"next_cursor"`
	TotalEstimate int               `json:"total_estimate"`
}

// Catalog exposes read-only views over a provider server source.
type Catalog struct {
	source Source
	stats  StatsProvider
}

// New creates a catalogue reading from the source given.
func New(source Source) *Catalog {
	return &Catalog{source: source}
}

// Query filters and paginates the catalogue.
func (c *Catalog) Query(query Query) (Page, error) {
	servers, err := c.servers()
	if err != nil {
		return Page{}, err
	}

	matched := make([]models.Server, 0, len(servers))
	for _, server := range servers {
		if !matches(server, query) {
			continue
		}
		matched = append(matched, server)
	}
	candidates := candidatesFromServers(matched)

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Hostname < candidates[j].Hostname
	})

	limit := query.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	offset, err := decodeCursor(query.Cursor)
	if err != nil {
		return Page{}, err
	}
	if offset > len(candidates) {
		offset = len(candidates)
	}

	end := offset + limit
	if end > len(candidates) {
		end = len(candidates)
	}

	page := Page{
		Items:         append([]ServerCandidate{}, candidates[offset:end]...),
		TotalEstimate: len(candidates),
	}
	if end < len(candidates) {
		cursor := encodeCursor(end)
		page.NextCursor = &cursor
	}

	return page, nil
}

// Facets returns the distinct values of the whole catalogue.
func (c *Catalog) Facets() (Facets, error) {
	servers, err := c.servers()
	if err != nil {
		return Facets{}, err
	}
	return buildFacets(candidatesFromServers(servers)), nil
}

func (c *Catalog) servers() ([]models.Server, error) {
	if c == nil || c.source == nil {
		return nil, nil
	}
	servers, err := c.source.Servers()
	if err != nil {
		return nil, fmt.Errorf("reading catalogue: %w", err)
	}
	return servers, nil
}

func matches(server models.Server, query Query) bool {
	if !matchesAny(server.Country, query.Countries) {
		return false
	}
	if !matchesAny(server.Region, query.Regions) {
		return false
	}
	if !matchesAny(server.City, query.Cities) {
		return false
	}
	if !matchesAny(server.ISP, query.ISPs) {
		return false
	}
	if !matchesAnyOf(server.Categories, query.Categories) {
		return false
	}
	if !matchesAny(serverTier(server), query.Tiers) {
		return false
	}
	if len(query.Protocols) > 0 &&
		!matchesAnyOf(serverProtocols(server), query.Protocols) {
		return false
	}
	if query.FreeOnly && !server.Free {
		return false
	}
	if query.OwnedOnly && !server.Owned {
		return false
	}
	if query.StreamOnly && !server.Stream {
		return false
	}
	return matchesSearch(server, query.Search)
}

func matchesAny(value string, accepted []string) bool {
	if len(accepted) == 0 {
		return true
	}
	for _, candidate := range accepted {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func matchesAnyOf(values, accepted []string) bool {
	if len(accepted) == 0 {
		return true
	}
	for _, value := range values {
		if matchesAny(value, accepted) {
			return true
		}
	}
	return false
}

func matchesSearch(server models.Server, search string) bool {
	search = strings.TrimSpace(search)
	if search == "" {
		return true
	}
	search = strings.ToLower(search)
	fields := []string{
		server.Hostname,
		server.ServerName,
		server.Country,
		server.Region,
		server.City,
		server.ISP,
	}
	fields = append(fields, server.Categories...)
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), search) {
			return true
		}
	}
	return false
}

func encodeCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(strconv.Itoa(offset)))
}

func decodeCursor(cursor string) (offset int, err error) {
	if cursor == "" {
		return 0, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, ErrInvalidCursor
	}
	offset, err = strconv.Atoi(string(decoded))
	if err != nil || offset < 0 {
		return 0, ErrInvalidCursor
	}
	return offset, nil
}
