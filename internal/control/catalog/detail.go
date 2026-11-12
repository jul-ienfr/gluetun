package catalog

import "strings"

// ServerDetail is the full public view of one server.
type ServerDetail struct {
	ServerCandidate
	AvailableTransports []string    `json:"available_transports"`
	Stats               ServerStats `json:"stats"`
}

// Get looks up one server by hostname.
func (c *Catalog) Get(hostname string) (candidate ServerCandidate, found bool,
	err error,
) {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return ServerCandidate{}, false, nil
	}

	servers, err := c.servers()
	if err != nil {
		return ServerCandidate{}, false, err
	}
	for _, server := range servers {
		if !strings.EqualFold(server.Hostname, hostname) {
			continue
		}
		return Candidate(server), true, nil
	}
	return ServerCandidate{}, false, nil
}

// Detail returns the full public view of one server.
func (c *Catalog) Detail(hostname string) (detail ServerDetail, found bool,
	err error,
) {
	candidate, found, err := c.Get(hostname)
	if err != nil || !found {
		return ServerDetail{}, found, err
	}

	detail = ServerDetail{
		ServerCandidate:     candidate,
		AvailableTransports: AvailableTransports(candidate),
	}
	if c != nil && c.stats != nil {
		detail.Stats = c.stats.LookupStats(candidate.Hostname)
	}
	return detail, true, nil
}
