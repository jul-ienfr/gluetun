package catalog

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// QueryFromValues parses the URL query parameters of GET /v1/servers.
func QueryFromValues(values url.Values) (Query, error) {
	query := Query{
		Countries:  cleanValues(values["country"]),
		Regions:    cleanValues(values["region"]),
		Cities:     cleanValues(values["city"]),
		ISPs:       cleanValues(values["isp"]),
		Categories: cleanValues(values["category"]),
		Tiers:      cleanValues(values["tier"]),
		Protocols:  cleanValues(values["protocol"]),
		Search:     strings.TrimSpace(values.Get("q")),
		Cursor:     strings.TrimSpace(values.Get("cursor")),
	}

	var err error
	query.FreeOnly, err = parseBool(values, "free_only")
	if err != nil {
		return Query{}, err
	}
	query.OwnedOnly, err = parseBool(values, "owned_only")
	if err != nil {
		return Query{}, err
	}
	query.StreamOnly, err = parseBool(values, "stream_only")
	if err != nil {
		return Query{}, err
	}

	query.Limit, err = parseLimit(values)
	if err != nil {
		return Query{}, err
	}

	return query, nil
}

func cleanValues(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				cleaned = append(cleaned, part)
			}
		}
	}
	return cleaned
}

func parseBool(values url.Values, field string) (bool, error) {
	value := strings.TrimSpace(values.Get(field))
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", field)
	}
	return parsed, nil
}

func parseLimit(values url.Values) (int, error) {
	value := strings.TrimSpace(values.Get("limit"))
	if value == "" {
		return DefaultLimit, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("limit must be a positive integer")
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	return limit, nil
}
