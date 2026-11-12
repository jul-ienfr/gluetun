package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
)

const maxHTTPBodyBytes = 64 << 10

type httpSource struct {
	name    string
	url     string
	client  *http.Client
	timeout time.Duration
}

// newHTTP creates an HTTP egress source. The URL is operator-configured and
// must answer with a bare IP, a JSON string or a JSON object carrying it.
func newHTTP(name, url string, client *http.Client,
	timeout time.Duration,
) *httpSource {
	return &httpSource{
		name:    name,
		url:     url,
		client:  client,
		timeout: timeout,
	}
}

func (s *httpSource) Name() string {
	return s.name
}

func (s *httpSource) Kind() egress.Kind {
	return egress.KindHTTP
}

func (s *httpSource) Fetch(ctx context.Context, _ int) (
	observation egress.Observation, err error,
) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	start := time.Now()
	observation = egress.Observation{
		Source:     s.name,
		Kind:       egress.KindHTTP,
		ObservedAt: start.UTC(),
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return observation, fmt.Errorf("building request: %w", err)
	}
	request.Header.Set("Accept", "application/json, text/plain")

	response, err := s.client.Do(request)
	if err != nil {
		return observation, wrapFetchError(ctx, err)
	}
	defer response.Body.Close()

	observation.LatencyMS = time.Since(start).Milliseconds()

	switch {
	case response.StatusCode == http.StatusTooManyRequests:
		return observation, fmt.Errorf("%w: %s", ErrBanned, response.Status)
	case response.StatusCode != http.StatusOK:
		return observation, fmt.Errorf("%w: %s", ErrHTTPStatus, response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxHTTPBodyBytes))
	if err != nil {
		return observation, fmt.Errorf("reading response: %w", err)
	}

	ip, payload, err := parseHTTPBody(body)
	if err != nil {
		return observation, err
	}
	observation.IP = ip
	observation.Country = payload.Country
	observation.Region = payload.Region
	observation.City = payload.City
	observation.ASN = payload.ASN
	observation.Organization = payload.Organization
	return observation, nil
}

type httpPayload struct {
	IP           string `json:"ip"`
	Query        string `json:"query"`
	YourFusedIP  string `json:"YourFusedIP"`
	Country      string `json:"country"`
	Region       string `json:"region"`
	City         string `json:"city"`
	ASN          uint   `json:"asn"`
	Organization string `json:"org"`
}

func parseHTTPBody(body []byte) (ip netip.Addr, payload httpPayload,
	err error,
) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ip, payload, ErrEmpty
	}

	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, `"`) {
		return parseJSONBody(trimmed)
	}

	ip, err = parseIP(trimmed)
	return ip, payload, err
}

func parseJSONBody(trimmed string) (ip netip.Addr, payload httpPayload,
	err error,
) {
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err == nil {
		candidate := firstNonEmpty(payload.IP, payload.Query, payload.YourFusedIP)
		if candidate == "" {
			return ip, payload, fmt.Errorf("%w: no IP field", ErrMalformed)
		}
		ip, err = parseIP(candidate)
		if err == nil {
			return ip, payload, nil
		}
	}

	var raw string
	if err := json.Unmarshal([]byte(trimmed), &raw); err == nil {
		ip, err = parseIP(raw)
		if err == nil {
			return ip, payload, nil
		}
	}
	return ip, payload, fmt.Errorf("%w: no IP in JSON body", ErrMalformed)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func parseIP(value string) (addr netip.Addr, err error) {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	if value == "" {
		return addr, ErrEmpty
	}
	if strings.Contains(value, ":") && strings.Count(value, ":") == 1 {
		// host:port is not accepted as an egress IP.
		return addr, fmt.Errorf("%w: %q", ErrMalformed, value)
	}
	addr, err = netip.ParseAddr(value)
	if err != nil {
		return addr, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return addr.Unmap(), nil
}

func wrapFetchError(ctx context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrTimeout, err)
	}
	return err
}
