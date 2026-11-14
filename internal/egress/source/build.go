package source

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const sourceSpecParts = 2

func httpSourceURL(name string) (url string, ok bool) {
	switch name {
	case "ipify":
		return "https://api.ipify.org?format=json", true
	case "ifconfig":
		return "https://ifconfig.me/ip", true
	case "icanhazip":
		return "https://icanhazip.com", true
	case "cloudflare":
		// Literal address: the answer does not need the tunnel DNS, which
		// breaks the startup deadlock where egress verification waits for a
		// resolver that only works once the tunnel is verified.
		return "http://1.1.1.1/cdn-cgi/trace", true
	default:
		return "", false
	}
}

func dnsSourceQuery(name string) (query string, ok bool) {
	switch name {
	case "whoami":
		return "whoami.cloudflare.", true
	case "opendns":
		return "myip.opendns.com.", true
	default:
		return "", false
	}
}

// Dependencies are the fixed objects used to build sources.
type Dependencies struct {
	HTTPClient *http.Client
	Resolver   Resolver
	PublicIP   PublicIPProvider
	Timeout    time.Duration
}

// Build resolves kind:name source specifications into ready sources.
func Build(specifications []string, dependencies Dependencies) (
	sources []Source, err error,
) {
	sources = make([]Source, 0, len(specifications))
	for _, specification := range specifications {
		source, err := buildOne(specification, dependencies)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, nil
}

//nolint:ireturn // the factory returns one of the source implementations
func buildOne(specification string, dependencies Dependencies) (Source, error) {
	parts := strings.SplitN(specification, ":", sourceSpecParts)
	if len(parts) != sourceSpecParts || parts[1] == "" {
		return nil, fmt.Errorf("source %q is not in the kind:name format", specification)
	}
	kind, name := parts[0], parts[1]

	switch kind {
	case "http", "static":
		return buildHTTP(specification, kind, name, dependencies)
	case "dns":
		query, ok := dnsSourceQuery(name)
		if !ok {
			if !strings.Contains(name, ".") {
				return nil, fmt.Errorf("unknown DNS source %q", name)
			}
			query = name
		}
		if dependencies.Resolver == nil {
			panic("DNS resolver is nil")
		}
		return newDNS(specification, query, dependencies.Resolver,
			dependencies.Timeout), nil
	case "publicip":
		if dependencies.PublicIP == nil {
			panic("public IP provider is nil")
		}
		return newPublicIP(specification, dependencies.PublicIP), nil
	default:
		return nil, fmt.Errorf("unknown source kind %q", kind)
	}
}

func buildHTTP(specification, kind, name string,
	dependencies Dependencies,
) (*httpSource, error) {
	if dependencies.HTTPClient == nil {
		panic("HTTP client is nil")
	}
	url, err := httpURL(kind, name)
	if err != nil {
		return nil, err
	}
	return newHTTP(specification, url, dependencies.HTTPClient,
		dependencies.Timeout), nil
}

func httpURL(kind, name string) (url string, err error) {
	switch kind {
	case "static":
		if !isHTTPURL(name) {
			return "", fmt.Errorf("static source %q is not a URL", name)
		}
		return name, nil
	case "http":
		knownURL, ok := httpSourceURL(name)
		if ok {
			return knownURL, nil
		}
		if !isHTTPURL(name) {
			return "", fmt.Errorf("unknown HTTP source %q", name)
		}
		return name, nil
	default:
		return "", fmt.Errorf("unknown source kind %q", kind)
	}
}

func isHTTPURL(value string) bool {
	return strings.HasPrefix(value, "http://") ||
		strings.HasPrefix(value, "https://")
}
