package catalog

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ValidateEndpointIP(t *testing.T) {
	t.Parallel()

	candidate := ServerCandidate{
		Hostname: "nl-1.example.com",
		IPs:      []string{"198.51.100.1", "2001:db8::1"},
	}

	testCases := map[string]struct {
		endpoint netip.Addr
		valid    bool
	}{
		"no endpoint": {
			endpoint: netip.Addr{},
			valid:    true,
		},
		"advertised IPv4": {
			endpoint: netip.MustParseAddr("198.51.100.1"),
			valid:    true,
		},
		"advertised IPv6": {
			endpoint: netip.MustParseAddr("2001:db8::1"),
			valid:    true,
		},
		"unadvertised": {
			endpoint: netip.MustParseAddr("198.51.100.9"),
			valid:    false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := ValidateEndpointIP(candidate, testCase.endpoint)
			if testCase.valid {
				assert.NoError(t, err)
				return
			}
			assert.True(t, errors.Is(err, ErrEndpointIPMismatch))
		})
	}
}

func Test_ValidateEndpointIP_InvalidCandidateIPs(t *testing.T) {
	t.Parallel()

	candidate := ServerCandidate{
		Hostname: "nl-1.example.com",
		IPs:      []string{"not-an-ip"},
	}
	err := ValidateEndpointIP(candidate,
		netip.MustParseAddr("198.51.100.1"))
	assert.True(t, errors.Is(err, ErrEndpointIPMismatch))
}
