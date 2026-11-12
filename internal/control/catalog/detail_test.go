package catalog

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeStats struct {
	stats map[string]ServerStats
}

func (f fakeStats) LookupStats(hostname string) ServerStats {
	return f.stats[hostname]
}

func Test_Catalog_Get(t *testing.T) {
	t.Parallel()

	catalog := newTestCatalog()

	candidate, found, err := catalog.Get("NL-1.Example.com")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "nl-1.example.com", candidate.Hostname)

	_, found, err = catalog.Get("missing.example.com")
	require.NoError(t, err)
	assert.False(t, found)

	_, found, err = catalog.Get("   ")
	require.NoError(t, err)
	assert.False(t, found)
}

func Test_Catalog_Detail(t *testing.T) {
	t.Parallel()

	cooldown := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	catalog := newTestCatalog()
	catalog.SetStatsProvider(fakeStats{stats: map[string]ServerStats{
		"de-2.example.com": {
			CooldownUntil: &cooldown,
			Successes:     3,
			Failures:      1,
		},
	}})

	detail, found, err := catalog.Detail("de-2.example.com")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "premium", detail.Tier)
	assert.Equal(t, []string{"wireguard"}, detail.AvailableTransports)
	require.NotNil(t, detail.Stats.CooldownUntil)
	assert.Equal(t, cooldown, *detail.Stats.CooldownUntil)
	assert.Equal(t, uint64(3), detail.Stats.Successes)

	detail, found, err = catalog.Detail("nl-1.example.com")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, []string{"openvpn-udp", "openvpn-tcp"},
		detail.AvailableTransports)
	assert.Nil(t, detail.Stats.CooldownUntil)
}

func Test_Catalog_Detail_Error(t *testing.T) {
	t.Parallel()

	catalog := New(fakeSource{err: errors.New("boom")})
	_, _, err := catalog.Detail("nl-1.example.com")
	assert.Error(t, err)
}

func Test_AvailableTransports(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		protocols []string
		expected  []string
	}{
		"wireguard": {
			protocols: []string{"wireguard"},
			expected:  []string{"wireguard"},
		},
		"openvpn": {
			protocols: []string{"openvpn-tcp", "openvpn-udp"},
			expected:  []string{"openvpn-udp", "openvpn-tcp"},
		},
		"unknown ignored": {
			protocols: []string{"amneziawg"},
			expected:  []string{},
		},
		"empty": {
			expected: []string{},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			transports := AvailableTransports(ServerCandidate{
				Protocols: testCase.protocols,
			})
			assert.Equal(t, testCase.expected, transports)
		})
	}
}
