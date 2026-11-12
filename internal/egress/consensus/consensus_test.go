package consensus

import (
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testNow() time.Time {
	return time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
}

func observation(source string, kind egress.Kind, ip string) egress.Observation {
	observation := egress.Observation{
		Source:     source,
		Kind:       kind,
		ObservedAt: testNow(),
	}
	if ip != "" {
		observation.IP = netip.MustParseAddr(ip)
	}
	return observation
}

func failedObservation(source string, reason egress.Reason) egress.Observation {
	return egress.Observation{
		Source: source,
		Kind:   egress.KindHTTP,
		Error:  &egress.SourceError{Reason: reason},
	}
}

func Test_Evaluate(t *testing.T) {
	t.Parallel()

	defaultOptions := Options{Quorum: 2, MinSources: 3}
	allowSingleOptions := Options{Quorum: 1, MinSources: 3, AllowSingle: true}
	testNetOptions := Options{Quorum: 2, MinSources: 3, AllowTestNets: true}

	testCases := map[string]struct {
		observations       []egress.Observation
		options            Options
		expectedVerified   bool
		expectedIP         string
		expectedQuorum     int
		expectedSourceN    int
		expectedConfidence egress.Confidence
		expectedDissenters []string
		expectedReason     egress.Reason
		expectedSingle     bool
	}{
		"quorum with one dissenter": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "23.1.2.3"),
				observation("dns:whoami", egress.KindDNS, "23.1.2.3"),
				observation("http:ifconfig", egress.KindHTTP, "45.6.7.8"),
			},
			options:            defaultOptions,
			expectedVerified:   true,
			expectedIP:         "23.1.2.3",
			expectedQuorum:     2,
			expectedSourceN:    3,
			expectedConfidence: egress.ConfidenceMedium,
			expectedDissenters: []string{"http:ifconfig"},
		},
		"all agree": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "23.1.2.3"),
				observation("dns:whoami", egress.KindDNS, "23.1.2.3"),
				observation("publicip:internal", egress.KindPublicIP, "23.1.2.3"),
			},
			options:            defaultOptions,
			expectedVerified:   true,
			expectedIP:         "23.1.2.3",
			expectedQuorum:     3,
			expectedSourceN:    3,
			expectedConfidence: egress.ConfidenceHigh,
		},
		"insufficient sources": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "23.1.2.3"),
			},
			options:          defaultOptions,
			expectedSourceN:  1,
			expectedReason:   egress.ReasonInsufficientSources,
			expectedVerified: false,
		},
		"host ip rejected everywhere": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "198.18.0.9"),
				observation("dns:whoami", egress.KindDNS, "198.18.0.9"),
				observation("publicip:internal", egress.KindPublicIP, "198.18.0.9"),
			},
			options: func() Options {
				options := defaultOptions
				options.HostIPs = []netip.Addr{netip.MustParseAddr("198.18.0.9")}
				return options
			}(),
			expectedSourceN:  3,
			expectedReason:   egress.ReasonNoQuorum,
			expectedVerified: false,
		},
		"no quorum": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "23.1.2.3"),
				observation("dns:whoami", egress.KindDNS, "45.6.7.8"),
				observation("http:ifconfig", egress.KindHTTP, "89.10.11.12"),
			},
			options:          defaultOptions,
			expectedSourceN:  3,
			expectedReason:   egress.ReasonNoQuorum,
			expectedVerified: false,
		},
		"failed source still counts as available": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "23.1.2.3"),
				observation("dns:whoami", egress.KindDNS, "23.1.2.3"),
				failedObservation("http:ifconfig", egress.ReasonBanned),
			},
			options:            defaultOptions,
			expectedVerified:   true,
			expectedIP:         "23.1.2.3",
			expectedQuorum:     2,
			expectedSourceN:    3,
			expectedConfidence: egress.ConfidenceMedium,
			expectedDissenters: []string{"http:ifconfig"},
		},
		"rejected observations do not make a quorum": {
			observations: []egress.Observation{
				failedObservation("http:ipify", egress.ReasonTimeout),
				failedObservation("dns:whoami", egress.ReasonTimeout),
				observation("http:ifconfig", egress.KindHTTP, "23.1.2.3"),
			},
			options:          defaultOptions,
			expectedSourceN:  3,
			expectedReason:   egress.ReasonNoQuorum,
			expectedVerified: false,
		},
		"single source allowed": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "23.1.2.3"),
			},
			options:            allowSingleOptions,
			expectedVerified:   true,
			expectedIP:         "23.1.2.3",
			expectedQuorum:     1,
			expectedSourceN:    1,
			expectedConfidence: egress.ConfidenceLow,
			expectedSingle:     true,
		},
		"publicip never sufficient alone": {
			observations: []egress.Observation{
				observation("publicip:internal", egress.KindPublicIP, "23.1.2.3"),
			},
			options:          allowSingleOptions,
			expectedSourceN:  1,
			expectedReason:   egress.ReasonNoQuorum,
			expectedVerified: false,
		},
		"publicip with independent source": {
			observations: []egress.Observation{
				observation("publicip:internal", egress.KindPublicIP, "23.1.2.3"),
				observation("http:ipify", egress.KindHTTP, "23.1.2.3"),
			},
			options:            Options{Quorum: 2, MinSources: 2},
			expectedVerified:   true,
			expectedIP:         "23.1.2.3",
			expectedQuorum:     2,
			expectedSourceN:    2,
			expectedConfidence: egress.ConfidenceHigh,
		},
		"dns wins tie break": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "8.8.8.8"),
				observation("dns:whoami", egress.KindDNS, "1.1.1.1"),
			},
			options:          allowSingleOptions,
			expectedVerified: true,
			expectedIP:       "1.1.1.1",
			expectedQuorum:   1,
			expectedSourceN:  2,
		},
		"smallest ip wins tie break": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "8.8.8.8"),
				observation("http:ifconfig", egress.KindHTTP, "1.1.1.1"),
			},
			options:          allowSingleOptions,
			expectedVerified: true,
			expectedIP:       "1.1.1.1",
			expectedQuorum:   1,
			expectedSourceN:  2,
		},
		"family six without ipv6": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "23.1.2.3"),
			},
			options: Options{
				Quorum: 1, MinSources: 1, AllowSingle: true, Family: 6,
			},
			expectedSourceN:  1,
			expectedReason:   egress.ReasonNoQuorum,
			expectedVerified: false,
		},
		"documentation rejected in production": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "203.0.113.7"),
				observation("dns:whoami", egress.KindDNS, "203.0.113.7"),
				observation("http:ifconfig", egress.KindHTTP, "203.0.113.7"),
			},
			options:          defaultOptions,
			expectedSourceN:  3,
			expectedReason:   egress.ReasonNoQuorum,
			expectedVerified: false,
		},
		"documentation allowed in tests": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "203.0.113.7"),
				observation("dns:whoami", egress.KindDNS, "203.0.113.7"),
				observation("http:ifconfig", egress.KindHTTP, "203.0.113.7"),
			},
			options:            testNetOptions,
			expectedVerified:   true,
			expectedIP:         "203.0.113.7",
			expectedQuorum:     3,
			expectedSourceN:    3,
			expectedConfidence: egress.ConfidenceHigh,
		},
		"two dissenters give low confidence": {
			observations: []egress.Observation{
				observation("http:ipify", egress.KindHTTP, "23.1.2.3"),
				observation("dns:whoami", egress.KindDNS, "23.1.2.3"),
				observation("http:ifconfig", egress.KindHTTP, "45.6.7.8"),
				observation("publicip:internal", egress.KindPublicIP, "89.10.11.12"),
			},
			options:            Options{Quorum: 2, MinSources: 3},
			expectedVerified:   true,
			expectedIP:         "23.1.2.3",
			expectedQuorum:     2,
			expectedSourceN:    4,
			expectedConfidence: egress.ConfidenceLow,
			expectedDissenters: []string{"http:ifconfig", "publicip:internal"},
		},
		"empty": {
			observations:     nil,
			options:          defaultOptions,
			expectedSourceN:  0,
			expectedReason:   egress.ReasonInsufficientSources,
			expectedVerified: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			verification := Evaluate(testCase.observations, testCase.options,
				testNow())

			assert.Equal(t, testCase.expectedVerified, verification.Verified)
			assert.Equal(t, testCase.expectedSourceN, verification.SourceCount)
			assert.Equal(t, testNow(), verification.VerifiedAt)
			assert.Equal(t, testCase.expectedSingle, verification.SingleSource)
			if testCase.expectedIP != "" {
				assert.Equal(t, testCase.expectedIP, verification.IP.String())
			}
			if testCase.expectedQuorum != 0 {
				assert.Equal(t, testCase.expectedQuorum, verification.Quorum)
			}
			if testCase.expectedConfidence != "" {
				assert.Equal(t, testCase.expectedConfidence, verification.Confidence)
			}
			if testCase.expectedDissenters != nil {
				assert.Equal(t, testCase.expectedDissenters, verification.Dissenters)
			}
			if testCase.expectedReason != "" {
				require.NotNil(t, verification.Reason)
				assert.Equal(t, testCase.expectedReason, *verification.Reason)
			} else {
				assert.Nil(t, verification.Reason)
			}
		})
	}
}

func Test_Evaluate_rejection_reasons_are_kept(t *testing.T) {
	t.Parallel()

	observations := []egress.Observation{
		observation("http:ipify", egress.KindHTTP, "198.18.0.9"),
		observation("dns:whoami", egress.KindDNS, "198.18.0.9"),
		observation("http:ifconfig", egress.KindHTTP, "198.18.0.9"),
	}
	options := Options{
		Quorum:     2,
		MinSources: 3,
		HostIPs:    []netip.Addr{netip.MustParseAddr("198.18.0.9")},
	}

	verification := Evaluate(observations, options, testNow())

	require.Len(t, verification.Observations, 3)
	for _, observation := range verification.Observations {
		assert.False(t, observation.Accepted)
		require.NotNil(t, observation.RejectionReason)
		assert.Equal(t, egress.ReasonHostIP, *observation.RejectionReason)
	}
}
