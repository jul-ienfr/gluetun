// Package integration holds control plane end-to-end and chaos tests.
package integration

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/canary"
	"github.com/qdm12/gluetun/internal/egress/consensus"
	"github.com/qdm12/gluetun/internal/egress/source"
	"github.com/qdm12/gluetun/internal/egress/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	honestEgressIP = "23.1.2.3"
	liarEgressIP   = "45.6.7.8"
	testTimeout    = 2 * time.Second
)

func buildStaticSources(t *testing.T, timeout time.Duration, urls ...string,
) []source.Source {
	t.Helper()

	specifications := make([]string, len(urls))
	for index, url := range urls {
		specifications[index] = "static:" + url
	}
	sources, err := source.Build(specifications, source.Dependencies{
		HTTPClient: &http.Client{Timeout: timeout},
		Timeout:    timeout,
	})
	require.NoError(t, err)
	return sources
}

func verifyNow(t *testing.T, service *verify.Service) egress.Verification {
	t.Helper()
	verification, err := service.Verify(t.Context(), verify.Request{Fresh: true})
	require.NoError(t, err)
	return verification
}

func newIPServers(t *testing.T, bodies ...string) (servers []*httptest.Server) {
	t.Helper()
	for _, body := range bodies {
		server := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
		t.Cleanup(server.Close)
		servers = append(servers, server)
	}
	return servers
}

func urlsOf(servers []*httptest.Server) (urls []string) {
	urls = make([]string, len(servers))
	for index, server := range servers {
		urls[index] = server.URL
	}
	return urls
}

func Test_EgressChaos(t *testing.T) {
	t.Parallel()

	hostIP := netip.MustParseAddr("198.18.0.9")

	testCases := map[string]struct {
		run func(t *testing.T)
	}{
		"EG_AT_01_three_sources_one_dissident": {
			run: func(t *testing.T) {
				t.Helper()

				servers := newIPServers(t, honestEgressIP, honestEgressIP, liarEgressIP)
				sources := buildStaticSources(t, testTimeout, urlsOf(servers)...)
				service := verify.New(verify.Settings{
					Sources: sources,
					Options: consensus.Options{Quorum: 2, MinSources: 3},
				})

				verification := verifyNow(t, service)
				assert.True(t, verification.Verified)
				assert.Equal(t, honestEgressIP, verification.IP.String())
				assert.Equal(t, 2, verification.Quorum)
				assert.Equal(t, 3, verification.SourceCount)
				// §4.2: one dissident lowers confidence to medium.
				assert.Equal(t, egress.ConfidenceMedium, verification.Confidence)
				assert.Len(t, verification.Dissenters, 1)
				assert.Equal(t, "static:"+servers[2].URL,
					verification.Dissenters[0])
			},
		},
		"EG_AT_02_single_source_refused": {
			run: func(t *testing.T) {
				t.Helper()

				servers := newIPServers(t, honestEgressIP)
				sources := buildStaticSources(t, testTimeout, urlsOf(servers)...)
				service := verify.New(verify.Settings{
					Sources: sources,
					Options: consensus.Options{Quorum: 2, MinSources: 3},
				})

				verification := verifyNow(t, service)
				assert.False(t, verification.Verified)
				require.NotNil(t, verification.Reason)
				assert.Equal(t, egress.ReasonInsufficientSources,
					*verification.Reason)
			},
		},
		"EG_AT_03_host_ip_never_proof": {
			run: func(t *testing.T) {
				t.Helper()

				servers := newIPServers(t, hostIP.String(), hostIP.String(),
					hostIP.String())
				sources := buildStaticSources(t, testTimeout, urlsOf(servers)...)
				service := verify.New(verify.Settings{
					Sources: sources,
					Options: consensus.Options{
						Quorum:     2,
						MinSources: 3,
						HostIPs:    []netip.Addr{hostIP},
					},
				})

				verification := verifyNow(t, service)
				assert.False(t, verification.Verified)
				require.NotNil(t, verification.Reason)
				assert.Equal(t, egress.ReasonNoQuorum, *verification.Reason)
				require.Len(t, verification.Observations, 3)
				for _, observation := range verification.Observations {
					require.NotNil(t, observation.RejectionReason)
					assert.Equal(t, egress.ReasonHostIP,
						*observation.RejectionReason)
				}
			},
		},
		"EG_AT_04_empty_canary_body_refused": {
			run: func(t *testing.T) {
				t.Helper()

				servers := newIPServers(t, honestEgressIP, honestEgressIP,
					honestEgressIP)
				emptyCanary := httptest.NewServer(http.HandlerFunc(
					func(_ http.ResponseWriter, _ *http.Request) {}))
				t.Cleanup(emptyCanary.Close)

				checker := canary.New(canary.Settings{
					URL:          emptyCanary.URL,
					ExpectStatus: http.StatusOK,
					MinBodyBytes: 1,
					Timeout:      testTimeout,
				}, &http.Client{Timeout: testTimeout})

				service := verify.New(verify.Settings{
					Sources: buildStaticSources(t, testTimeout, urlsOf(servers)...),
					Options: consensus.Options{Quorum: 2, MinSources: 3},
					Canary:  checker,
				})

				verification := verifyNow(t, service)
				assert.False(t, verification.Verified)
				require.NotNil(t, verification.Reason)
				assert.Equal(t, egress.ReasonCanaryFailed, *verification.Reason)
				require.NotNil(t, verification.Canary)
				require.NotNil(t, verification.Canary.Failure)
				assert.Equal(t, egress.ReasonEmptyBody,
					*verification.Canary.Failure)
			},
		},
		"EG_AT_05_cache_serves_same_result": {
			run: func(t *testing.T) {
				t.Helper()

				servers := newIPServers(t, honestEgressIP, honestEgressIP,
					honestEgressIP)
				service := verify.New(verify.Settings{
					Sources:  buildStaticSources(t, testTimeout, urlsOf(servers)...),
					Options:  consensus.Options{Quorum: 2, MinSources: 3},
					CacheTTL: 10 * time.Second,
				})

				first := verifyNow(t, service)
				second, err := service.Verify(t.Context(), verify.Request{})
				require.NoError(t, err)

				assert.True(t, first.Verified)
				assert.True(t, second.Cached)
				assert.Equal(t, first.IP, second.IP)
				assert.Equal(t, 10, second.TTLS)
			},
		},
		"EG_AT_06_liar_does_not_win": {
			run: func(t *testing.T) {
				t.Helper()

				servers := newIPServers(t, liarEgressIP, honestEgressIP,
					honestEgressIP)
				service := verify.New(verify.Settings{
					Sources: buildStaticSources(t, testTimeout, urlsOf(servers)...),
					Options: consensus.Options{Quorum: 2, MinSources: 3},
				})

				verification := verifyNow(t, service)
				assert.True(t, verification.Verified)
				assert.Equal(t, honestEgressIP, verification.IP.String())
				assert.Equal(t, egress.ConfidenceMedium, verification.Confidence)
			},
		},
		"EG_AT_07_rate_limited_source_backs_off": {
			run: func(t *testing.T) {
				t.Helper()

				var rateLimitedCalls atomic.Int64
				rateLimited := httptest.NewServer(http.HandlerFunc(
					func(w http.ResponseWriter, _ *http.Request) {
						rateLimitedCalls.Add(1)
						w.WriteHeader(http.StatusTooManyRequests)
					}))
				t.Cleanup(rateLimited.Close)

				honest := newIPServers(t, honestEgressIP, honestEgressIP)
				sources := buildStaticSources(t, testTimeout,
					append(urlsOf(honest), rateLimited.URL)...)
				service := verify.New(verify.Settings{
					Sources:          sources,
					Options:          consensus.Options{Quorum: 2, MinSources: 3},
					SourceBackoff:    time.Second,
					SourceBackoffMax: 4 * time.Second,
				})

				first := verifyNow(t, service)
				assert.True(t, first.Verified)
				assert.Equal(t, int64(1), rateLimitedCalls.Load())
				require.Len(t, first.Observations, 3)
				for _, observation := range first.Observations {
					if observation.Error == nil {
						continue
					}
					assert.Equal(t, egress.ReasonBanned,
						observation.Error.Reason)
				}

				second := verifyNow(t, service)
				assert.True(t, second.Verified)
				assert.Equal(t, int64(1), rateLimitedCalls.Load())
			},
		},
		"EG_AT_08_ipv6_family_never_falls_back": {
			run: func(t *testing.T) {
				t.Helper()

				servers := newIPServers(t, honestEgressIP, honestEgressIP,
					honestEgressIP)
				service := verify.New(verify.Settings{
					Sources: buildStaticSources(t, testTimeout, urlsOf(servers)...),
					Options: consensus.Options{
						Quorum:     2,
						MinSources: 3,
						Family:     6,
					},
				})

				verification := verifyNow(t, service)
				assert.False(t, verification.Verified)
				assert.False(t, verification.IP.IsValid())
				require.NotNil(t, verification.Reason)
				assert.Equal(t, egress.ReasonNoQuorum, *verification.Reason)
				for _, observation := range verification.Observations {
					require.NotNil(t, observation.RejectionReason)
					assert.Equal(t, egress.ReasonWrongFamily,
						*observation.RejectionReason)
				}
			},
		},
		"slow_source_does_not_block_quorum": {
			run: func(t *testing.T) {
				t.Helper()

				slow := httptest.NewServer(http.HandlerFunc(
					func(_ http.ResponseWriter, request *http.Request) {
						<-request.Context().Done()
					}))
				t.Cleanup(slow.Close)

				honest := newIPServers(t, honestEgressIP, honestEgressIP)
				sources := buildStaticSources(t, 50*time.Millisecond,
					append(urlsOf(honest), slow.URL)...)
				service := verify.New(verify.Settings{
					Sources: sources,
					Options: consensus.Options{Quorum: 2, MinSources: 3},
					Timeout: testTimeout,
				})

				verification := verifyNow(t, service)
				assert.True(t, verification.Verified)
				assert.Equal(t, honestEgressIP, verification.IP.String())

				var timedOut bool
				for _, observation := range verification.Observations {
					if observation.Error == nil {
						continue
					}
					timedOut = timedOut ||
						observation.Error.Reason == egress.ReasonTimeout
				}
				assert.True(t, timedOut)
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			testCase.run(t)
		})
	}
}
