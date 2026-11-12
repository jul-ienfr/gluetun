package verify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/canary"
	"github.com/qdm12/gluetun/internal/egress/consensus"
	"github.com/qdm12/gluetun/internal/egress/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSource struct {
	name  string
	kind  egress.Kind
	fetch func(ctx context.Context, family int) (egress.Observation, error)
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Kind() egress.Kind {
	return f.kind
}

func (f *fakeSource) Fetch(ctx context.Context, family int) (
	egress.Observation, error,
) {
	return f.fetch(ctx, family)
}

func ipObservation(name string, kind egress.Kind, ip string) egress.Observation {
	return egress.Observation{
		Source:     name,
		Kind:       kind,
		IP:         netip.MustParseAddr(ip),
		ObservedAt: time.Now().UTC(),
	}
}

func instantSource(name string, kind egress.Kind) *fakeSource {
	return &fakeSource{
		name: name,
		kind: kind,
		fetch: func(_ context.Context, _ int) (egress.Observation, error) {
			return ipObservation(name, kind, "23.1.2.3"), nil
		},
	}
}

func baseOptions() consensus.Options {
	return consensus.Options{
		Quorum:        2,
		MinSources:    3,
		AllowTestNets: true,
	}
}

func Test_Service_Verify_cache(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int64
	newSource := func(name string) *fakeSource {
		return &fakeSource{
			name: name,
			kind: egress.KindHTTP,
			fetch: func(_ context.Context, _ int) (egress.Observation, error) {
				calls.Add(1)
				return ipObservation(name, egress.KindHTTP, "23.1.2.3"), nil
			},
		}
	}

	service := New(Settings{
		Sources: []source.Source{
			newSource("http:a"), newSource("http:b"), newSource("http:c"),
		},
		Options:  baseOptions(),
		CacheTTL: 10 * time.Second,
		Now:      func() time.Time { return now },
	})

	first, err := service.Verify(context.Background(), Request{})
	require.NoError(t, err)
	assert.True(t, first.Verified)
	assert.False(t, first.Cached)
	assert.Equal(t, 10, first.TTLS)
	assert.Equal(t, int64(3), calls.Load())

	now = now.Add(5 * time.Second)
	cached, err := service.Verify(context.Background(), Request{})
	require.NoError(t, err)
	assert.True(t, cached.Cached)
	assert.Equal(t, 10, cached.TTLS)
	assert.Equal(t, int64(3), calls.Load())

	now = now.Add(6 * time.Second)
	fresh, err := service.Verify(context.Background(), Request{})
	require.NoError(t, err)
	assert.False(t, fresh.Cached)
	assert.Equal(t, int64(6), calls.Load())
}

func Test_Service_Verify_single_flight(t *testing.T) {
	t.Parallel()

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int64
	blocking := &fakeSource{
		name: "http:blocking",
		kind: egress.KindHTTP,
		fetch: func(ctx context.Context, _ int) (egress.Observation, error) {
			calls.Add(1)
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return egress.Observation{}, ctx.Err()
			}
			return ipObservation("http:blocking", egress.KindHTTP, "23.1.2.3"), nil
		},
	}

	service := New(Settings{
		Sources: []source.Source{
			blocking,
			instantSource("http:b", egress.KindHTTP),
			instantSource("dns:c", egress.KindDNS),
		},
		Options: baseOptions(),
	})

	const callers = 10
	var waitGroup sync.WaitGroup
	waitGroup.Add(callers)
	results := make(chan egress.Verification, callers)
	errs := make(chan error, callers)
	for range callers {
		go func() {
			defer waitGroup.Done()
			verification, err := service.Verify(context.Background(),
				Request{Fresh: true})
			results <- verification
			errs <- err
		}()
	}

	<-started
	close(release)
	waitGroup.Wait()
	close(results)
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
	for verification := range results {
		assert.True(t, verification.Verified)
	}
	// singleflight only coalesces overlapping calls: callers that reach
	// Verify after the blocked collection finished run a collection of
	// their own. What must hold is that some calls were coalesced.
	assert.GreaterOrEqual(t, calls.Load(), int64(1))
	assert.Less(t, calls.Load(), int64(callers))
}

func Test_Service_Verify_canary_failure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(
		func(_ http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(server.Close)

	checker := canary.New(canary.Settings{
		URL:          server.URL,
		ExpectStatus: http.StatusOK,
		MinBodyBytes: 1,
		Timeout:      time.Second,
	}, &http.Client{})

	service := New(Settings{
		Sources: []source.Source{
			instantSource("http:a", egress.KindHTTP),
			instantSource("http:b", egress.KindHTTP),
			instantSource("dns:c", egress.KindDNS),
		},
		Options: baseOptions(),
		Canary:  checker,
	})

	verification, err := service.Verify(context.Background(), Request{Fresh: true})
	require.NoError(t, err)
	assert.False(t, verification.Verified)
	require.NotNil(t, verification.Reason)
	assert.Equal(t, egress.ReasonCanaryFailed, *verification.Reason)
	require.NotNil(t, verification.Canary)
	assert.False(t, verification.Canary.OK)
}

func Test_Service_CheckCanary(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}))
	t.Cleanup(server.Close)

	checker := canary.New(canary.Settings{
		URL:          server.URL,
		ExpectStatus: http.StatusOK,
		MinBodyBytes: 1,
		Timeout:      time.Second,
	}, &http.Client{})

	service := New(Settings{Canary: checker})
	result, err := service.CheckCanary(t.Context())
	require.NoError(t, err)
	assert.True(t, result.OK)
	assert.Equal(t, int64(2), result.BodyBytes)
	assert.False(t, result.CheckedAt.IsZero())

	disabled := New(Settings{})
	_, err = disabled.CheckCanary(t.Context())
	require.ErrorIs(t, err, ErrCanaryDisabled)
}

func Test_Service_Verify_timeout(t *testing.T) {
	t.Parallel()

	blocking := &fakeSource{
		name: "http:blocking",
		kind: egress.KindHTTP,
		fetch: func(ctx context.Context, _ int) (egress.Observation, error) {
			<-ctx.Done()
			return egress.Observation{}, ctx.Err()
		},
	}
	service := New(Settings{
		Sources: []source.Source{
			blocking,
			instantSource("http:b", egress.KindHTTP),
			instantSource("dns:c", egress.KindDNS),
		},
		Options: baseOptions(),
		Timeout: 20 * time.Millisecond,
	})

	_, err := service.Verify(context.Background(), Request{Fresh: true})
	require.ErrorIs(t, err, ErrTimeout)
}

func Test_Service_Verify_backoff(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	var failingCalls atomic.Int64
	failing := &fakeSource{
		name: "http:failing",
		kind: egress.KindHTTP,
		fetch: func(_ context.Context, _ int) (egress.Observation, error) {
			failingCalls.Add(1)
			return egress.Observation{}, source.ErrHTTPStatus
		},
	}

	service := New(Settings{
		Sources: []source.Source{
			failing,
			instantSource("http:b", egress.KindHTTP),
			instantSource("dns:c", egress.KindDNS),
		},
		Options:          baseOptions(),
		SourceBackoff:    time.Second,
		SourceBackoffMax: 4 * time.Second,
		Now:              func() time.Time { return now },
	})

	first, err := service.Verify(context.Background(), Request{Fresh: true})
	require.NoError(t, err)
	assert.True(t, first.Verified)
	assert.Equal(t, int64(1), failingCalls.Load())

	now = now.Add(10 * time.Millisecond)
	second, err := service.Verify(context.Background(), Request{Fresh: true})
	require.NoError(t, err)
	assert.True(t, second.Verified)
	assert.Equal(t, int64(1), failingCalls.Load())
	require.Len(t, second.Observations, 3)
	for _, observation := range second.Observations {
		if observation.Source == "http:failing" {
			require.NotNil(t, observation.Error)
			assert.Equal(t, egress.ReasonHTTPStatus, observation.Error.Reason)
			assert.Equal(t, "source in backoff", observation.Error.Message)
		}
	}
}

func Test_Service_History(t *testing.T) {
	t.Parallel()

	var mutex sync.Mutex
	ip := "23.1.2.3"
	newSource := func(name string) *fakeSource {
		return &fakeSource{
			name: name,
			kind: egress.KindHTTP,
			fetch: func(_ context.Context, _ int) (egress.Observation, error) {
				mutex.Lock()
				defer mutex.Unlock()
				return ipObservation(name, egress.KindHTTP, ip), nil
			},
		}
	}

	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	service := New(Settings{
		Sources: []source.Source{
			newSource("http:a"), newSource("http:b"), newSource("http:c"),
		},
		Options: baseOptions(),
		Now:     func() time.Time { return now },
	})

	_, err := service.Verify(context.Background(), Request{Fresh: true})
	require.NoError(t, err)

	mutex.Lock()
	ip = "45.6.7.8"
	mutex.Unlock()
	now = now.Add(time.Second)
	_, err = service.Verify(context.Background(), Request{Fresh: true})
	require.NoError(t, err)

	history := service.History(10, time.Time{})
	require.Len(t, history, 2)
	assert.Equal(t, "45.6.7.8", history[0].IP.String())
	assert.Equal(t, "23.1.2.3", history[1].IP.String())

	filtered := service.History(10, now)
	require.Len(t, filtered, 1)
	assert.Equal(t, "45.6.7.8", filtered[0].IP.String())

	limited := service.History(1, time.Time{})
	require.Len(t, limited, 1)
	assert.Equal(t, "45.6.7.8", limited[0].IP.String())
}

func Test_classify(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		err      error
		expected egress.Reason
	}{
		"timeout":     {err: source.ErrTimeout, expected: egress.ReasonTimeout},
		"deadline":    {err: context.DeadlineExceeded, expected: egress.ReasonTimeout},
		"http_status": {err: source.ErrHTTPStatus, expected: egress.ReasonHTTPStatus},
		"malformed":   {err: source.ErrMalformed, expected: egress.ReasonMalformed},
		"empty":       {err: source.ErrEmpty, expected: egress.ReasonEmpty},
		"banned":      {err: source.ErrBanned, expected: egress.ReasonBanned},
		"transport":   {err: errors.New("connection refused"), expected: egress.ReasonTransport},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.expected, classify(testCase.err).Reason)
		})
	}
}
