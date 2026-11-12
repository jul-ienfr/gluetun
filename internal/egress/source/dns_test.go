package source

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type resolverFunc func(ctx context.Context, name string) ([]string, error)

func (f resolverFunc) LookupTXT(ctx context.Context, name string) (
	[]string, error,
) {
	return f(ctx, name)
}

func Test_DNSSource_Fetch(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		resolver    Resolver
		timeout     time.Duration
		expectedIP  string
		expectedErr error
	}{
		"ipv4": {
			resolver: resolverFunc(func(_ context.Context, name string) ([]string, error) {
				assert.Equal(t, "whoami.test.", name)
				return []string{"23.1.2.3"}, nil
			}),
			expectedIP: "23.1.2.3",
		},
		"ipv6": {
			resolver: resolverFunc(func(_ context.Context, _ string) ([]string, error) {
				return []string{"2001:4860:4860::8888"}, nil
			}),
			expectedIP: "2001:4860:4860::8888",
		},
		"second_record": {
			resolver: resolverFunc(func(_ context.Context, _ string) ([]string, error) {
				return []string{"not-an-ip", "23.1.2.3"}, nil
			}),
			expectedIP: "23.1.2.3",
		},
		"empty": {
			resolver: resolverFunc(func(_ context.Context, _ string) ([]string, error) {
				return nil, nil
			}),
			expectedErr: ErrEmpty,
		},
		"malformed": {
			resolver: resolverFunc(func(_ context.Context, _ string) ([]string, error) {
				return []string{"not-an-ip"}, nil
			}),
			expectedErr: ErrMalformed,
		},
		"lookup_error": {
			resolver: resolverFunc(func(_ context.Context, _ string) ([]string, error) {
				return nil, errors.New("servfail")
			}),
			expectedErr: ErrMalformed,
		},
		"timeout": {
			resolver: resolverFunc(func(ctx context.Context, _ string) ([]string, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}),
			timeout:     20 * time.Millisecond,
			expectedErr: ErrTimeout,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			timeout := testCase.timeout
			if timeout == 0 {
				timeout = time.Second
			}
			source := newDNS("dns:test", "whoami.test.", testCase.resolver, timeout)

			observation, err := source.Fetch(context.Background(), 4)
			if testCase.expectedErr != nil {
				require.ErrorIs(t, err, testCase.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "dns:test", observation.Source)
			assert.Equal(t, testCase.expectedIP, observation.IP.String())
		})
	}
}
