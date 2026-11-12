package source

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_HTTPSource_Fetch(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		handler      http.HandlerFunc
		timeout      time.Duration
		expectedIP   netip.Addr
		expectedMeta bool
		expectedErr  error
	}{
		"json_ip": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(`{"ip":"23.1.2.3"}`))
			},
			expectedIP: netip.MustParseAddr("23.1.2.3"),
		},
		"json_with_metadata": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(`{"ip":"23.1.2.3","country":"NL",` +
					`"region":"NH","city":"Amsterdam","asn":9009,"org":"M247"}`))
			},
			expectedIP:   netip.MustParseAddr("23.1.2.3"),
			expectedMeta: true,
		},
		"json_string": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(`"23.1.2.3"`))
			},
			expectedIP: netip.MustParseAddr("23.1.2.3"),
		},
		"plain_text": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte("23.1.2.3\n"))
			},
			expectedIP: netip.MustParseAddr("23.1.2.3"),
		},
		"ipv6": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte("2001:4860:4860::8888"))
			},
			expectedIP: netip.MustParseAddr("2001:4860:4860::8888"),
		},
		"empty": {
			handler:     func(_ http.ResponseWriter, _ *http.Request) {},
			expectedErr: ErrEmpty,
		},
		"malformed": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte("not-an-ip"))
			},
			expectedErr: ErrMalformed,
		},
		"host_and_port": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte("23.1.2.3:443"))
			},
			expectedErr: ErrMalformed,
		},
		"too_many_requests": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusTooManyRequests)
			},
			expectedErr: ErrBanned,
		},
		"bad_status": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusBadGateway)
			},
			expectedErr: ErrHTTPStatus,
		},
		"timeout": {
			handler: func(_ http.ResponseWriter, request *http.Request) {
				<-request.Context().Done()
			},
			timeout:     20 * time.Millisecond,
			expectedErr: ErrTimeout,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(testCase.handler)
			t.Cleanup(server.Close)

			timeout := testCase.timeout
			if timeout == 0 {
				timeout = time.Second
			}
			source := newHTTP("http:test", server.URL, &http.Client{}, timeout)

			observation, err := source.Fetch(context.Background(), 4)
			if testCase.expectedErr != nil {
				require.ErrorIs(t, err, testCase.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "http:test", observation.Source)
			assert.Equal(t, testCase.expectedIP, observation.IP)
			assert.False(t, observation.ObservedAt.IsZero())
			assert.GreaterOrEqual(t, observation.LatencyMS, int64(0))
			if testCase.expectedMeta {
				assert.Equal(t, "NL", observation.Country)
				assert.Equal(t, "NH", observation.Region)
				assert.Equal(t, "Amsterdam", observation.City)
				assert.Equal(t, uint(9009), observation.ASN)
				assert.Equal(t, "M247", observation.Organization)
			}
		})
	}
}

func Test_parseHTTPBody(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		body        string
		expectedIP  string
		expectedErr error
	}{
		"json_ip":     {body: `{"ip":"23.1.2.3"}`, expectedIP: "23.1.2.3"},
		"query":       {body: `{"query":"23.1.2.3"}`, expectedIP: "23.1.2.3"},
		"fused":       {body: `{"YourFusedIP":"23.1.2.3"}`, expectedIP: "23.1.2.3"},
		"plain":       {body: "23.1.2.3", expectedIP: "23.1.2.3"},
		"quoted":      {body: `"23.1.2.3"`, expectedIP: "23.1.2.3"},
		"blank":       {body: "  ", expectedErr: ErrEmpty},
		"no_ip":       {body: `{"country":"NL"}`, expectedErr: ErrMalformed},
		"invalid_ip":  {body: `{"ip":"999.1.2.3"}`, expectedErr: ErrMalformed},
		"domain_name": {body: "example.com", expectedErr: ErrMalformed},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ip, _, err := parseHTTPBody([]byte(testCase.body))
			if testCase.expectedErr != nil {
				require.ErrorIs(t, err, testCase.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedIP, ip.String())
		})
	}
}

func Test_wrapFetchError(t *testing.T) {
	t.Parallel()

	assert.ErrorIs(t, wrapFetchError(context.Background(), context.DeadlineExceeded),
		ErrTimeout)
	assert.NotErrorIs(t, wrapFetchError(context.Background(), errors.New("refused")),
		ErrTimeout)
}
