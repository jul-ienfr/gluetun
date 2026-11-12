package canary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Checker_Check(t *testing.T) {
	t.Parallel()

	const body = "canary-ok"
	sum := sha256.Sum256([]byte(body))

	testCases := map[string]struct {
		handler         http.HandlerFunc
		url             string
		method          string
		expectStatus    int
		minBodyBytes    int64
		expectSHA256    string
		timeout         time.Duration
		expectedOK      bool
		expectedStatus  int
		expectedFailure egress.Reason
	}{
		"disabled": {
			expectedOK: true,
		},
		"body_ok": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(body))
			},
			expectStatus:   200,
			minBodyBytes:   1,
			expectedOK:     true,
			expectedStatus: 200,
		},
		"empty_body": {
			handler:         func(_ http.ResponseWriter, _ *http.Request) {},
			expectStatus:    200,
			minBodyBytes:    1,
			expectedStatus:  200,
			expectedFailure: egress.ReasonEmptyBody,
		},
		"body_too_small": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte("ok"))
			},
			expectStatus:    200,
			minBodyBytes:    3,
			expectedStatus:  200,
			expectedFailure: egress.ReasonBodyTooSmall,
		},
		"hash_match": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(body))
			},
			expectStatus:   200,
			minBodyBytes:   1,
			expectSHA256:   hex.EncodeToString(sum[:]),
			expectedOK:     true,
			expectedStatus: 200,
		},
		"hash_mismatch": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(body))
			},
			expectStatus:    200,
			minBodyBytes:    1,
			expectSHA256:    hex.EncodeToString(make([]byte, 32)),
			expectedStatus:  200,
			expectedFailure: egress.ReasonHashMismatch,
		},
		"redirect_not_followed": {
			handler: func(writer http.ResponseWriter, request *http.Request) {
				http.Redirect(writer, request, "https://example.invalid/", http.StatusFound)
			},
			expectStatus:    200,
			minBodyBytes:    1,
			expectedStatus:  302,
			expectedFailure: egress.Reason("status_302"),
		},
		"unexpected_status": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusBadGateway)
			},
			expectStatus:    200,
			minBodyBytes:    1,
			expectedStatus:  502,
			expectedFailure: egress.Reason("status_502"),
		},
		"post_method": {
			handler: func(writer http.ResponseWriter, request *http.Request) {
				assert.Equal(t, http.MethodPost, request.Method)
				_, _ = writer.Write([]byte(body))
			},
			method:         http.MethodPost,
			expectStatus:   200,
			minBodyBytes:   1,
			expectedOK:     true,
			expectedStatus: 200,
		},
		"timeout": {
			handler: func(_ http.ResponseWriter, request *http.Request) {
				<-request.Context().Done()
			},
			expectStatus:    200,
			minBodyBytes:    1,
			timeout:         20 * time.Millisecond,
			expectedFailure: egress.ReasonTimeout,
		},
		"tls_error": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(body))
			},
			expectStatus:    200,
			minBodyBytes:    1,
			expectedFailure: egress.ReasonTLS,
		},
		"transport_error": {
			url:             "http://127.0.0.1:1/health",
			expectStatus:    200,
			minBodyBytes:    1,
			expectedFailure: egress.ReasonTransport,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			url := testCase.url
			var server *httptest.Server
			if testCase.handler != nil {
				if testCase.expectedFailure == egress.ReasonTLS {
					server = httptest.NewTLSServer(testCase.handler)
				} else {
					server = httptest.NewServer(testCase.handler)
				}
				url = server.URL
			}
			if server != nil {
				t.Cleanup(server.Close)
			}

			checker := New(Settings{
				URL:          url,
				Method:       testCase.method,
				ExpectStatus: testCase.expectStatus,
				MinBodyBytes: testCase.minBodyBytes,
				ExpectSHA256: testCase.expectSHA256,
				Timeout:      testCase.timeout,
			}, &http.Client{})

			result := checker.Check(context.Background())

			assert.Equal(t, testCase.expectedOK, result.OK)
			if testCase.expectedStatus != 0 {
				assert.Equal(t, testCase.expectedStatus, result.Status)
			}
			if testCase.expectedFailure != "" {
				require.NotNil(t, result.Failure)
				assert.Equal(t, testCase.expectedFailure, *result.Failure)
			} else {
				assert.Nil(t, result.Failure)
			}
		})
	}
}

func Test_Checker_Enabled(t *testing.T) {
	t.Parallel()

	assert.False(t, New(Settings{}, &http.Client{}).Enabled())
	assert.True(t, New(Settings{URL: "https://example.invalid"}, &http.Client{}).Enabled())
}
