// Package canary checks a neutral HTTP endpoint through the tunnel.
package canary

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
)

const maxBodyBytes = 4 << 20

// Settings configure the canary request.
type Settings struct {
	URL          string
	Method       string
	ExpectStatus int
	MinBodyBytes int64
	ExpectSHA256 string
	Timeout      time.Duration
}

// Checker performs a single canary request per verification.
type Checker struct {
	client   *http.Client
	settings Settings
}

// New creates a canary checker from operator settings.
func New(settings Settings, client *http.Client) *Checker {
	if client == nil {
		panic("HTTP client is nil")
	}
	return &Checker{
		client:   client,
		settings: settings,
	}
}

// Enabled reports whether a canary URL is configured.
func (c *Checker) Enabled() bool {
	return c.settings.URL != ""
}

// Settings returns the effective canary settings.
func (c *Checker) Settings() Settings {
	return c.settings
}

// Check performs the canary request without following redirections.
func (c *Checker) Check(ctx context.Context) (result egress.CanaryResult) {
	if !c.Enabled() {
		return egress.CanaryResult{OK: true}
	}

	timeout := c.settings.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	result = egress.CanaryResult{
		URL:       c.settings.URL,
		CheckedAt: start.UTC(),
	}

	method := c.settings.Method
	if method == "" {
		method = http.MethodGet
	}
	request, err := http.NewRequestWithContext(ctx, method, c.settings.URL, nil)
	if err != nil {
		result.Failure = reasonPointer(egress.ReasonMalformed)
		return result
	}

	client := *c.client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	response, err := client.Do(request)
	result.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		result.Failure = reasonPointer(failureReason(ctx, err))
		return result
	}
	defer response.Body.Close()

	result.Status = response.StatusCode
	if response.StatusCode != c.settings.ExpectStatus {
		reason := egress.Reason(fmt.Sprintf("status_%d", response.StatusCode))
		result.Failure = &reason
		return result
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		result.Failure = reasonPointer(failureReason(ctx, err))
		return result
	}
	result.BodyBytes = int64(len(body))
	sum := sha256.Sum256(body)
	result.BodySHA256 = hex.EncodeToString(sum[:])

	if result.BodyBytes < c.settings.MinBodyBytes {
		if result.BodyBytes == 0 {
			result.Failure = reasonPointer(egress.ReasonEmptyBody)
		} else {
			result.Failure = reasonPointer(egress.ReasonBodyTooSmall)
		}
		return result
	}

	if c.settings.ExpectSHA256 != "" &&
		!strings.EqualFold(result.BodySHA256, c.settings.ExpectSHA256) {
		result.Failure = reasonPointer(egress.ReasonHashMismatch)
		return result
	}

	result.OK = true
	return result
}

func failureReason(ctx context.Context, err error) egress.Reason {
	var certificateError *tls.CertificateVerificationError
	var authorityError x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	switch {
	case errors.As(err, &certificateError),
		errors.As(err, &authorityError),
		errors.As(err, &hostnameError):
		return egress.ReasonTLS
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(ctx.Err(), context.DeadlineExceeded):
		return egress.ReasonTimeout
	default:
		return egress.ReasonTransport
	}
}

func reasonPointer(reason egress.Reason) *egress.Reason {
	return &reason
}
