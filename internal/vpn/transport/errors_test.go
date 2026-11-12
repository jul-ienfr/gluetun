package transport

import (
	"context"
	"errors"
	"syscall"
	"testing"
)

func TestReasonOf(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		err      error
		expected Reason
	}{
		"nil":                {err: nil, expected: ReasonNone},
		"typed auth":         {err: NewFailure(ReasonAuth, errors.New("denied")), expected: ReasonAuth},
		"wrapped typed":      {err: errors.Join(errors.New("outer"), NewFailure(ReasonTLS, errors.New("tls"))), expected: ReasonTLS},
		"deadline":           {err: context.DeadlineExceeded, expected: ReasonHandshakeTimeout},
		"canceled":           {err: context.Canceled, expected: ReasonCanceled},
		"connection refused": {err: syscall.ECONNREFUSED, expected: ReasonTCPRefused},
		"unknown":            {err: errors.New("boom"), expected: ReasonUnknown},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reason := ReasonOf(testCase.err)
			if reason != testCase.expected {
				t.Fatalf("expected %q, got %q", testCase.expected, reason)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		err       error
		transport Transport
		expected  Reason
	}{
		"unknown tcp": {err: errors.New("boom"), transport: OpenVPNTCP, expected: ReasonTCPRefused},
		"unknown udp": {err: errors.New("boom"), transport: OpenVPNUDP, expected: ReasonUDPBlocked},
		"typed keeps": {err: NewFailure(ReasonNoEgress, errors.New("no")), transport: OpenVPNTCP, expected: ReasonNoEgress},
		"refused tcp": {err: syscall.ECONNREFUSED, transport: OpenVPNTCP, expected: ReasonTCPRefused},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reason := Classify(testCase.err, testCase.transport)
			if reason != testCase.expected {
				t.Fatalf("expected %q, got %q", testCase.expected, reason)
			}
		})
	}
}

func TestReasonValid(t *testing.T) {
	t.Parallel()

	reasons := []Reason{
		ReasonNone, ReasonAuth, ReasonUDPBlocked, ReasonTCPRefused, ReasonTLS,
		ReasonHandshakeTimeout, ReasonNoEgress, ReasonInterfaceDown,
		ReasonConfigInvalid, ReasonBreakerOpen, ReasonCanceled, ReasonUnknown,
	}
	for _, reason := range reasons {
		if !reason.Valid() {
			t.Fatalf("reason %q should be valid", reason)
		}
	}
	if Reason("paid").Valid() {
		t.Fatal("unknown reason should be invalid")
	}
}

func TestFailureUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("cause")
	err := NewFailure(ReasonAuth, cause)
	if !errors.Is(err, cause) {
		t.Fatal("failure does not unwrap to cause")
	}
	if err.Error() != "auth: cause" {
		t.Fatalf("unexpected error string: %q", err.Error())
	}
}
