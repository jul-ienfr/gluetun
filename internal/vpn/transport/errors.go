package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

type Reason string

const (
	ReasonNone             Reason = ""
	ReasonAuth             Reason = "auth"
	ReasonUDPBlocked       Reason = "udp_blocked"
	ReasonTCPRefused       Reason = "tcp_refused"
	ReasonTLS              Reason = "tls"
	ReasonHandshakeTimeout Reason = "handshake_timeout"
	ReasonNoEgress         Reason = "no_egress"
	ReasonInterfaceDown    Reason = "interface_down"
	ReasonConfigInvalid    Reason = "config_invalid"
	ReasonBreakerOpen      Reason = "breaker_open"
	ReasonCanceled         Reason = "canceled"
	ReasonUnknown          Reason = "unknown"
)

func (r Reason) Valid() bool {
	switch r {
	case ReasonNone, ReasonAuth, ReasonUDPBlocked, ReasonTCPRefused,
		ReasonTLS, ReasonHandshakeTimeout, ReasonNoEgress,
		ReasonInterfaceDown, ReasonConfigInvalid, ReasonBreakerOpen,
		ReasonCanceled, ReasonUnknown:
		return true
	}
	return false
}

type Failure struct {
	Reason Reason
	Err    error
}

func (f *Failure) Error() string {
	if f.Err == nil {
		return string(f.Reason)
	}
	return fmt.Sprintf("%s: %s", f.Reason, f.Err)
}

func (f *Failure) Unwrap() error {
	return f.Err
}

func NewFailure(reason Reason, err error) error {
	return &Failure{Reason: reason, Err: err}
}

func ReasonOf(err error) Reason {
	if err == nil {
		return ReasonNone
	}
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Reason
	}
	if errors.Is(err, context.Canceled) {
		return ReasonCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return ReasonHandshakeTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ReasonHandshakeTimeout
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return ReasonTCPRefused
	case errors.Is(err, os.ErrDeadlineExceeded):
		return ReasonHandshakeTimeout
	}
	return ReasonUnknown
}

func Classify(err error, transport Transport) Reason {
	if err == nil {
		return ReasonNone
	}
	reason := ReasonOf(err)
	if reason != ReasonUnknown {
		return reason
	}
	if transport == OpenVPNTCP {
		return ReasonTCPRefused
	}
	return ReasonUDPBlocked
}
