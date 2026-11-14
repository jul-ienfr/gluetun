package vpn

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/verify"
)

type fakeEgressVerifier struct {
	results []egress.Verification
	errs    []error
	calls   int
}

func (f *fakeEgressVerifier) Verify(_ context.Context,
	_ verify.Request,
) (egress.Verification, error) {
	index := f.calls
	f.calls++
	if index < len(f.errs) && f.errs[index] != nil {
		return egress.Verification{}, f.errs[index]
	}
	if index < len(f.results) {
		return f.results[index], nil
	}
	return egress.Verification{}, errors.New("no verification scripted")
}

func Test_ladderDriver_VerifyEgress_RetriesUntilVerified(t *testing.T) {
	t.Parallel()

	address := netip.MustParseAddr("203.0.113.7")
	verifier := &fakeEgressVerifier{results: []egress.Verification{
		{Verified: false},
		{Verified: true, IP: address},
	}}
	driver := &ladderDriver{loop: &Loop{egress: verifier}}

	ip, err := driver.VerifyEgress(t.Context())
	if err != nil {
		t.Fatalf("verifying egress: %v", err)
	}
	if ip != address {
		t.Fatalf("ip = %s, want %s", ip, address)
	}
	if verifier.calls != 2 {
		t.Fatalf("calls = %d, want 2", verifier.calls)
	}
	if driver.lastVerified.IsZero() {
		t.Fatal("lastVerified is zero")
	}
}

func Test_ladderDriver_VerifyEgress_FailsAfterRetries(t *testing.T) {
	t.Parallel()

	verifier := &fakeEgressVerifier{results: []egress.Verification{
		{Verified: false},
		{Verified: false},
		{Verified: false},
	}}
	driver := &ladderDriver{loop: &Loop{egress: verifier}}

	_, err := driver.VerifyEgress(t.Context())
	if err == nil {
		t.Fatal("expected an error")
	}
	if verifier.calls != 10 {
		t.Fatalf("calls = %d, want 10", verifier.calls)
	}
}
