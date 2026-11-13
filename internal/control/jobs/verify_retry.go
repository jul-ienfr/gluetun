package jobs

import (
	"context"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/verify"
)

const (
	// egressVerifyAttempts bounds the retries after a tunnel change. Three
	// attempts cover a WireGuard handshake plus its first DNS answer.
	egressVerifyAttempts   = 3
	egressVerifyRetryDelay = time.Second
)

// verifyEgressUntilVerified retries a fresh egress verification while the
// sources answer without a quorum. A tunnel that has just been applied needs a
// few seconds before its DNS and egress settle; a single probe would race it.
// Verifier errors are returned immediately: they signal a broken service, not
// a tunnel that is still coming up.
func verifyEgressUntilVerified(ctx context.Context, verifier EgressVerifier,
	request verify.Request,
) (verification egress.Verification, err error) {
	for attempt := range egressVerifyAttempts {
		verification, err = verifier.Verify(ctx, request)
		if err != nil {
			return verification, err
		}
		if verification.Verified || attempt == egressVerifyAttempts-1 {
			return verification, nil
		}
		timer := time.NewTimer(egressVerifyRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return verification, nil
		case <-timer.C:
		}
	}
	return verification, nil
}
