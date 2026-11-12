package dns

import (
	"context"

	"github.com/miekg/dns"
	"github.com/qdm12/gluetun/internal/dns/ladder"
)

type ladderMiddleware struct {
	ctx        context.Context //nolint:containedctx
	resolver   *ladder.Ladder
	failClosed bool
	logger     Logger
}

func newLadderMiddleware(ctx context.Context, resolver *ladder.Ladder,
	failClosed bool, logger Logger,
) *ladderMiddleware {
	return &ladderMiddleware{
		ctx:        ctx,
		resolver:   resolver,
		failClosed: failClosed,
		logger:     logger,
	}
}

func (m *ladderMiddleware) String() string { return "DNS ladder" }

func (m *ladderMiddleware) Stop() error { return nil }

func (m *ladderMiddleware) Wrap(next dns.Handler) dns.Handler {
	return dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response, err := m.resolver.Resolve(m.ctx, request)
		if err != nil {
			if !m.failClosed {
				next.ServeDNS(writer, request)
				return
			}
			m.logger.Warn("DNS ladder exhausted: " + err.Error())
			_ = writer.WriteMsg(new(dns.Msg).SetRcode(request,
				dns.RcodeServerFailure))
			return
		}

		response.SetReply(request)
		_ = writer.WriteMsg(response)
	})
}
