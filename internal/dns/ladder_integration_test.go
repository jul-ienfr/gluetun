package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/qdm12/gluetun/internal/dns/ladder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_buildLadder_DefaultTiers(t *testing.T) {
	t.Parallel()

	resolver, err := buildLadder(LadderOptions{
		Enabled:          true,
		Ladder:           []string{"dot", "plain"},
		DefaultProviders: []string{"cloudflare"},
	})
	require.NoError(t, err)

	tiers := resolver.Tiers()
	require.Len(t, tiers, 2)
	assert.Equal(t, ladder.TierDoT, tiers[0].Type)
	assert.Equal(t, ladder.TierPlain, tiers[1].Type)
	require.NotEmpty(t, tiers[0].Endpoints)
	assert.Equal(t, "cloudflare-dns.com", tiers[0].Endpoints[0].TLSName)
	require.NotEmpty(t, tiers[1].Endpoints)
	assert.Empty(t, tiers[1].Endpoints[0].TLSName)
	assert.Equal(t, ladder.StateUp, tiers[0].State)
	assert.Equal(t, ladder.StateUp, tiers[1].State)
}

func Test_buildLadder_DoH(t *testing.T) {
	t.Parallel()

	resolver, err := buildLadder(LadderOptions{
		Enabled:          true,
		Ladder:           []string{"doh"},
		DefaultProviders: []string{"cloudflare"},
	})
	require.NoError(t, err)

	tiers := resolver.Tiers()
	require.Len(t, tiers, 1)
	require.NotEmpty(t, tiers[0].Endpoints)
	assert.Equal(t, "https://cloudflare-dns.com/dns-query",
		tiers[0].Endpoints[0].URL)
	assert.Equal(t, "1.1.1.1:443", tiers[0].Endpoints[0].Address)
}

func Test_buildLadder_CustomPlainAddresses(t *testing.T) {
	t.Parallel()

	address := netipAddrPort(t, "127.0.0.53", 53)
	resolver, err := buildLadder(LadderOptions{
		Enabled:          true,
		Ladder:           []string{"plain"},
		DefaultProviders: []string{"cloudflare"},
		PlainAddresses:   []netip.AddrPort{address},
	})
	require.NoError(t, err)

	tiers := resolver.Tiers()
	require.Len(t, tiers, 1)
	require.Len(t, tiers[0].Endpoints, 1)
	assert.Equal(t, "127.0.0.53:53", tiers[0].Endpoints[0].Address)
}

func Test_buildLadder_UnknownTier(t *testing.T) {
	t.Parallel()

	_, err := buildLadder(LadderOptions{
		Enabled:          true,
		Ladder:           []string{"dnscrypt"},
		DefaultProviders: []string{"cloudflare"},
	})
	assert.Error(t, err)
}

func Test_LadderMiddleware_Fallback(t *testing.T) {
	t.Parallel()

	exchanger := &fakeLadderExchanger{}
	exchanger.handler = func(tier ladder.TierType) (*dns.Msg, error) {
		if tier == ladder.TierDoT {
			return nil, errors.New("TCP 853 blocked")
		}
		response := new(dns.Msg)
		response.Rcode = dns.RcodeSuccess
		return response, nil
	}

	resolver, err := ladder.New(ladder.Settings{
		Ladder: []ladder.TierType{ladder.TierDoT, ladder.TierPlain},
		Endpoints: map[ladder.TierType][]ladder.Endpoint{
			ladder.TierDoT:   {ladder.NewEndpoint("1.1.1.1:853", "cloudflare")},
			ladder.TierPlain: {ladder.NewEndpoint("8.8.8.8:53", "google")},
		},
		Exchanger: exchanger,
	})
	require.NoError(t, err)

	baseCalled := false
	base := dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {
		baseCalled = true
	})

	middleware := newLadderMiddleware(context.Background(), resolver, true,
		&testLogger{})
	handler := middleware.Wrap(base)

	writer := newTestResponseWriter()
	handler.ServeDNS(writer, testDNSRequest())

	assert.False(t, baseCalled)
	require.NotNil(t, writer.message)
	assert.Equal(t, dns.RcodeSuccess, writer.message.Rcode)
	assert.Equal(t, []ladder.TierType{ladder.TierDoT, ladder.TierPlain},
		exchanger.tiers)
}

func Test_LadderMiddleware_FailClosed(t *testing.T) {
	t.Parallel()

	exchanger := &fakeLadderExchanger{
		handler: func(ladder.TierType) (*dns.Msg, error) {
			return nil, errors.New("all tiers blocked")
		},
	}
	resolver, err := ladder.New(ladder.Settings{
		Ladder: []ladder.TierType{ladder.TierPlain},
		Endpoints: map[ladder.TierType][]ladder.Endpoint{
			ladder.TierPlain: {ladder.NewEndpoint("8.8.8.8:53", "google")},
		},
		Exchanger: exchanger,
	})
	require.NoError(t, err)

	baseCalled := false
	base := dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {
		baseCalled = true
	})

	failClosed := newLadderMiddleware(context.Background(), resolver, true,
		&testLogger{}).Wrap(base)
	writer := newTestResponseWriter()
	failClosed.ServeDNS(writer, testDNSRequest())
	assert.False(t, baseCalled)
	require.NotNil(t, writer.message)
	assert.Equal(t, dns.RcodeServerFailure, writer.message.Rcode)

	baseCalled = false
	notFailClosed := newLadderMiddleware(context.Background(), resolver, false,
		&testLogger{}).Wrap(base)
	writer = newTestResponseWriter()
	notFailClosed.ServeDNS(writer, testDNSRequest())
	assert.True(t, baseCalled)
}

type fakeLadderExchanger struct {
	tiers   []ladder.TierType
	handler func(tier ladder.TierType) (*dns.Msg, error)
}

func (f *fakeLadderExchanger) Exchange(_ context.Context,
	tierType ladder.TierType, _ ladder.Endpoint, _ *dns.Msg, _ bool,
) (*dns.Msg, error) {
	f.tiers = append(f.tiers, tierType)
	return f.handler(tierType)
}

type testLogger struct{}

func (l *testLogger) Debug(string)         {}
func (l *testLogger) Info(string)          {}
func (l *testLogger) Infof(string, ...any) {}
func (l *testLogger) Warn(string)          {}
func (l *testLogger) Warnf(string, ...any) {}
func (l *testLogger) Error(string)         {}

type testResponseWriter struct {
	message *dns.Msg
}

func newTestResponseWriter() *testResponseWriter {
	return &testResponseWriter{}
}

func (w *testResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (w *testResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{}
}

func (w *testResponseWriter) WriteMsg(message *dns.Msg) error {
	w.message = message
	return nil
}

func (w *testResponseWriter) Write(data []byte) (int, error) {
	message := new(dns.Msg)
	err := message.Unpack(data)
	if err != nil {
		return 0, err
	}
	w.message = message
	return len(data), nil
}

func (w *testResponseWriter) Close() error        { return nil }
func (w *testResponseWriter) TsigStatus() error   { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool) {}
func (w *testResponseWriter) Hijack()             {}

func testDNSRequest() *dns.Msg {
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	return request
}

func netipAddrPort(t *testing.T, address string, port uint16) netip.AddrPort {
	t.Helper()
	addr, err := netip.ParseAddr(address)
	require.NoError(t, err)
	return netip.AddrPortFrom(addr, port)
}
