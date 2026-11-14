package ladder

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type exchangeCall struct {
	tier    TierType
	address string
	tcp     bool
}

type fakeExchanger struct {
	calls   []exchangeCall
	handler func(call exchangeCall) (*dns.Msg, error)
}

func (f *fakeExchanger) Exchange(_ context.Context, tierType TierType,
	endpoint Endpoint, _ *dns.Msg, tcp bool,
) (*dns.Msg, error) {
	call := exchangeCall{tier: tierType, address: endpoint.Address, tcp: tcp}
	f.calls = append(f.calls, call)
	return f.handler(call)
}

func testRequest() *dns.Msg {
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	return request
}

func successResponse() *dns.Msg {
	response := new(dns.Msg)
	response.Rcode = dns.RcodeSuccess
	return response
}

func nameErrorResponse() *dns.Msg {
	response := new(dns.Msg)
	response.Rcode = dns.RcodeNameError
	return response
}

func newTestLadder(t *testing.T, exchanger Exchanger,
	endpoints map[TierType][]Endpoint,
) *Ladder {
	t.Helper()
	ladder, err := New(Settings{
		Ladder:    []TierType{TierDoT, TierPlain},
		Endpoints: endpoints,
		Health: NewHealth(HealthSettings{
			FailuresToDown:     3,
			SuccessesToRecover: 2,
			BaseCooldown:       time.Second,
			MaxCooldown:        time.Minute,
		}),
		Exchanger: exchanger,
	})
	require.NoError(t, err)
	return ladder
}

func Test_Ladder_Fallback(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{}
	exchanger.handler = func(call exchangeCall) (*dns.Msg, error) {
		if call.tier == TierDoT {
			return nil, errors.New("TCP 853 blocked")
		}
		return successResponse(), nil
	}
	ladder := newTestLadder(t, exchanger, map[TierType][]Endpoint{
		TierDoT:   {NewEndpoint("1.1.1.1:853", "cloudflare")},
		TierPlain: {NewEndpoint("8.8.8.8:53", "google")},
	})

	response, err := ladder.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, []exchangeCall{
		{tier: TierDoT, address: "1.1.1.1:853"},
		{tier: TierPlain, address: "8.8.8.8:53"},
	}, exchanger.calls)

	assert.Equal(t, TierPlain, ladder.ActiveTier())
	assert.False(t, ladder.FailClosed())

	tiers := ladder.Tiers()
	require.Len(t, tiers, 2)
	assert.Equal(t, StateDegraded, tiers[0].State)
	assert.Equal(t, StateUp, tiers[1].State)

	// The next request goes directly to the recovered tier.
	_, err = ladder.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	require.Len(t, exchanger.calls, 3)
	assert.Equal(t, TierPlain, exchanger.calls[2].tier)
}

func Test_Ladder_PlainIsTriedEvenWhenItsTierIsDown(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{}
	exchanger.handler = func(call exchangeCall) (*dns.Msg, error) {
		if call.tier == TierDoT {
			return nil, errors.New("TCP 853 blocked")
		}
		return successResponse(), nil
	}
	ladder := newTestLadder(t, exchanger, map[TierType][]Endpoint{
		TierDoT:   {NewEndpoint("1.1.1.1:853", "cloudflare")},
		TierPlain: {NewEndpoint("8.8.8.8:53", "google")},
	})
	ladder.tiers[1].State = StateDown
	cooldown := time.Now().Add(time.Minute)
	ladder.tiers[1].CooldownUntil = &cooldown

	response, err := ladder.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Len(t, exchanger.calls, 2)
	assert.Equal(t, TierDoT, exchanger.calls[0].tier)
	assert.Equal(t, TierPlain, exchanger.calls[1].tier)
}

func Test_Ladder_NXDOMAINIsTerminal(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{
		handler: func(exchangeCall) (*dns.Msg, error) {
			return nameErrorResponse(), nil
		},
	}
	ladder := newTestLadder(t, exchanger, map[TierType][]Endpoint{
		TierDoT:   {NewEndpoint("1.1.1.1:853", "cloudflare")},
		TierPlain: {NewEndpoint("8.8.8.8:53", "google")},
	})

	response, err := ladder.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeNameError, response.Rcode)
	require.Len(t, exchanger.calls, 1)
	assert.Equal(t, TierDoT, exchanger.calls[0].tier)
	assert.Equal(t, StateUp, ladder.Tiers()[0].State)
}

func Test_Ladder_TruncatedRetriesTCP(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{}
	exchanger.handler = func(call exchangeCall) (*dns.Msg, error) {
		if !call.tcp {
			response := successResponse()
			response.Truncated = true
			return response, nil
		}
		return successResponse(), nil
	}
	ladder := newTestLadder(t, exchanger, map[TierType][]Endpoint{
		TierDoT: {NewEndpoint("1.1.1.1:853", "cloudflare")},
	})

	response, err := ladder.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	assert.False(t, response.Truncated)
	assert.Equal(t, []exchangeCall{
		{tier: TierDoT, address: "1.1.1.1:853"},
		{tier: TierDoT, address: "1.1.1.1:853", tcp: true},
	}, exchanger.calls)
}

func Test_Ladder_SecondEndpointKeepsTier(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{}
	exchanger.handler = func(call exchangeCall) (*dns.Msg, error) {
		if call.address == "1.1.1.1:853" {
			response := successResponse()
			response.Rcode = dns.RcodeServerFailure
			return response, nil
		}
		return successResponse(), nil
	}
	ladder := newTestLadder(t, exchanger, map[TierType][]Endpoint{
		TierDoT: {
			NewEndpoint("1.1.1.1:853", "cloudflare"),
			NewEndpoint("9.9.9.9:853", "quad9"),
		},
		TierPlain: {NewEndpoint("8.8.8.8:53", "google")},
	})

	_, err := ladder.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	assert.Equal(t, []exchangeCall{
		{tier: TierDoT, address: "1.1.1.1:853"},
		{tier: TierDoT, address: "9.9.9.9:853"},
	}, exchanger.calls)
	assert.Equal(t, StateUp, ladder.Tiers()[0].State)
}

func Test_Ladder_Exhausted(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{
		handler: func(exchangeCall) (*dns.Msg, error) {
			return nil, errors.New("timeout")
		},
	}
	ladder := newTestLadder(t, exchanger, map[TierType][]Endpoint{
		TierDoT: {NewEndpoint("1.1.1.1:853", "cloudflare")},
	})

	_, err := ladder.Resolve(context.Background(), testRequest())
	assert.ErrorIs(t, err, ErrLadderExhausted)
	assert.Len(t, exchanger.calls, 1)
}

func Test_Ladder_DownTiersFailClosed(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{
		handler: func(exchangeCall) (*dns.Msg, error) {
			return nil, errors.New("timeout")
		},
	}
	ladder, err := New(Settings{
		Ladder: []TierType{TierDoT},
		Endpoints: map[TierType][]Endpoint{
			TierDoT: {NewEndpoint("1.1.1.1:853", "cloudflare")},
		},
		Health: NewHealth(HealthSettings{
			FailuresToDown: 1,
			BaseCooldown:   time.Minute,
			MaxCooldown:    time.Minute,
		}),
		Exchanger: exchanger,
	})
	require.NoError(t, err)

	_, err = ladder.Resolve(context.Background(), testRequest())
	assert.ErrorIs(t, err, ErrLadderExhausted)
	assert.True(t, ladder.FailClosed())
	assert.Empty(t, ladder.ActiveTier())

	_, err = ladder.Resolve(context.Background(), testRequest())
	assert.ErrorIs(t, err, ErrLadderExhausted)
	assert.Len(t, exchanger.calls, 1)
}

func Test_NewLadder_Validation(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{handler: func(exchangeCall) (*dns.Msg, error) {
		return successResponse(), nil
	}}

	_, err := New(Settings{})
	assert.Error(t, err)

	_, err = New(Settings{Exchanger: exchanger})
	assert.ErrorIs(t, err, ErrNoTierConfigured)

	_, err = New(Settings{
		Ladder:    []TierType{"unknown"},
		Exchanger: exchanger,
	})
	assert.Error(t, err)

	ladder, err := New(Settings{
		Ladder: []TierType{TierDoT, TierDoT},
		Endpoints: map[TierType][]Endpoint{
			TierDoT: {NewEndpoint("1.1.1.1:853", "cloudflare")},
		},
		Exchanger: exchanger,
	})
	require.NoError(t, err)
	assert.Len(t, ladder.Tiers(), 1)
}

func Test_Ladder_NoEndpoint(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{handler: func(exchangeCall) (*dns.Msg, error) {
		return successResponse(), nil
	}}
	ladder, err := New(Settings{
		Ladder:    []TierType{TierPlain},
		Exchanger: exchanger,
	})
	require.NoError(t, err)
	assert.Equal(t, StateDown, ladder.Tiers()[0].State)
	assert.True(t, ladder.FailClosed())

	_, err = ladder.Resolve(context.Background(), testRequest())
	assert.ErrorIs(t, err, ErrLadderExhausted)
	assert.Empty(t, exchanger.calls)
}

func Test_Ladder_TiersAreCopied(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{handler: func(exchangeCall) (*dns.Msg, error) {
		return successResponse(), nil
	}}
	ladder := newTestLadder(t, exchanger, map[TierType][]Endpoint{
		TierDoT: {NewEndpoint("1.1.1.1:853", "cloudflare")},
	})

	_, err := ladder.Resolve(context.Background(), testRequest())
	require.NoError(t, err)

	tiers := ladder.Tiers()
	tiers[0].State = StateDown
	tiers[0].Endpoints[0].State = StateDown
	assert.Equal(t, StateUp, ladder.Tiers()[0].State)
	assert.Equal(t, StateUp, ladder.Tiers()[0].Endpoints[0].State)
}
