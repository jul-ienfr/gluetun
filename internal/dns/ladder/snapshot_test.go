package ladder

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Ladder_Snapshot(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{handler: func(exchangeCall) (*dns.Msg, error) {
		return successResponse(), nil
	}}
	ladder, err := New(Settings{
		Ladder: []TierType{TierDoT, TierPlain},
		Endpoints: map[TierType][]Endpoint{
			TierDoT:   {NewEndpoint("1.1.1.1:853", "cloudflare")},
			TierPlain: {NewEndpoint("8.8.8.8:53", "google")},
		},
		Exchanger:  exchanger,
		FailClosed: true,
	})
	require.NoError(t, err)

	snapshot := ladder.Snapshot()
	assert.Equal(t, []TierType{TierDoT, TierPlain}, snapshot.Ladder)
	assert.Equal(t, TierDoT, snapshot.ActiveTier)
	assert.True(t, snapshot.FailClosed)
	require.Len(t, snapshot.Tiers, 2)
	assert.False(t, snapshot.UpdatedAt.IsZero())
}

func Test_Ladder_Probe(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{handler: func(exchangeCall) (*dns.Msg, error) {
		return successResponse(), nil
	}}
	ladder, err := New(Settings{
		Ladder: []TierType{TierDoT},
		Endpoints: map[TierType][]Endpoint{
			TierDoT: {NewEndpoint("1.1.1.1:853", "cloudflare")},
		},
		Exchanger: exchanger,
	})
	require.NoError(t, err)

	result, err := ladder.Probe(context.Background(), TierDoT, "example.com",
		false)
	require.NoError(t, err)
	assert.True(t, result.OK)
	assert.Equal(t, TierDoT, result.Tier)
	assert.Equal(t, "NOERROR", result.Rcode)
	assert.Empty(t, result.Error)

	tiers := ladder.Tiers()
	assert.Equal(t, uint64(1), tiers[0].Successes)
}

func Test_Ladder_Probe_DryRunKeepsHealth(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{handler: func(exchangeCall) (*dns.Msg, error) {
		return nil, errors.New("blocked")
	}}
	ladder, err := New(Settings{
		Ladder: []TierType{TierPlain},
		Endpoints: map[TierType][]Endpoint{
			TierPlain: {NewEndpoint("8.8.8.8:53", "google")},
		},
		Exchanger: exchanger,
	})
	require.NoError(t, err)

	result, err := ladder.Probe(context.Background(), TierPlain, "",
		true)
	require.NoError(t, err)
	assert.False(t, result.OK)
	assert.Equal(t, TierPlain, result.Tier)
	assert.NotEmpty(t, result.Error)

	tiers := ladder.Tiers()
	assert.Equal(t, uint64(0), tiers[0].Failures)
	assert.Equal(t, StateUp, tiers[0].Endpoints[0].State)
}

func Test_Ladder_Probe_UnknownTier(t *testing.T) {
	t.Parallel()

	exchanger := &fakeExchanger{handler: func(exchangeCall) (*dns.Msg, error) {
		return successResponse(), nil
	}}
	ladder, err := New(Settings{
		Ladder: []TierType{TierDoT},
		Endpoints: map[TierType][]Endpoint{
			TierDoT: {NewEndpoint("1.1.1.1:853", "cloudflare")},
		},
		Exchanger: exchanger,
	})
	require.NoError(t, err)

	_, err = ladder.Probe(context.Background(), TierDoH, "example.com",
		false)
	assert.True(t, errors.Is(err, ErrUnknownTier))
}
