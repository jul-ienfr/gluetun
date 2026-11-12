package catalog

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCatalog() *Catalog {
	return New(fakeSource{servers: testServers()})
}

func pageHostnames(page Page) []string {
	hostnames := make([]string, len(page.Items))
	for index, item := range page.Items {
		hostnames[index] = item.Hostname
	}
	return hostnames
}

func Test_Catalog_Query(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		query    Query
		expected []string
	}{
		"all sorted by hostname": {
			query: Query{},
			expected: []string{
				"de-2.example.com",
				"nl-1.example.com",
				"us-3.example.com",
			},
		},
		"country case insensitive": {
			query:    Query{Countries: []string{"netherlands"}},
			expected: []string{"nl-1.example.com"},
		},
		"protocol openvpn tcp": {
			query:    Query{Protocols: []string{"openvpn-tcp"}},
			expected: []string{"nl-1.example.com"},
		},
		"protocol wireguard": {
			query: Query{Protocols: []string{"wireguard"}},
			expected: []string{
				"de-2.example.com",
				"us-3.example.com",
			},
		},
		"free only": {
			query: Query{FreeOnly: true},
			expected: []string{
				"nl-1.example.com",
				"us-3.example.com",
			},
		},
		"owned only": {
			query:    Query{OwnedOnly: true},
			expected: []string{"de-2.example.com"},
		},
		"stream only": {
			query: Query{StreamOnly: true},
			expected: []string{
				"de-2.example.com",
				"nl-1.example.com",
			},
		},
		"category": {
			query:    Query{Categories: []string{"p2p"}},
			expected: []string{"de-2.example.com"},
		},
		"tier": {
			query: Query{Tiers: []string{"free"}},
			expected: []string{
				"nl-1.example.com",
				"us-3.example.com",
			},
		},
		"search city": {
			query:    Query{Search: "berlin"},
			expected: []string{"de-2.example.com"},
		},
		"search category": {
			query:    Query{Search: "P2P"},
			expected: []string{"de-2.example.com"},
		},
		"no match": {
			query:    Query{Countries: []string{"France"}},
			expected: []string{},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			page, err := newTestCatalog().Query(testCase.query)
			require.NoError(t, err)
			assert.Equal(t, testCase.expected, pageHostnames(page))
			assert.Equal(t, len(testCase.expected), page.TotalEstimate)
		})
	}
}

func Test_Catalog_Query_Pagination(t *testing.T) {
	t.Parallel()

	catalog := newTestCatalog()

	first, err := catalog.Query(Query{Limit: 1})
	require.NoError(t, err)
	assert.Equal(t, []string{"de-2.example.com"}, pageHostnames(first))
	assert.Equal(t, 3, first.TotalEstimate)
	require.NotNil(t, first.NextCursor)

	second, err := catalog.Query(Query{Limit: 1, Cursor: *first.NextCursor})
	require.NoError(t, err)
	assert.Equal(t, []string{"nl-1.example.com"}, pageHostnames(second))
	require.NotNil(t, second.NextCursor)

	third, err := catalog.Query(Query{Limit: 1, Cursor: *second.NextCursor})
	require.NoError(t, err)
	assert.Equal(t, []string{"us-3.example.com"}, pageHostnames(third))
	assert.Nil(t, third.NextCursor)
}

func Test_Catalog_Query_InvalidCursor(t *testing.T) {
	t.Parallel()

	_, err := newTestCatalog().Query(Query{Cursor: "not-a-cursor"})
	assert.True(t, errors.Is(err, ErrInvalidCursor))
}

func Test_Catalog_Query_LimitClamp(t *testing.T) {
	t.Parallel()

	page, err := newTestCatalog().Query(Query{Limit: MaxLimit + 100})
	require.NoError(t, err)
	assert.Len(t, page.Items, 3)

	page, err = newTestCatalog().Query(Query{})
	require.NoError(t, err)
	assert.Len(t, page.Items, 3)
}

func Test_QueryFromValues(t *testing.T) {
	t.Parallel()

	values := url.Values{
		"country":     []string{"Netherlands,Germany"},
		"city":        []string{" Amsterdam "},
		"protocol":    []string{"wireguard", "openvpn-tcp"},
		"tier":        []string{"free"},
		"q":           []string{"  berlin "},
		"free_only":   []string{"true"},
		"owned_only":  []string{"false"},
		"stream_only": []string{"1"},
		"limit":       []string{"10"},
		"cursor":      []string{" abc "},
	}

	query, err := QueryFromValues(values)
	require.NoError(t, err)
	assert.Equal(t, []string{"Netherlands", "Germany"}, query.Countries)
	assert.Equal(t, []string{"Amsterdam"}, query.Cities)
	assert.Equal(t, []string{"wireguard", "openvpn-tcp"}, query.Protocols)
	assert.Equal(t, []string{"free"}, query.Tiers)
	assert.Equal(t, "berlin", query.Search)
	assert.True(t, query.FreeOnly)
	assert.False(t, query.OwnedOnly)
	assert.True(t, query.StreamOnly)
	assert.Equal(t, 10, query.Limit)
	assert.Equal(t, "abc", query.Cursor)
}

func Test_QueryFromValues_Errors(t *testing.T) {
	t.Parallel()

	testCases := map[string]url.Values{
		"invalid limit":     {"limit": []string{"nope"}},
		"zero limit":        {"limit": []string{"0"}},
		"invalid free only": {"free_only": []string{"maybe"}},
	}

	for name, values := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := QueryFromValues(values)
			assert.Error(t, err)
		})
	}
}
