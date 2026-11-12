package observability

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_IsSensitiveKey(t *testing.T) {
	t.Parallel()

	testCases := map[string]bool{
		"password":            true,
		"PASSWORD":            true,
		"db_password":         true,
		"passwd":              true,
		"api_key":             true,
		"apikey":              true,
		"api-key":             true,
		"API Key":             true,
		"token":               true,
		"refresh_token":       true,
		"secret":              true,
		"client_secret":       true,
		"private_key":         true,
		"privatekey":          true,
		"authorization":       true,
		"credential":          true,
		"username":            false,
		"hostname":            false,
		"public_ip":           false,
		"transport":           false,
		"dns_ladder":          false,
		"monkey":              false,
		"tokens_per_second":   true,
		"secretary_general":   true,
		"tunnel_public_key":   false,
		"wireguard_endpoint":  false,
		"ovpn_config_content": false,
	}

	for key, expected := range testCases {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, expected, IsSensitiveKey(key))
		})
	}
}

func Test_ScrubText(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		input    string
		expected string
	}{
		"bearer token": {
			input:    "Authorization: Bearer abc.def-123_456",
			expected: "Authorization: Bearer ***",
		},
		"lowercase bearer": {
			input:    "header bearer tokenvalue",
			expected: "header bearer ***",
		},
		"api key equals": {
			input:    "api_key=deadbeef",
			expected: "api_key=***",
		},
		"api-key colon": {
			input:    "api-key: secret-value",
			expected: "api-key: ***",
		},
		"quoted token": {
			input:    `token: "quoted value"`,
			expected: `token: ***`,
		},
		"password": {
			input:    "password=hunter2;user=me",
			expected: "password=***;user=me",
		},
		"secret": {
			input:    "client secret=abc",
			expected: "client secret=***",
		},
		"url userinfo": {
			input: "dialing https://" + "user" + ":" + "pass" +
				"@example.com:443/v1",
			expected: "dialing https://***@example.com:443/v1",
		},
		"plain url untouched": {
			input:    "dialing https://example.com:443/v1",
			expected: "dialing https://example.com:443/v1",
		},
		"two credentials": {
			input:    "api_key=aaa password=bbb",
			expected: "api_key=*** password=***",
		},
		"no credential": {
			input:    "transport=wireguard server=nl-1",
			expected: "transport=wireguard server=nl-1",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.expected, ScrubText(testCase.input))
		})
	}
}

func Test_ScrubMap(t *testing.T) {
	t.Parallel()

	t.Run("nil map", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, ScrubMap(nil))
	})

	t.Run("top level secret", func(t *testing.T) {
		t.Parallel()

		fields := map[string]any{
			"password": "hunter2",
			"hostname": "nl-1",
		}
		scrubbed := ScrubMap(fields)

		assert.Equal(t, "***", scrubbed["password"])
		assert.Equal(t, "nl-1", scrubbed["hostname"])
	})

	t.Run("input map is not mutated", func(t *testing.T) {
		t.Parallel()

		fields := map[string]any{"api_key": "deadbeef"}
		_ = ScrubMap(fields)

		assert.Equal(t, "deadbeef", fields["api_key"])
	})

	t.Run("nested maps", func(t *testing.T) {
		t.Parallel()

		endpoint := "https://" + "alice" + ":" + "secret" + "@vpn.example.com"
		fields := map[string]any{
			"job": map[string]any{
				"id":       "job_01",
				"token":    "nested-token",
				"endpoint": endpoint,
			},
		}
		scrubbed := ScrubMap(fields)
		job, ok := scrubbed["job"].(map[string]any)
		require.True(t, ok)

		assert.Equal(t, "job_01", job["id"])
		assert.Equal(t, "***", job["token"])
		assert.Equal(t, "https://***@vpn.example.com", job["endpoint"])
	})

	t.Run("map of strings", func(t *testing.T) {
		t.Parallel()

		fields := map[string]any{
			"env": map[string]string{
				"API_KEY": "deadbeef",
				"REGION":  "nl",
			},
		}
		scrubbed := ScrubMap(fields)
		env, ok := scrubbed["env"].(map[string]string)
		require.True(t, ok)

		assert.Equal(t, "***", env["API_KEY"])
		assert.Equal(t, "nl", env["REGION"])
	})

	t.Run("slices", func(t *testing.T) {
		t.Parallel()

		fields := map[string]any{
			"headers": []any{
				"Bearer abc",
				map[string]any{"secret": "x"},
			},
			"values": []string{"token=abc", "plain"},
		}
		scrubbed := ScrubMap(fields)

		headers, ok := scrubbed["headers"].([]any)
		require.True(t, ok)
		assert.Equal(t, "Bearer ***", headers[0])
		nested, ok := headers[1].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "***", nested["secret"])

		values, ok := scrubbed["values"].([]string)
		require.True(t, ok)
		assert.Equal(t, []string{"token=***", "plain"}, values)
	})

	t.Run("scalar types preserved", func(t *testing.T) {
		t.Parallel()

		fields := map[string]any{
			"count": 3,
			"ok":    true,
			"ratio": 0.5,
		}
		scrubbed := ScrubMap(fields)

		assert.Equal(t, 3, scrubbed["count"])
		assert.Equal(t, true, scrubbed["ok"])
		assert.Equal(t, 0.5, scrubbed["ratio"])
	})
}
