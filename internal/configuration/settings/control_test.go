package settings

import (
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/reader/sources/env"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Control_SetDefaults(t *testing.T) {
	t.Parallel()

	var control Control
	control.setDefaults()

	assert.Equal(t, ptrTo(true), control.Enabled)
	assert.Equal(t, "/gluetun/control", control.StateDir)
	assert.Equal(t, "state", control.StateMode)
	assert.Equal(t, ptrTo(true), control.Egress.Enabled)
	assert.Equal(t, []string{"http:ipify", "dns:whoami", "publicip:internal"},
		control.Egress.Sources)
	assert.Equal(t, uint(2), control.Egress.Quorum)
	assert.Equal(t, uint(3), control.Egress.MinSources)
	assert.Equal(t, ptrTo(false), control.Egress.AllowSingle)
	assert.Equal(t, 10*time.Second, control.Egress.CacheTTL)
	assert.Equal(t, 1500*time.Millisecond, control.Egress.SourceTimeout)
	assert.Equal(t, 30*time.Second, control.Egress.SourceBackoff)
	assert.Equal(t, 300*time.Second, control.Egress.SourceBackoffMax)
	assert.Equal(t, "4", control.Egress.Family)
	assert.Equal(t, ptrTo(true), control.Egress.HostIPAuto)
	assert.Equal(t, ptrTo(false), control.Egress.AllowTestNets)
	assert.Equal(t, []string{"dot", "plain"}, control.DNS.Ladder)
	assert.Equal(t, ptrTo(true), control.DNS.FailClosed)
	assert.Equal(t, ptrTo(false), control.DNS.RedundancyRequired)
	assert.Empty(t, control.DNS.ProvidersDot)
	assert.Empty(t, control.DNS.ProvidersDoh)
	assert.Empty(t, control.DNS.PlainAddresses)
	assert.Equal(t, 800*time.Millisecond, control.DNS.Timeout)
	assert.Equal(t, 2, control.DNS.Attempts)
	assert.Equal(t, 3, control.DNS.FailuresToDown)
	assert.Equal(t, 2, control.DNS.SuccessesToRecover)
	assert.Equal(t, 5*time.Second, control.DNS.BaseCooldown)
	assert.Equal(t, 5*time.Minute, control.DNS.MaxCooldown)
	assert.Equal(t, 30*time.Second, control.DNS.ProbeInterval)
	assert.Equal(t, "example.com", control.DNS.ProbeDomain)
}

func Test_Control_Validate(t *testing.T) {
	t.Parallel()

	defaults := func() Control {
		var control Control
		control.setDefaults()
		return control
	}

	testCases := map[string]struct {
		control Control
		err     string
	}{
		"defaults": {
			control: defaults(),
		},
		"disabled skips validation": {
			control: func() Control {
				control := defaults()
				control.Enabled = ptrTo(false)
				control.StateDir = "relative"
				control.StateMode = "invalid"
				return control
			}(),
		},
		"relative state directory": {
			control: func() Control {
				control := defaults()
				control.StateDir = "relative"
				return control
			}(),
			err: "state directory path must be absolute: relative",
		},
		"invalid state mode": {
			control: func() Control {
				control := defaults()
				control.StateMode = "invalid"
				return control
			}(),
			err: "state mode: value is not one of the possible choices: invalid must be one of state, env or merge",
		},
		"quorum greater than minimum sources": {
			control: func() Control {
				control := defaults()
				control.Egress.Quorum = 4
				return control
			}(),
			err: "egress: quorum 4 is greater than minimum sources 3",
		},
		"too few sources": {
			control: func() Control {
				control := defaults()
				control.Egress.Sources = []string{"http:ipify"}
				return control
			}(),
			err: "egress: configured sources 1 is less than minimum sources 3",
		},
		"invalid source format": {
			control: func() Control {
				control := defaults()
				control.Egress.Sources = []string{"ipify"}
				return control
			}(),
			err: "egress: source 1 is not in the kind:name format: ipify",
		},
		"invalid source kind": {
			control: func() Control {
				control := defaults()
				control.Egress.Sources = []string{"ftp:ipify"}
				return control
			}(),
			err: "egress: source 1 kind: value is not one of the possible " +
				"choices: ftp must be one of http, dns, publicip or static",
		},
		"invalid family": {
			control: func() Control {
				control := defaults()
				control.Egress.Family = "5"
				return control
			}(),
			err: "egress: family: value is not one of the possible choices: 5 must be one of 4, 6 or both",
		},
		"negative cache TTL": {
			control: func() Control {
				control := defaults()
				control.Egress.CacheTTL = -time.Second
				return control
			}(),
			err: "egress: cache TTL cannot be negative: -1s",
		},
		"zero source timeout": {
			control: func() Control {
				control := defaults()
				control.Egress.SourceTimeout = 0
				return control
			}(),
			err: "egress: source timeout must be greater than 0",
		},
		"maximum backoff lower than backoff": {
			control: func() Control {
				control := defaults()
				control.Egress.SourceBackoffMax = time.Second
				return control
			}(),
			err: "egress: source maximum backoff 1s is less than source backoff 30s",
		},
		"host IP set with automatic capture": {
			control: func() Control {
				control := defaults()
				control.Egress.HostIP = netip.AddrFrom4([4]byte{192, 0, 2, 1})
				return control
			}(),
			err: "egress: host IP cannot be set when host IP auto capture is enabled",
		},
		"automatic capture disabled without host IP": {
			control: func() Control {
				control := defaults()
				control.Egress.HostIPAuto = ptrTo(false)
				return control
			}(),
			err: "egress: host IP must be set when host IP auto capture is disabled",
		},
		"single tier with redundancy required": {
			control: func() Control {
				control := defaults()
				control.DNS.Ladder = []string{"dot"}
				control.DNS.RedundancyRequired = ptrTo(true)
				return control
			}(),
			err: "dns: at least two tiers are required when fail closed and redundancy are enabled",
		},
		"duplicate tiers": {
			control: func() Control {
				control := defaults()
				control.DNS.Ladder = []string{"dot", "dot"}
				return control
			}(),
			err: `dns: tier "dot" is duplicated`,
		},
		"unknown tier": {
			control: func() Control {
				control := defaults()
				control.DNS.Ladder = []string{"dot", "udp"}
				return control
			}(),
			err: "dns: tier 2: value is not one of the possible choices: udp must be one of dot, doh or plain",
		},
		"unknown DoT provider": {
			control: func() Control {
				control := defaults()
				control.DNS.ProvidersDot = []string{"unknown"}
				return control
			}(),
			err: "dns: DNS_TIER_PROVIDERS_DOT provider 1: provider does not match any known providers: unknown",
		},
		"zero tier timeout": {
			control: func() Control {
				control := defaults()
				control.DNS.Timeout = 0
				return control
			}(),
			err: "dns: DNS tier timeout must be positive: 0s",
		},
		"maximum cooldown lower than base": {
			control: func() Control {
				control := defaults()
				control.DNS.MaxCooldown = time.Second
				return control
			}(),
			err: "dns: DNS health cooldown maximum 1s is less than base 5s",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.control.validate()

			if testCase.err == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, testCase.err, err.Error())
		})
	}
}

func Test_Control_Copy(t *testing.T) {
	t.Parallel()

	var original Control
	original.setDefaults()

	copied := original.copy()
	require.NotNil(t, copied.Enabled)
	assert.NotSame(t, original.Enabled, copied.Enabled)

	copied.Egress.Sources[0] = "http:changed"
	assert.Equal(t, "http:ipify", original.Egress.Sources[0])

	copied.DNS.Ladder[0] = "doh"
	assert.Equal(t, "dot", original.DNS.Ladder[0])

	original.DNS.ProvidersDot = []string{"cloudflare"}
	copied = original.copy()
	copied.DNS.ProvidersDot[0] = "google"
	assert.Equal(t, "cloudflare", original.DNS.ProvidersDot[0])
}

func Test_Control_Read(t *testing.T) {
	t.Parallel()

	environ := []string{
		"CONTROL_PLANE_ENABLED=off",
		"CONTROL_STATE_DIR=/tmp/control",
		"CONTROL_STATE_MODE=merge",
		"CONTROL_EGRESS_ENABLED=off",
		"CONTROL_EGRESS_SOURCES=http:custom,dns:custom,publicip:custom",
		"CONTROL_EGRESS_QUORUM=2",
		"CONTROL_EGRESS_MIN_SOURCES=4",
		"CONTROL_EGRESS_ALLOW_SINGLE=true",
		"CONTROL_EGRESS_CACHE_TTL_S=5",
		"CONTROL_EGRESS_SOURCE_TIMEOUT_MS=250",
		"CONTROL_EGRESS_SOURCE_BACKOFF_MS=1000",
		"CONTROL_EGRESS_SOURCE_BACKOFF_MAX_MS=2000",
		"CONTROL_EGRESS_FAMILY=both",
		"CONTROL_EGRESS_FORBIDDEN_IPS=198.51.100.1,198.51.100.2",
		"CONTROL_EGRESS_HOST_IP_AUTO=false",
		"CONTROL_HOST_IP=192.0.2.10",
		"CONTROL_EGRESS_ALLOW_TEST_NETS=true",
		"DNS_LADDER=dot,doh,plain",
		"DNS_FAIL_CLOSED=false",
		"DNS_REDUNDANCY_REQUIRED=true",
		"DNS_TIER_PROVIDERS_DOT=cloudflare,quad9",
		"DNS_TIER_PROVIDERS_DOH=google",
		"DNS_TIER_ADDRESSES_PLAIN=1.1.1.1:53,9.9.9.9:53",
		"DNS_TIER_TIMEOUT_MS=750",
		"DNS_TIER_ATTEMPTS=3",
		"DNS_HEALTH_FAILURES=4",
		"DNS_HEALTH_SUCCESSES=3",
		"DNS_HEALTH_COOLDOWN_MS=10000",
		"DNS_HEALTH_COOLDOWN_MAX_MS=120000",
		"DNS_PROBE_INTERVAL_S=15",
		"DNS_PROBE_DOMAIN=probe.example.com",
	}
	settingsReader := reader.New(reader.Settings{
		Sources: []reader.Source{
			env.New(env.Settings{Environ: environ}),
		},
	})

	var control Control
	err := control.read(settingsReader)
	require.NoError(t, err)
	control.setDefaults()

	assert.Equal(t, ptrTo(false), control.Enabled)
	assert.Equal(t, "/tmp/control", control.StateDir)
	assert.Equal(t, "merge", control.StateMode)
	assert.Equal(t, ptrTo(false), control.Egress.Enabled)
	assert.Equal(t, []string{"http:custom", "dns:custom", "publicip:custom"},
		control.Egress.Sources)
	assert.Equal(t, uint(2), control.Egress.Quorum)
	assert.Equal(t, uint(4), control.Egress.MinSources)
	assert.Equal(t, ptrTo(true), control.Egress.AllowSingle)
	assert.Equal(t, 5*time.Second, control.Egress.CacheTTL)
	assert.Equal(t, 250*time.Millisecond, control.Egress.SourceTimeout)
	assert.Equal(t, time.Second, control.Egress.SourceBackoff)
	assert.Equal(t, 2*time.Second, control.Egress.SourceBackoffMax)
	assert.Equal(t, "both", control.Egress.Family)
	assert.Equal(t, []netip.Addr{
		netip.AddrFrom4([4]byte{198, 51, 100, 1}),
		netip.AddrFrom4([4]byte{198, 51, 100, 2}),
	}, control.Egress.ForbiddenIPs)
	assert.Equal(t, ptrTo(false), control.Egress.HostIPAuto)
	assert.Equal(t, netip.AddrFrom4([4]byte{192, 0, 2, 10}), control.Egress.HostIP)
	assert.Equal(t, ptrTo(true), control.Egress.AllowTestNets)
	assert.Equal(t, []string{"dot", "doh", "plain"}, control.DNS.Ladder)
	assert.Equal(t, ptrTo(false), control.DNS.FailClosed)
	assert.Equal(t, ptrTo(true), control.DNS.RedundancyRequired)
	assert.Equal(t, []string{"cloudflare", "quad9"}, control.DNS.ProvidersDot)
	assert.Equal(t, []string{"google"}, control.DNS.ProvidersDoh)
	assert.Equal(t, []netip.AddrPort{
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 53),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{9, 9, 9, 9}), 53),
	}, control.DNS.PlainAddresses)
	assert.Equal(t, 750*time.Millisecond, control.DNS.Timeout)
	assert.Equal(t, 3, control.DNS.Attempts)
	assert.Equal(t, 4, control.DNS.FailuresToDown)
	assert.Equal(t, 3, control.DNS.SuccessesToRecover)
	assert.Equal(t, 10*time.Second, control.DNS.BaseCooldown)
	assert.Equal(t, 120*time.Second, control.DNS.MaxCooldown)
	assert.Equal(t, 15*time.Second, control.DNS.ProbeInterval)
	assert.Equal(t, "probe.example.com", control.DNS.ProbeDomain)
}
