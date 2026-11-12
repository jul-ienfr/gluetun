package consensus

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/stretchr/testify/assert"
)

func Test_RejectionReason(t *testing.T) {
	t.Parallel()

	hostIPv4 := netip.MustParseAddr("198.18.0.9")
	hostIPv6 := netip.MustParseAddr("2001:4860::9")
	forbiddenIPv4 := netip.MustParseAddr("198.18.0.8")
	forbiddenIPv6 := netip.MustParseAddr("2001:4860::8")

	baseOptions := Options{
		Family:       0,
		HostIPs:      []netip.Addr{hostIPv4, hostIPv6},
		ForbiddenIPs: []netip.Addr{forbiddenIPv4, forbiddenIPv6},
	}
	allowTestOptions := baseOptions
	allowTestOptions.AllowTestNets = true
	family4Options := baseOptions
	family4Options.Family = 4
	family6Options := baseOptions
	family6Options.Family = 6

	testCases := map[string]struct {
		ip       string
		options  *Options
		expected egress.Reason
	}{
		"public_ipv4":             {ip: "8.8.8.8"},
		"public_ipv4_cloudflare":  {ip: "1.1.1.1"},
		"public_ipv6":             {ip: "2001:4860:4860::8888"},
		"private_10":              {ip: "10.0.0.1", expected: egress.ReasonPrivate},
		"private_10_edge":         {ip: "10.255.255.255", expected: egress.ReasonPrivate},
		"private_172_16":          {ip: "172.16.0.1", expected: egress.ReasonPrivate},
		"private_172_31":          {ip: "172.31.255.255", expected: egress.ReasonPrivate},
		"public_172_32":           {ip: "172.32.0.1"},
		"private_192_168":         {ip: "192.168.1.1", expected: egress.ReasonPrivate},
		"private_192_168_edge":    {ip: "192.168.255.255", expected: egress.ReasonPrivate},
		"private_ipv6_ula":        {ip: "fd00::1", expected: egress.ReasonPrivate},
		"private_ipv6_ula_edge":   {ip: "fdff:ffff::1", expected: egress.ReasonPrivate},
		"loopback_ipv4":           {ip: "127.0.0.1", expected: egress.ReasonLoopback},
		"loopback_ipv4_edge":      {ip: "127.255.255.254", expected: egress.ReasonLoopback},
		"loopback_ipv6":           {ip: "::1", expected: egress.ReasonLoopback},
		"link_local_ipv4":         {ip: "169.254.1.1", expected: egress.ReasonLinkLocal},
		"link_local_ipv6":         {ip: "fe80::1", expected: egress.ReasonLinkLocal},
		"public_169_253":          {ip: "169.253.0.1"},
		"cgnat_low":               {ip: "100.64.0.1", expected: egress.ReasonCGNAT},
		"cgnat_high":              {ip: "100.127.255.255", expected: egress.ReasonCGNAT},
		"public_100_63":           {ip: "100.63.255.255"},
		"public_100_128":          {ip: "100.128.0.0"},
		"multicast_ipv4":          {ip: "224.0.0.1", expected: egress.ReasonMulticast},
		"multicast_ipv4_high":     {ip: "239.255.255.250", expected: egress.ReasonMulticast},
		"multicast_ipv6":          {ip: "ff02::1", expected: egress.ReasonMulticast},
		"unspecified_ipv4":        {ip: "0.0.0.0", expected: egress.ReasonUnspecified},
		"unspecified_ipv6":        {ip: "::", expected: egress.ReasonUnspecified},
		"documentation_192_0_2":   {ip: "192.0.2.1", expected: egress.ReasonDocumenting},
		"documentation_198_51":    {ip: "198.51.100.1", expected: egress.ReasonDocumenting},
		"documentation_203_0_113": {ip: "203.0.113.1", expected: egress.ReasonDocumenting},
		"documentation_ipv6":      {ip: "2001:db8::1", expected: egress.ReasonDocumenting},
		"documentation_allowed":   {ip: "192.0.2.1", options: &allowTestOptions},
		"documentation_allowed6":  {ip: "2001:db8::1", options: &allowTestOptions},
		"host_ipv4":               {ip: hostIPv4.String(), expected: egress.ReasonHostIP},
		"host_ipv6":               {ip: hostIPv6.String(), expected: egress.ReasonHostIP},
		"host_ipv4_mapped":        {ip: "::ffff:198.18.0.9", expected: egress.ReasonHostIP},
		"forbidden_ipv4":          {ip: forbiddenIPv4.String(), expected: egress.ReasonForbiddenIP},
		"forbidden_ipv6":          {ip: forbiddenIPv6.String(), expected: egress.ReasonForbiddenIP},
		"wrong_family_v6":         {ip: "2001:4860::1", options: &family4Options, expected: egress.ReasonWrongFamily},
		"wrong_family_v4":         {ip: "8.8.8.8", options: &family6Options, expected: egress.ReasonWrongFamily},
		"family_v4_ok":            {ip: "8.8.8.8", options: &family4Options},
		"family_v6_ok":            {ip: "2001:4860::1", options: &family6Options},
		"mapped_public_family4":   {ip: "::ffff:8.8.8.8", options: &family4Options},
		"invalid":                 {expected: egress.ReasonMalformed},
	}

	assert.GreaterOrEqual(t, len(testCases), 40)

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			options := baseOptions
			if testCase.options != nil {
				options = *testCase.options
			}
			ip := netip.Addr{}
			if testCase.ip != "" {
				ip = netip.MustParseAddr(testCase.ip)
			}

			reason := RejectionReason(ip, options)
			assert.Equal(t, testCase.expected, reason)
		})
	}
}
