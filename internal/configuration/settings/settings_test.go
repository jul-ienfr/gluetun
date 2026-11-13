package settings

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Settings_String(t *testing.T) {
	t.Parallel()

	withDefaults := func(s Settings) Settings {
		s.SetDefaults()
		return s
	}

	testCases := map[string]struct {
		settings Settings
		s        string
	}{
		"default settings": {
			settings: withDefaults(Settings{}),
			s: `Settings summary:
├── VPN settings:
|   ├── VPN provider settings:
|   |   ├── Name: private internet access
|   |   └── Server selection settings:
|   |       ├── VPN type: openvpn
|   |       ├── Selection mode: random
|   |       └── OpenVPN server selection settings:
|   |           ├── Protocol: UDP
|   |           └── Private Internet Access encryption preset: strong
|   ├── OpenVPN settings:
|   |   ├── OpenVPN version: 2.6
|   |   ├── User: [not set]
|   |   ├── Password: [not set]
|   |   ├── Private Internet Access encryption preset: strong
|   |   ├── Network interface: tun0
|   |   ├── Run OpenVPN as: root
|   |   └── Verbosity level: 1
|   └── Path MTU discovery:
|       ├── ICMP addresses:
|       |   ├── 1.1.1.1
|       |   └── 8.8.8.8
|       └── TCP addresses:
|           ├── 1.1.1.1:53
|           ├── 8.8.8.8:53
|           ├── 1.1.1.1:443
|           ├── 8.8.8.8:443
|           ├── [2606:4700:4700::1111]:53
|           ├── [2001:4860:4860::8888]:53
|           ├── [2606:4700:4700::1111]:443
|           └── [2001:4860:4860::8888]:443
├── DNS settings:
|   ├── Upstream resolver type: dot
|   ├── Upstream resolvers:
|   |   └── Cloudflare
|   ├── Caching: yes
|   ├── IPv6: no
|   ├── Update period: every 24h0m0s
|   └── DNS filtering settings:
|       ├── Block malicious: yes
|       └── Block ads: no
├── Firewall settings:
|   ├── Enabled: yes
|   └── Iptables settings:
|       └── Log level: INFO
├── Log settings:
|   └── Log level: INFO
├── IPv6 settings:
|   └── Check addresses:
|       ├── [2001:4860:4860::8888]:53
|       └── [2606:4700:4700::1111]:53
├── Metrics settings:
|   └── Type: noop
├── Health settings:
|   ├── Server listening address: 127.0.0.1:9999
|   ├── Target addresses:
|   |   ├── cloudflare.com:443
|   |   └── github.com:443
|   ├── Small health check type: ICMP echo request
|   |   └── ICMP target IPs:
|   |       ├── 1.1.1.1
|   |       └── 8.8.8.8
|   └── Restart VPN on healthcheck failure: yes
├── SOCKS5 proxy server settings:
|   └── Enabled: no
├── Shadowsocks server settings:
|   └── Enabled: no
├── HTTP proxy settings:
|   └── Enabled: no
├── Control server settings:
|   ├── Listening address: :8000
|   ├── Logging: yes
|   └── Authentication file path: /gluetun/auth/config.toml
├── Control plane settings:
|   ├── Enabled: yes
|   ├── State directory: /gluetun/control
|   ├── State mode: state
|   ├── Egress verification settings:
|   |   ├── Enabled: yes
|   |   ├── Sources: http:ipify, dns:whoami, publicip:internal
|   |   ├── Quorum: 2
|   |   ├── Minimum sources: 3
|   |   ├── Allow single source: no
|   |   ├── Cache TTL: 10s
|   |   ├── Source timeout: 1.5s
|   |   ├── Source backoff: 30s
|   |   ├── Source maximum backoff: 5m0s
|   |   ├── IP family: 4
|   |   ├── Host IP automatic capture: yes
|   |   └── Allow test networks: no
|   ├── DNS ladder settings:
|   |   ├── Ladder: dot, plain
|   |   ├── Fail closed: yes
|   |   ├── Redundancy required: no
|   |   ├── Tier timeout: 800ms
|   |   ├── Tier attempts: 2
|   |   ├── Health failures to down: 3
|   |   ├── Health successes to recover: 2
|   |   ├── Health cooldown: 5s
|   |   ├── Health cooldown maximum: 5m0s
|   |   ├── Probe interval: 30s
|   |   └── Probe domain: example.com
|   ├── Transport ladder settings:
|   |   ├── Enabled: yes
|   |   ├── Ladder: wireguard, openvpn-udp, openvpn-tcp
|   |   ├── Attempt timeout: 30s
|   |   ├── TCP attempt timeout: 45s
|   |   ├── Maximum attempts: 2
|   |   ├── Breaker threshold: 3
|   |   ├── Breaker cooldown: 2m0s
|   |   ├── Breaker cooldown maximum: 15m0s
|   |   ├── Backoff base: 30s
|   |   ├── Backoff maximum: 5m0s
|   |   ├── Maximum cycles: 3
|   |   ├── Jitter: 0.2
|   |   └── Local reconnect maximum: 3
|   └── Canary settings:
|       └── Enabled: no
├── Storage settings:
|   └── Servers directory path: /gluetun/servers/
├── OS Alpine settings:
|   ├── Process UID: 1000
|   └── Process GID: 1000
├── Public IP settings:
|   ├── IP file path: /tmp/gluetun/ip
|   ├── Public IP data base API: ipinfo
|   └── Public IP data backup APIs:
|       ├── cloudflare
|       ├── ifconfigco
|       └── ip2location
└── Version settings:
    └── Enabled: yes`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := testCase.settings.String()

			assert.Equal(t, testCase.s, s)
		})
	}
}
