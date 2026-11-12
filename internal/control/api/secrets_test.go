package api

import (
	"encoding/json"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stringPointer(value string) *string {
	return &value
}

func secretVPNSettings() settings.VPN {
	return settings.VPN{
		Type: "openvpn",
		Provider: settings.Provider{
			Name: "nordvpn",
			PortForwarding: settings.PortForwarding{
				Username: "port-forward-user",
				Password: "port-forward-password",
			},
		},
		OpenVPN: settings.OpenVPN{
			User:          stringPointer("openvpn-user"),
			Password:      stringPointer("openvpn-password"),
			Key:           stringPointer("openvpn-private-key"),
			EncryptedKey:  stringPointer("openvpn-encrypted-key"),
			KeyPassphrase: stringPointer("openvpn-key-passphrase"),
		},
		Wireguard: settings.Wireguard{
			PrivateKey:   stringPointer("wireguard-private-key"),
			PreSharedKey: stringPointer("wireguard-pre-shared-key"),
			Interface:    "wg0",
		},
		AmneziaWg: settings.AmneziaWg{
			HeaderProtectionKey: stringPointer("amnezia-header-key"),
		},
	}
}

func Test_MaskedVPNSettings_RedactsEverySecret(t *testing.T) {
	t.Parallel()

	masked, err := MaskedVPNSettings(secretVPNSettings())
	require.NoError(t, err)

	encoded, err := json.Marshal(masked)
	require.NoError(t, err)
	text := string(encoded)

	secrets := []string{
		"port-forward-password",
		"openvpn-password",
		"openvpn-private-key",
		"openvpn-encrypted-key",
		"openvpn-key-passphrase",
		"wireguard-private-key",
		"wireguard-pre-shared-key",
		"amnezia-header-key",
	}
	for _, secret := range secrets {
		assert.NotContains(t, text, secret)
	}
	assert.Contains(t, text, RedactedSecret)

	assert.Contains(t, text, "nordvpn")
	assert.Contains(t, text, "wg0")
	assert.Contains(t, text, "openvpn-user",
		"usernames are not secrets and must stay visible")
}

func Test_MaskedVPNSettings_PreservesShape(t *testing.T) {
	t.Parallel()

	vpnSettings := secretVPNSettings()
	masked, err := MaskedVPNSettings(vpnSettings)
	require.NoError(t, err)

	openVPN, ok := masked["openvpn"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, RedactedSecret, openVPN["password"])
	assert.Equal(t, RedactedSecret, openVPN["key"])
	assert.Equal(t, RedactedSecret, openVPN["key_passphrase"])
	assert.Equal(t, RedactedSecret, openVPN["encrypted_key"])

	wireguard, ok := masked["wireguard"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, RedactedSecret, wireguard["private_key"])
	assert.Equal(t, RedactedSecret, wireguard["pre_shared_key"])
	assert.Equal(t, "wg0", wireguard["interface"])

	amnezia, ok := masked["amneziawg"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, RedactedSecret, amnezia["header_protection_key"])

	provider, ok := masked["provider"].(map[string]any)
	require.True(t, ok)
	portForwarding, ok := provider["port_forwarding"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, RedactedSecret, portForwarding["password"])
}
