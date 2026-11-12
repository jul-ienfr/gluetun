package api

import (
	"encoding/json"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/control/observability"
)

// RedactedSecret replaces every secret value in masked responses.
const RedactedSecret = "***"

// MaskedVPNSettings returns a JSON-serializable view of the VPN settings with
// every secret value redacted. Non-secret fields are preserved so operators can
// still inspect the effective configuration.
func MaskedVPNSettings(vpn settings.VPN) (masked map[string]any, err error) {
	raw, err := json.Marshal(vpn)
	if err != nil {
		return nil, err
	}

	var fields map[string]any
	err = json.Unmarshal(raw, &fields)
	if err != nil {
		return nil, err
	}

	return observability.ScrubMap(fields), nil
}
