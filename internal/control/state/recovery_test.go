package state

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustState(t *testing.T, stationID string, settings TunnelSettings) DesiredState {
	t.Helper()
	state, err := NewDesiredState(stationID, ModeState, settings, testTime())
	require.NoError(t, err)
	return state
}

func Test_StoreRecover(t *testing.T) {
	t.Parallel()

	environment := testSettings()
	otherSettings := TunnelSettings{
		Provider:  "proton",
		VPN:       "openvpn",
		Countries: []string{"Iceland"},
	}
	persistedOther := mustState(t, "station-1", otherSettings)
	persistedSame := mustState(t, "station-1", environment)
	persistedPartial := mustState(t, "station-1", TunnelSettings{Provider: "proton"})
	persistedForeign := mustState(t, "station-2", otherSettings)

	mergedExpected := environment
	mergedExpected.Provider = "proton"

	testCases := map[string]struct {
		mode            string
		persisted       *DesiredState
		invalidContent  string
		expectedAction  string
		expectedDesired TunnelSettings
		expectLoadError bool
	}{
		"absent state": {
			mode:            ModeState,
			expectedAction:  ActionAbsent,
			expectedDesired: environment,
		},
		"absent state in merge mode": {
			mode:            ModeMerge,
			expectedAction:  ActionAbsent,
			expectedDesired: environment,
		},
		"state mode keeps persisted state": {
			mode:            ModeState,
			persisted:       &persistedOther,
			expectedAction:  ActionRecovered,
			expectedDesired: otherSettings,
		},
		"state mode with matching environment": {
			mode:            ModeState,
			persisted:       &persistedSame,
			expectedAction:  ActionRecovered,
			expectedDesired: environment,
		},
		"env mode overrides persisted state": {
			mode:            ModeEnv,
			persisted:       &persistedOther,
			expectedAction:  ActionDrift,
			expectedDesired: environment,
		},
		"env mode with matching environment": {
			mode:            ModeEnv,
			persisted:       &persistedSame,
			expectedAction:  ActionRecovered,
			expectedDesired: environment,
		},
		"merge mode fills missing values": {
			mode:            ModeMerge,
			persisted:       &persistedPartial,
			expectedAction:  ActionMerged,
			expectedDesired: mergedExpected,
		},
		"merge mode with matching environment": {
			mode:            ModeMerge,
			persisted:       &persistedSame,
			expectedAction:  ActionRecovered,
			expectedDesired: environment,
		},
		"foreign station state": {
			mode:            ModeState,
			persisted:       &persistedForeign,
			expectedAction:  ActionDrift,
			expectedDesired: environment,
		},
		"invalid state is not overwritten": {
			mode:            ModeState,
			invalidContent:  "{not json",
			expectedAction:  ActionInvalid,
			expectedDesired: environment,
			expectLoadError: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := New(t.TempDir())
			if testCase.persisted != nil {
				err := store.Save(*testCase.persisted)
				require.NoError(t, err)
			}
			if testCase.invalidContent != "" {
				err := os.WriteFile(store.statePath,
					[]byte(testCase.invalidContent), 0o600)
				require.NoError(t, err)
			}

			decision, err := store.Recover("station-1", environment, testCase.mode)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedAction, decision.Action)
			assert.True(t,
				decision.State.Desired.Equal(testCase.expectedDesired),
				"decision desired settings do not match")

			entries, err := store.journal.Read()
			require.NoError(t, err)
			require.NotEmpty(t, entries)
			assert.Equal(t, testCase.expectedAction,
				entries[len(entries)-1].Action)

			if testCase.expectLoadError {
				content, err := os.ReadFile(store.statePath)
				require.NoError(t, err)
				assert.Equal(t, testCase.invalidContent, string(content))
				return
			}

			loaded, found, err := store.Load()
			require.NoError(t, err)
			require.True(t, found)
			assert.True(t, loaded.Desired.Equal(testCase.expectedDesired),
				"persisted desired settings do not match")
		})
	}
}

func Test_StoreRecoverUnknownMode(t *testing.T) {
	t.Parallel()

	store := New(t.TempDir())

	_, err := store.Recover("station-1", testSettings(), "bogus")
	assert.ErrorIs(t, err, ErrInvalidState)
}

func Test_StoreRecoverInvalidJournalsWithoutChecksum(t *testing.T) {
	t.Parallel()

	store := New(t.TempDir())
	err := os.WriteFile(store.statePath, []byte("{not json"), 0o600)
	require.NoError(t, err)

	decision, err := store.Recover("station-1", testSettings(), ModeState)
	require.NoError(t, err)
	assert.Equal(t, ActionInvalid, decision.Action)

	entries, err := store.journal.Read()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, ActionInvalid, entries[0].Action)
	assert.Empty(t, entries[0].Checksum)
	assert.NotEmpty(t, entries[0].Message)
}
