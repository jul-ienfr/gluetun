package state

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_StoreLoadAbsent(t *testing.T) {
	t.Parallel()

	store := New(t.TempDir())

	_, found, err := store.Load()
	require.NoError(t, err)
	assert.False(t, found)
}

func Test_StoreSaveLoad(t *testing.T) {
	t.Parallel()

	store := New(t.TempDir())
	state := testDesiredState(t)

	err := store.Save(state)
	require.NoError(t, err)

	loaded, found, err := store.Load()
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, state, loaded)

	entries, err := store.journal.Read()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "save", entries[0].Action)
	assert.Equal(t, state.Checksum, entries[0].Checksum)
}

func Test_StoreSaveSealsState(t *testing.T) {
	t.Parallel()

	store := New(t.TempDir())
	state := testDesiredState(t)
	state.Checksum = ""

	err := store.Save(state)
	require.NoError(t, err)

	loaded, found, err := store.Load()
	require.NoError(t, err)
	require.True(t, found)
	assert.NotEmpty(t, loaded.Checksum)
	assert.True(t, loaded.Desired.Equal(testSettings()))
}

func Test_StoreLoadInvalid(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		content string
	}{
		"malformed JSON": {
			content: "{",
		},
		"missing fields": {
			content: "{}",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := New(t.TempDir())
			err := os.WriteFile(store.statePath, []byte(testCase.content), 0o600)
			require.NoError(t, err)

			_, found, err := store.Load()
			assert.True(t, found)
			assert.ErrorIs(t, err, ErrInvalidState)
		})
	}
}

func Test_StoreLoadChecksumMismatch(t *testing.T) {
	t.Parallel()

	store := New(t.TempDir())
	state := testDesiredState(t)
	state.StationID = "station-2"

	encoded, err := json.MarshalIndent(state, "", "  ")
	require.NoError(t, err)
	err = os.WriteFile(store.statePath, encoded, 0o600)
	require.NoError(t, err)

	_, found, err := store.Load()
	assert.True(t, found)
	assert.ErrorIs(t, err, ErrChecksumMismatch)
}

func Test_StoreSaveInvalidKeepsPrevious(t *testing.T) {
	t.Parallel()

	store := New(t.TempDir())
	previous := testDesiredState(t)
	err := store.Save(previous)
	require.NoError(t, err)

	invalid := previous
	invalid.Mode = "bogus"

	err = store.Save(invalid)
	assert.ErrorIs(t, err, ErrInvalidState)

	loaded, found, err := store.Load()
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, previous, loaded)
}

func Test_StoreSaveWriteFailure(t *testing.T) {
	t.Parallel()

	store := New(t.TempDir())
	err := os.Mkdir(store.statePath, 0o700)
	require.NoError(t, err)

	err = store.Save(testDesiredState(t))
	assert.Error(t, err)

	entries, err := os.ReadDir(store.directory)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "state.json", entries[0].Name())
}
