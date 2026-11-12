package state

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_writeFileAtomic(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")

	err := writeFileAtomic(path, []byte("first"))
	require.NoError(t, err)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "first", string(content))

	err = writeFileAtomic(path, []byte("second"))
	require.NoError(t, err)

	content, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "second", string(content))

	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "state.json", entries[0].Name())

	if runtime.GOOS != "windows" {
		information, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, fs.FileMode(0o600), information.Mode().Perm())
	}
}

func Test_writeFileAtomicMissingDirectory(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing", "state.json")

	err := writeFileAtomic(path, []byte("content"))
	assert.Error(t, err)
}
