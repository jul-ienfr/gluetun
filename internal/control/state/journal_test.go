package state

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_JournalAppendRead(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "journal.jsonl")
	journal := NewJournal(path, 1<<20, 2)

	expected := []JournalEntry{
		{At: testTime(), Action: "save", Checksum: "checksum"},
		{At: testTime().Add(time.Minute), Action: ActionDrift, Message: "drift"},
	}
	for _, entry := range expected {
		err := journal.Append(entry)
		require.NoError(t, err)
	}

	entries, err := journal.Read()
	require.NoError(t, err)
	assert.Equal(t, expected, entries)
}

func Test_JournalAppendSetsTime(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "journal.jsonl")
	journal := NewJournal(path, 1<<20, 2)

	err := journal.Append(JournalEntry{Action: "save"})
	require.NoError(t, err)

	entries, err := journal.Read()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.False(t, entries[0].At.IsZero())
}

func Test_JournalReadMissingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "journal.jsonl")
	journal := NewJournal(path, 1<<20, 2)

	entries, err := journal.Read()
	require.NoError(t, err)
	assert.Nil(t, entries)
}

func Test_JournalRotation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "journal.jsonl")
	const (
		maxBytes int64 = 300
		maxFiles int   = 2
	)
	journal := NewJournal(path, maxBytes, maxFiles)

	entry := JournalEntry{
		At:      testTime(),
		Action:  "save",
		Message: strings.Repeat("x", 100),
	}
	for range 20 {
		err := journal.Append(entry)
		require.NoError(t, err)
	}

	information, err := os.Stat(path)
	require.NoError(t, err)
	assert.LessOrEqual(t, information.Size(), maxBytes)

	for index := 1; index <= maxFiles; index++ {
		archive := path + "." + strconv.Itoa(index)
		_, err = os.Stat(archive)
		require.NoError(t, err, "archive %s is missing", archive)
	}

	_, err = os.Stat(path + "." + strconv.Itoa(maxFiles+1))
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func Test_NewJournalPanics(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		path     string
		maxBytes int64
		maxFiles int
	}{
		"empty path": {
			path:     "",
			maxBytes: 1,
			maxFiles: 1,
		},
		"zero maximum bytes": {
			path:     "journal.jsonl",
			maxBytes: 0,
			maxFiles: 1,
		},
		"zero maximum files": {
			path:     "journal.jsonl",
			maxBytes: 1,
			maxFiles: 0,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Panics(t, func() {
				NewJournal(testCase.path, testCase.maxBytes, testCase.maxFiles)
			})
		})
	}
}
