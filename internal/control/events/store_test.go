package events

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testEvent(sequence uint64) Event {
	return Event{
		Seq:      sequence,
		Time:     time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC),
		Type:     "job.committed",
		Severity: SeverityInfo,
		JobID:    "job-1",
		Data:     map[string]any{"hostname": "nl-1.example.com"},
	}
}

func Test_FileLog_AppendAndLoad(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	log := NewFileLog(directory, 4096, 3)

	for sequence := uint64(1); sequence <= 3; sequence++ {
		err := log.Append(testEvent(sequence))
		require.NoError(t, err)
	}

	allEvents, lastSeq, err := log.Load(0)
	require.NoError(t, err)
	assert.Equal(t, uint64(3), lastSeq)
	require.Len(t, allEvents, 3)
	assert.Equal(t, uint64(1), allEvents[0].Seq)
	assert.Equal(t, uint64(3), allEvents[2].Seq)

	lastEvents, lastSeq, err := log.Load(2)
	require.NoError(t, err)
	assert.Equal(t, uint64(3), lastSeq)
	require.Len(t, lastEvents, 2)
	assert.Equal(t, uint64(2), lastEvents[0].Seq)
	assert.Equal(t, uint64(3), lastEvents[1].Seq)
}

func Test_FileLog_MissingDirectory(t *testing.T) {
	t.Parallel()

	log := NewFileLog(filepath.Join(t.TempDir(), "missing"), 4096, 3)
	events, lastSeq, err := log.Load(0)
	require.NoError(t, err)
	assert.Empty(t, events)
	assert.Zero(t, lastSeq)
}

func Test_FileLog_RotationKeepsLastSequence(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	log := NewFileLog(directory, 600, 2)

	for sequence := uint64(1); sequence <= 20; sequence++ {
		err := log.Append(testEvent(sequence))
		require.NoError(t, err)
	}

	events, lastSeq, err := log.Load(0)
	require.NoError(t, err)
	assert.Equal(t, uint64(20), lastSeq)
	require.NotEmpty(t, events)
	assert.Equal(t, uint64(20), events[len(events)-1].Seq)

	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(entries), 2)
}

func Test_FileLog_InvalidChecksumIsIgnored(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	err := os.MkdirAll(directory, 0o700)
	require.NoError(t, err)

	valid := logRecord{Event: testEvent(1), Checksum: checksumFor(t, testEvent(1))}
	validLine, err := marshalRecord(valid)
	require.NoError(t, err)

	corrupted := []byte(`{"event":{"seq":2,"ts":"2026-11-12T12:00:00Z","type":"job.committed","severity":"info"},"checksum":"deadbeef"}` + "\n")

	content := append(validLine, corrupted...)
	err = os.WriteFile(filepath.Join(directory, logFileName), content, 0o600)
	require.NoError(t, err)

	log := NewFileLog(directory, 4096, 3)
	events, lastSeq, err := log.Load(0)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), lastSeq)
	require.Len(t, events, 1)
	assert.Equal(t, uint64(1), events[0].Seq)
}

func checksumFor(t *testing.T, event Event) string {
	t.Helper()
	encoded, err := json.Marshal(event)
	require.NoError(t, err)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func marshalRecord(record logRecord) ([]byte, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
