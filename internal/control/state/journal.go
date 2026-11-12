package state

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	journalFileMode     = 0o600
	journalMaxLineBytes = 64 << 10
)

// JournalEntry is one append-only state transition record.
type JournalEntry struct {
	At       time.Time `json:"at"`
	Action   string    `json:"action"`
	Checksum string    `json:"checksum,omitempty"`
	Message  string    `json:"message,omitempty"`
}

// Journal is a size-bounded, rotated append-only file.
type Journal struct {
	path     string
	maxBytes int64
	maxFiles int
	mutex    sync.Mutex
}

// NewJournal creates a journal with bounded size and retention.
func NewJournal(path string, maxBytes int64, maxFiles int) *Journal {
	if path == "" {
		panic("journal path is empty")
	}
	if maxBytes <= 0 {
		panic("journal maximum bytes must be positive")
	}
	if maxFiles < 1 {
		panic("journal maximum files must be at least one")
	}
	return &Journal{
		path:     path,
		maxBytes: maxBytes,
		maxFiles: maxFiles,
	}
}

// Append writes one entry and fsyncs it.
func (j *Journal) Append(entry JournalEntry) error {
	if entry.At.IsZero() {
		entry.At = time.Now().UTC()
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encoding journal entry: %w", err)
	}
	encoded = append(encoded, '\n')

	j.mutex.Lock()
	defer j.mutex.Unlock()

	err = j.rotateIfNeeded(int64(len(encoded)))
	if err != nil {
		return fmt.Errorf("rotating journal: %w", err)
	}

	file, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		journalFileMode)
	if err != nil {
		return fmt.Errorf("opening journal: %w", err)
	}
	defer file.Close()

	_, err = file.Write(encoded)
	if err != nil {
		return fmt.Errorf("writing journal: %w", err)
	}

	err = file.Sync()
	if err != nil {
		return fmt.Errorf("syncing journal: %w", err)
	}
	return nil
}

// Read returns every decoded entry of the current journal file.
func (j *Journal) Read() (entries []JournalEntry, err error) {
	j.mutex.Lock()
	defer j.mutex.Unlock()

	file, err := os.Open(j.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening journal: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, journalMaxLineBytes), journalMaxLineBytes)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry JournalEntry
		err = json.Unmarshal(line, &entry)
		if err != nil {
			return nil, fmt.Errorf("decoding journal entry: %w", err)
		}
		entries = append(entries, entry)
	}

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("reading journal: %w", err)
	}
	return entries, nil
}

func (j *Journal) rotateIfNeeded(pending int64) error {
	information, err := os.Stat(j.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stating journal: %w", err)
	}
	if information.Size()+pending <= j.maxBytes {
		return nil
	}

	_ = os.Remove(j.path + "." + strconv.Itoa(j.maxFiles))
	for index := j.maxFiles - 1; index >= 1; index-- {
		from := j.path + "." + strconv.Itoa(index)
		to := j.path + "." + strconv.Itoa(index+1)
		err = os.Rename(from, to)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("rotating journal archive: %w", err)
		}
	}

	err = os.Rename(j.path, j.path+".1")
	if err != nil {
		return fmt.Errorf("archiving journal: %w", err)
	}
	return nil
}
