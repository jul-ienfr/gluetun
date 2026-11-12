package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	stateDirectoryMode       = 0o700
	stateFileName            = "state.json"
	journalFileName          = "state.journal.jsonl"
	journalMaxBytes    int64 = 1 << 20
	journalMaxFiles          = 3
)

// Store persists the desired state and its journal in one directory.
type Store struct {
	directory string
	statePath string
	journal   *Journal
	now       func() time.Time
	mutex     sync.Mutex
}

// New creates a state store rooted at a directory.
func New(directory string) *Store {
	if directory == "" {
		panic("state directory is empty")
	}
	return &Store{
		directory: directory,
		statePath: filepath.Join(directory, stateFileName),
		journal: NewJournal(filepath.Join(directory, journalFileName),
			journalMaxBytes, journalMaxFiles),
		now: time.Now,
	}
}

// Load reads and validates the persisted desired state. It returns found false
// when no state file exists yet.
func (s *Store) Load() (state DesiredState, found bool, err error) {
	encoded, err := os.ReadFile(s.statePath)
	if errors.Is(err, fs.ErrNotExist) {
		return DesiredState{}, false, nil
	}
	if err != nil {
		return DesiredState{}, false, fmt.Errorf("reading desired state: %w", err)
	}

	err = json.Unmarshal(encoded, &state)
	if err != nil {
		return DesiredState{}, true,
			fmt.Errorf("%w: decoding JSON: %w", ErrInvalidState, err)
	}

	err = state.validate()
	if err != nil {
		return DesiredState{}, true, err
	}
	return state, true, nil
}

// Save seals the state, writes it atomically and journals the write. The
// previous state is left untouched if any step fails.
func (s *Store) Save(state DesiredState) (err error) {
	sealed, err := Seal(state)
	if err != nil {
		return fmt.Errorf("sealing desired state: %w", err)
	}

	encoded, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding desired state: %w", err)
	}
	encoded = append(encoded, '\n')

	s.mutex.Lock()
	defer s.mutex.Unlock()

	err = os.MkdirAll(s.directory, stateDirectoryMode)
	if err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}

	err = writeFileAtomic(s.statePath, encoded)
	if err != nil {
		return fmt.Errorf("writing desired state: %w", err)
	}

	err = s.journal.Append(JournalEntry{
		At:       sealed.UpdatedAt,
		Action:   "save",
		Checksum: sealed.Checksum,
	})
	if err != nil {
		return fmt.Errorf("journaling desired state: %w", err)
	}
	return nil
}

func (s *Store) clock() time.Time {
	if s.now == nil {
		return time.Now().UTC()
	}
	return s.now().UTC()
}
