package events

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

// Default retention of the persisted event log.
const (
	DefaultLogMaxBytes int64 = 1 << 20
	DefaultLogMaxFiles       = 3
)

const logFileName = "events.jsonl"

// FileLog persists events as an append-only JSONL log with size-bounded
// rotation. Each record carries a checksum of its event so a truncated or
// corrupted trailing write is ignored on load instead of poisoning the replay.
type FileLog struct {
	directory string
	maxBytes  int64
	maxFiles  int
	mutex     sync.Mutex
}

// NewFileLog creates an event log rooted at a directory.
func NewFileLog(directory string, maxBytes int64, maxFiles int) *FileLog {
	if directory == "" {
		panic("event log directory is empty")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultLogMaxBytes
	}
	if maxFiles <= 0 {
		maxFiles = DefaultLogMaxFiles
	}
	return &FileLog{
		directory: directory,
		maxBytes:  maxBytes,
		maxFiles:  maxFiles,
	}
}

type logRecord struct {
	Event    Event  `json:"event"`
	Checksum string `json:"checksum"`
}

// Append durably appends one event and rotates the log once it reaches its
// size budget.
func (l *FileLog) Append(event Event) error {
	encodedEvent, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encoding event: %w", err)
	}
	sum := sha256.Sum256(encodedEvent)

	encodedRecord, err := json.Marshal(logRecord{
		Event:    event,
		Checksum: hex.EncodeToString(sum[:]),
	})
	if err != nil {
		return fmt.Errorf("encoding event record: %w", err)
	}
	encodedRecord = append(encodedRecord, '\n')

	l.mutex.Lock()
	defer l.mutex.Unlock()

	err = os.MkdirAll(l.directory, 0o700)
	if err != nil {
		return fmt.Errorf("creating event log directory: %w", err)
	}

	err = l.rotateIfNeeded(int64(len(encodedRecord)))
	if err != nil {
		return err
	}

	path := filepath.Join(l.directory, logFileName)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening event log: %w", err)
	}
	_, writeErr := file.Write(encodedRecord)
	syncErr := file.Sync()
	closeErr := file.Close()
	err = errors.Join(writeErr, syncErr, closeErr)
	if err != nil {
		return fmt.Errorf("writing event log: %w", err)
	}
	return nil
}

func (l *FileLog) rotateIfNeeded(incoming int64) error {
	path := filepath.Join(l.directory, logFileName)
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking event log size: %w", err)
	}
	if info.Size() == 0 || info.Size()+incoming <= l.maxBytes {
		return nil
	}
	return l.rotate()
}

func (l *FileLog) rotate() error {
	if l.maxFiles == 1 {
		err := os.Remove(filepath.Join(l.directory, logFileName))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("removing event log: %w", err)
		}
		return nil
	}

	for index := l.maxFiles - 1; index >= 1; index-- {
		path := l.pathAt(index)
		err := os.Remove(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("removing rotated event log: %w", err)
		}
	}

	for index := l.maxFiles - 2; index >= 1; index-- {
		err := os.Rename(l.pathAt(index), l.pathAt(index+1))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("rotating event log: %w", err)
		}
	}

	err := os.Rename(filepath.Join(l.directory, logFileName), l.pathAt(1))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("rotating event log: %w", err)
	}
	return nil
}

func (l *FileLog) pathAt(index int) string {
	if index == 0 {
		return filepath.Join(l.directory, logFileName)
	}
	return filepath.Join(l.directory,
		fmt.Sprintf("events.%d.jsonl", index))
}

// Load returns the last events of the log, oldest first, and the highest
// sequence number found. A limit of zero or less returns every retained event.
func (l *FileLog) Load(limit int) (events []Event, lastSeq uint64, err error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	for index := l.maxFiles - 1; index >= 0; index-- {
		path := l.pathAt(index)
		fileEvents, readErr := readLogFile(path)
		if readErr != nil {
			return nil, 0, readErr
		}
		for _, event := range fileEvents {
			if event.Seq == 0 || event.Seq <= lastSeq {
				continue
			}
			lastSeq = event.Seq
			events = append(events, event)
		}
	}

	if limit > 0 && len(events) > limit {
		events = slices.Clone(events[len(events)-limit:])
	}
	return events, lastSeq, nil
}

func readLogFile(path string) (events []Event, err error) {
	encoded, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading event log: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(encoded))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var record logRecord
		err = json.Unmarshal(line, &record)
		if err != nil {
			continue
		}
		if !record.valid() {
			continue
		}
		events = append(events, record.Event)
	}
	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("scanning event log: %w", err)
	}
	return events, nil
}

func (r logRecord) valid() bool {
	if r.Checksum == "" || r.Event.Seq == 0 {
		return false
	}
	encoded, err := json.Marshal(r.Event)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]) == r.Checksum
}
