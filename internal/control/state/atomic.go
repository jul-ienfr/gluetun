package state

import (
	"fmt"
	"os"
	"path/filepath"
)

const stateFileMode = 0o600

func writeFileAtomic(path string, data []byte) (err error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}

	_, err = temporary.Write(data)
	if err != nil {
		cleanup()
		return fmt.Errorf("writing temporary file: %w", err)
	}

	err = temporary.Chmod(stateFileMode)
	if err != nil {
		cleanup()
		return fmt.Errorf("setting temporary file mode: %w", err)
	}

	err = temporary.Sync()
	if err != nil {
		cleanup()
		return fmt.Errorf("syncing temporary file: %w", err)
	}

	err = temporary.Close()
	if err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("closing temporary file: %w", err)
	}

	err = os.Rename(temporaryPath, path)
	if err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("renaming temporary file: %w", err)
	}

	syncDirectory(directory)
	return nil
}

// syncDirectory flushes a directory entry when the platform supports it.
func syncDirectory(directory string) {
	file, err := os.Open(directory)
	if err != nil {
		return
	}
	defer file.Close()
	_ = file.Sync()
}
