package toolplane

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteLevel records the action level beside the identity, validated first so
// an Advisor cannot leave the node with a word ReadLevel refuses.
func WriteLevel(dir, level string) error {
	l, err := ParseLevel(level)
	if err != nil {
		return err
	}
	return writeDial(filepath.Join(dir, LevelFileName), l.String())
}

// WriteConsent records the consent setting beside the identity.
func WriteConsent(dir, c string) error {
	v, err := ParseConsent(c)
	if err != nil {
		return err
	}
	return writeDial(filepath.Join(dir, ConsentFileName), v.String())
}

// writeDial: mode 0644 — readable by the CLI, writable by root only, which
// is what ReadLevel/ReadConsent insist on.
func writeDial(path, word string) error {
	if err := os.WriteFile(path, []byte(word+"\n"), 0o644); err != nil {
		return fmt.Errorf("toolplane: write %s: %w", path, err)
	}
	return os.Chmod(path, 0o644)
}
