package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ConsoleOriginsFileName is where RecordConsoleOrigins writes, inside the
// identity directory. The node's own configuration management reads it; the
// agent never acts on it.
const ConsoleOriginsFileName = "console-origins"

// RecordConsoleOrigins writes the origins the SaaS reported, one
// "<target> <origin>" per line.
//
// Sorted and compared before writing: this runs on every connect and the node
// watches the file, so an unchanged set must not wake the watcher.
//
// An empty map removes the file. Reporting no origins is a statement, and
// leaving the last set behind would keep a node trusting a withdrawn one.
func RecordConsoleOrigins(dir string, origins map[string]string) error {
	path := filepath.Join(dir, ConsoleOriginsFileName)

	if len(origins) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("identity: remove console origins: %w", err)
		}
		return nil
	}

	targets := make([]string, 0, len(origins))
	for t := range origins {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	var b strings.Builder
	for _, t := range targets {
		// The node reads this line by line, so a newline would forge an entry.
		// Refused whole rather than written half-trusted.
		if strings.ContainsAny(t, " \t\r\n") || strings.ContainsAny(origins[t], " \t\r\n") {
			return fmt.Errorf("identity: console origin for %q contains whitespace", t)
		}
		fmt.Fprintf(&b, "%s %s\n", t, origins[t])
	}
	content := b.String()

	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("identity: create dir: %w", err)
	}
	// Temp file then rename: the node may read this at any moment.
	tmp, err := os.CreateTemp(dir, ConsoleOriginsFileName+".*")
	if err != nil {
		return fmt.Errorf("identity: temp console origins: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("identity: write console origins: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("identity: close console origins: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("identity: chmod console origins: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("identity: install console origins: %w", err)
	}
	return nil
}
