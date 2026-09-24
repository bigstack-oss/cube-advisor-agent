package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CurrentReleaseFileName holds the agent version the SaaS reported as current
// at the last connect, or is absent when it reported none.
const CurrentReleaseFileName = "current-release"

// RecordCurrentRelease writes the SaaS's current agent version beside the
// identity, for the node's own tooling (advisor status, cluster check,
// advisor upgrade) to compare with what is installed. Written only when it
// changes, so a watcher sees real changes and not every reconnect.
func RecordCurrentRelease(dir, version string) error {
	path := filepath.Join(dir, CurrentReleaseFileName)
	version = strings.TrimSpace(version)
	if version == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("identity: remove current release: %w", err)
		}
		return nil
	}
	// One token, no whitespace: the node reads it into a shell variable.
	if strings.ContainsAny(version, " \t\r\n/") {
		return fmt.Errorf("identity: current release %q is not a version", version)
	}
	if cur, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(cur)) == version {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(version+"\n"), 0o644); err != nil {
		return fmt.Errorf("identity: write current release: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("identity: write current release: %w", err)
	}
	return nil
}
