package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PeersPendingFileName marks a fresh enrolment whose peers this node has not
// yet tried to enrol. Written by enroll, consumed on the first admitted connect.
const PeersPendingFileName = "peers-pending"

// MarkPeersPending records that this node's peers still need enrolling.
func MarkPeersPending(dir string) error {
	if err := os.WriteFile(filepath.Join(dir, PeersPendingFileName), nil, 0o600); err != nil {
		return fmt.Errorf("identity: mark peers pending: %w", err)
	}
	return nil
}

// TakePeersPending reports whether the mark was set, and clears it.
func TakePeersPending(dir string) bool {
	return os.Remove(filepath.Join(dir, PeersPendingFileName)) == nil
}

// PeersVersionFileName holds the CubeCOS version (/etc/version) this node
// last ran the peer fan-out on, or recorded on first sight.
const PeersVersionFileName = "peers-version"

// PeersVersion returns the recorded CubeCOS version; ok is false when none is.
func PeersVersion(dir string) (v string, ok bool) {
	b, err := os.ReadFile(filepath.Join(dir, PeersVersionFileName))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// RecordPeersVersion writes the CubeCOS version the fan-out last ran on.
func RecordPeersVersion(dir, v string) error {
	path := filepath.Join(dir, PeersVersionFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.TrimSpace(v)+"\n"), 0o600); err != nil {
		return fmt.Errorf("identity: record peers version: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("identity: record peers version: %w", err)
	}
	return nil
}
