package identity

import (
	"fmt"
	"os"
	"path/filepath"
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
