package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentReleaseIsRecordedOnlyWhenItChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, CurrentReleaseFileName)

	if err := RecordCurrentRelease(dir, "0.4.10"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "0.4.10\n" {
		t.Fatalf("file = %q, %v", b, err)
	}
	first, _ := os.Stat(path)

	// Same version again: untouched, so a watcher does not fire on every connect.
	if err := RecordCurrentRelease(dir, "0.4.10"); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.Stat(path); !again.ModTime().Equal(first.ModTime()) {
		t.Error("an unchanged version rewrote the file")
	}

	if err := RecordCurrentRelease(dir, "0.4.11"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "0.4.11\n" {
		t.Errorf("file = %q after a newer release", b)
	}

	// A SaaS that reports nothing takes the claim back rather than leaving a stale one.
	if err := RecordCurrentRelease(dir, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("an empty report left the old file behind")
	}
}

func TestCurrentReleaseRefusesAnythingButAVersion(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"0.4.10 rc", "../x", "a\nb"} {
		if err := RecordCurrentRelease(dir, bad); err == nil {
			t.Errorf("%q was recorded", bad)
		}
	}
}
