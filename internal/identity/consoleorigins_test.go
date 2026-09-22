package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func readOrigins(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ConsoleOriginsFileName))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

func TestConsoleOriginsAreWrittenSortedSoAWatcherSeesOnlyRealChanges(t *testing.T) {
	dir := t.TempDir()
	in := map[string]string{
		"cube-cos-skyline": "https://10.32.1.61:9999",
		"cube-cos":         "https://10.32.1.61",
		"cube-cmp":         "https://10.32.1.60",
	}
	if err := RecordConsoleOrigins(dir, in); err != nil {
		t.Fatalf("record: %v", err)
	}
	want := "cube-cmp https://10.32.1.60\n" +
		"cube-cos https://10.32.1.61\n" +
		"cube-cos-skyline https://10.32.1.61:9999\n"
	if got := readOrigins(t, dir); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// This runs on every reconnect and the node watches the file. Rewriting
// identical content would wake the watcher — and restart keystone — every time
// a network flap reconnected the tunnel.
func TestRewritingTheSameOriginsDoesNotTouchTheFile(t *testing.T) {
	dir := t.TempDir()
	in := map[string]string{"cube-cos-skyline": "https://10.32.1.61:9999"}
	if err := RecordConsoleOrigins(dir, in); err != nil {
		t.Fatalf("first: %v", err)
	}
	path := filepath.Join(dir, ConsoleOriginsFileName)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// A different map iteration order must still compare equal.
	if err := RecordConsoleOrigins(dir, map[string]string{"cube-cos-skyline": "https://10.32.1.61:9999"}); err != nil {
		t.Fatalf("second: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("an unchanged set rewrote the file")
	}
}

// The SaaS reporting nothing is a statement, not an absence of news: the
// console is off, or serves nothing this cluster is reachable on. Leaving the
// last set behind would keep the node trusting a withdrawn origin.
func TestNoOriginsWithdrawsTheRecord(t *testing.T) {
	dir := t.TempDir()
	if err := RecordConsoleOrigins(dir, map[string]string{"cube-cos": "https://10.32.1.61"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := RecordConsoleOrigins(dir, nil); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ConsoleOriginsFileName)); !os.IsNotExist(err) {
		t.Errorf("record outlived the withdrawal: %v", err)
	}
}

func TestWithdrawingWhenThereWasNoRecordIsNotAnError(t *testing.T) {
	if err := RecordConsoleOrigins(t.TempDir(), nil); err != nil {
		t.Errorf("withdraw on empty dir: %v", err)
	}
}

// The node reads this file line by line. A value carrying a newline would
// forge an entry it never sent, so the whole record is refused rather than
// written half-trusted.
func TestWhitespaceInARecordIsRefusedOutright(t *testing.T) {
	for name, in := range map[string]map[string]string{
		"newline in origin": {"cube-cos": "https://10.32.1.61\ncube-cos-skyline https://evil.test"},
		"space in origin":   {"cube-cos": "https://10.32.1.61 evil.test"},
		"newline in target": {"cube-cos\nx": "https://10.32.1.61"},
		"tab in origin":     {"cube-cos": "https://10.32.1.61\tx"},
	} {
		dir := t.TempDir()
		if err := RecordConsoleOrigins(dir, in); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(filepath.Join(dir, ConsoleOriginsFileName)); !os.IsNotExist(err) {
			t.Errorf("%s: wrote a file anyway", name)
		}
	}
}

func TestTheRecordIsReadableByTheNodesConfigTooling(t *testing.T) {
	dir := t.TempDir()
	if err := RecordConsoleOrigins(dir, map[string]string{"cube-cos": "https://10.32.1.61"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, ConsoleOriginsFileName))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
	}
}

// A failed write must leave nothing behind for the node to read.
func TestAFailedWriteLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	if err := RecordConsoleOrigins(dir, map[string]string{"a b": "https://x"}); err == nil {
		t.Fatal("accepted a target with a space")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(ents) != 0 {
		t.Errorf("left %d file(s) behind", len(ents))
	}
}
