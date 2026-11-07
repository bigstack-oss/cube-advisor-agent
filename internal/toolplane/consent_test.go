package toolplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ADR 0011's "unset means always": the three ways a cluster can say nothing all
// answer the cautious value, and none of them is an error.
func TestAnUnsaidConsentAsksForEverything(t *testing.T) {
	for _, c := range []struct {
		name  string
		write func(dir string)
	}{
		{"no file", func(string) {}},
		{"empty file", func(dir string) { writeConsent(t, dir, "", 0o644) }},
		{"whitespace", func(dir string) { writeConsent(t, dir, "  \n\t\n", 0o644) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			c.write(dir)
			got, err := ReadConsent(dir)
			if err != nil {
				t.Fatalf("ReadConsent = %v, want no error for %s", err, c.name)
			}
			if got != ConsentAlways {
				t.Errorf("ReadConsent = %s, want always", got)
			}
		})
	}
}

// A word nobody in this build recognises is the failure the file exists to
// prevent: an operator who wrote "none" meaning "never" has a cluster asking
// about everything while they believe it asks about nothing. Loud, and still
// falling closed.
func TestAnUnreadableConsentIsLoudAndStillFallsClosed(t *testing.T) {
	dir := t.TempDir()
	writeConsent(t, dir, "none\n", 0o644)

	got, err := ReadConsent(dir)
	if err == nil {
		t.Fatal("ReadConsent accepted a word that is not a consent setting")
	}
	if got != ConsentAlways {
		t.Errorf("ReadConsent = %s alongside its error, want always", got)
	}
	if !strings.Contains(err.Error(), "none") {
		t.Errorf("error %q does not quote what the operator wrote", err)
	}
	if !strings.Contains(err.Error(), ConsentFileName) {
		t.Errorf("error %q does not name the file to correct", err)
	}
}

// Whoever can write this file can stop the cluster asking a person before it
// acts, so a file others may write is not a control.
func TestAConsentFileOthersCanWriteIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeConsent(t, dir, "never\n", 0o666)

	got, err := ReadConsent(dir)
	if err == nil {
		t.Fatal("ReadConsent accepted a world-writable consent file")
	}
	if got != ConsentAlways {
		t.Errorf("ReadConsent = %s alongside its error, want always", got)
	}
	if !strings.Contains(err.Error(), "asking a person") {
		t.Errorf("error %q does not say what the mode would let someone do", err)
	}
}

// Readability is deliberately unconstrained: a policy statement its customer
// should be able to read without root, and it holds no secret.
func TestAReadableConsentFileIsFine(t *testing.T) {
	dir := t.TempDir()
	writeConsent(t, dir, "destructive\n", 0o644)

	got, err := ReadConsent(dir)
	if err != nil {
		t.Fatalf("ReadConsent = %v, want a world-readable file to be accepted", err)
	}
	if got != ConsentDestructive {
		t.Errorf("ReadConsent = %s, want destructive", got)
	}
}

func writeConsent(t *testing.T, dir, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, ConsentFileName)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to the process umask, so a mode the test means to
	// be group- or world-writable has to be set explicitly.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
