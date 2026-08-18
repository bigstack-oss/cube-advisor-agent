package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The token-reading rules are worth testing directly: they are the difference
// between a pairing token that appears in ps and one that does not, and an
// installer picks the path.

func TestReadTokenSources(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readToken("flag-token", "", false)
	if err != nil || got != "flag-token" {
		t.Errorf("flag: %q, %v", got, err)
	}

	got, err = readToken("", file, false)
	if err != nil || got != "file-token" {
		t.Errorf("file: %q, %v — surrounding whitespace should be trimmed", got, err)
	}
}

// Exactly one source, so a caller cannot half-supply two and get a surprise.
func TestReadTokenRequiresExactlyOneSource(t *testing.T) {
	if _, err := readToken("", "", false); err == nil {
		t.Error("no token source was accepted")
	}
	if _, err := readToken("a", "b", false); err == nil {
		t.Error("two token sources were accepted")
	}
}

func TestReadTokenRejectsAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken("", empty, false); err == nil {
		t.Error("an empty token file was accepted")
	}
	if _, err := readToken("", filepath.Join(dir, "absent"), false); err == nil {
		t.Error("a missing token file was accepted")
	}
}

// Enrolling twice must not be a side effect of running the command again.
func TestEnrollRefusesWhenAlreadyEnrolled(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"agent.key", "agent.crt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code := enrollCmd([]string{"-server", "https://example", "-cluster", "c", "-dir", dir, "-token", "t"})
	if code != exitAlready {
		t.Errorf("exit = %d, want %d (already enrolled)", code, exitAlready)
	}
}

func TestEnrollRequiresAServer(t *testing.T) {
	if code := enrollCmd([]string{"-token", "t"}); code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
}

func TestStatusReportsNotEnrolled(t *testing.T) {
	if code := statusCmd([]string{"-dir", t.TempDir()}); code != exitAlready {
		t.Errorf("exit = %d, want %d", code, exitAlready)
	}
}

// A present-but-unloadable identity is a different problem from an absent one —
// usually the key's permissions were changed — and an operator needs to be able
// to tell them apart.
func TestStatusDistinguishesAnUnusableIdentity(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"agent.key", "agent.crt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not pem"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code := statusCmd([]string{"-dir", dir}); code != exitFailed {
		t.Errorf("exit = %d, want %d (present but unusable)", code, exitFailed)
	}
}

func TestExitCodesAreDistinct(t *testing.T) {
	seen := map[int]string{}
	for name, code := range map[string]int{
		"ok": exitOK, "usage": exitUsage, "already": exitAlready,
		"tokenRefused": exitTokenRefused, "unreachable": exitUnreachable, "failed": exitFailed,
	} {
		if prev, dup := seen[code]; dup {
			t.Errorf("%s and %s share exit code %d; an installer cannot branch on them", name, prev, code)
		}
		seen[code] = name
	}
}

func TestUsageMentionsEverySubcommand(t *testing.T) {
	// Cheap guard against adding a subcommand nobody can discover.
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	usage()
	w.Close()
	os.Stderr = old
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	for _, cmd := range []string{"enroll", "status", "version"} {
		if !strings.Contains(out, cmd) {
			t.Errorf("usage does not mention %q", cmd)
		}
	}
}
