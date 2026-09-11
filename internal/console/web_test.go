package console_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/console"
)

func writeAllowlist(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "web-targets.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The allowlist is the boundary. A name it does not contain is refused, and
// the refusal names no address — the caller learns nothing about the node.
func TestTheAllowlistRefusesWhatItDoesNotName(t *testing.T) {
	p := writeAllowlist(t, `{"dashboard":"127.0.0.1:8080","cmp-portal":"10.32.1.101:443"}`)
	a, err := console.LoadWebAllowlist(p)
	if err != nil {
		t.Fatal(err)
	}

	got, err := a.Resolve("dashboard")
	if err != nil || got != "127.0.0.1:8080" {
		t.Errorf("dashboard = %q, %v", got, err)
	}
	if _, err := a.Resolve("etcd"); !errors.Is(err, console.ErrNotAllowed) {
		t.Errorf("unlisted name: %v, want ErrNotAllowed", err)
	}
	// An address is not a name. Asking for one directly is refused too.
	if _, err := a.Resolve("10.32.1.101:443"); !errors.Is(err, console.ErrNotAllowed) {
		t.Errorf("address as name: %v, want ErrNotAllowed", err)
	}
}

// A malformed entry must fail at load, not at the first operator who uses it.
func TestAnEntryWithoutAPortIsRejectedAtLoad(t *testing.T) {
	p := writeAllowlist(t, `{"dashboard":"127.0.0.1"}`)
	if _, err := console.LoadWebAllowlist(p); err == nil {
		t.Fatal("a host with no port loaded without complaint")
	}
}

// No file means no web targets, which must be a clean empty allowlist rather
// than an error that stops the agent serving SSH.
func TestAMissingAllowlistIsEmptyNotFatal(t *testing.T) {
	a, err := console.LoadWebAllowlist(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("missing file: %v", err)
	}
	if len(a) != 0 {
		t.Errorf("missing file produced %d entries", len(a))
	}
}
