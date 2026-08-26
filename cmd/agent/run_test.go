package main

import (
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
)

// resolveServerAddr's fallback precedence is the whole point of issue #19:
// run should need no operator argument once a cluster is enrolled, but an
// operator who does pass -server must still be obeyed.

func TestResolveServerAddrPrefersAnExplicitServer(t *testing.T) {
	dir := t.TempDir()
	if err := identity.SaveServer(dir, "persisted.example:8443"); err != nil {
		t.Fatal(err)
	}
	got, err := resolveServerAddr("explicit.example:9443", dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "explicit.example:9443" {
		t.Errorf("resolveServerAddr = %q, want the explicit -server to win over the persisted address", got)
	}
}

func TestResolveServerAddrFallsBackToThePersistedAddress(t *testing.T) {
	dir := t.TempDir()
	if err := identity.SaveServer(dir, "persisted.example:8443"); err != nil {
		t.Fatal(err)
	}
	got, err := resolveServerAddr("", dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "persisted.example:8443" {
		t.Errorf("resolveServerAddr = %q, want the persisted address", got)
	}
}

// Neither an explicit -server nor a persisted one (an unenrolled node, or one
// enrolled before this feature existed) must fail with a message telling the
// operator exactly what to do — not a confusing dial against an empty address.
func TestResolveServerAddrFailsClearlyWithNeither(t *testing.T) {
	_, err := resolveServerAddr("", t.TempDir())
	if err == nil {
		t.Fatal("no -server and nothing persisted was accepted")
	}
	if !strings.Contains(err.Error(), "enrol") || !strings.Contains(err.Error(), "-server") {
		t.Errorf("error should tell the operator to enrol or pass -server: %v", err)
	}
}
