package main

import (
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
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

// #232: the Hello names what this node serves, so the SaaS can stop offering
// tools its mirror admits and the node refuses.
func TestHelloReportsTheServedLevelAndConsent(t *testing.T) {
	reg, err := toolplane.New(nil, nopAuditor{},
		toolplane.WithLevel(toolplane.LevelOperate),
		toolplane.WithConsent(toolplane.ConsentNever))
	if err != nil {
		t.Fatal(err)
	}
	h := helloFor("acme-prod-01", "SHA256:abc", reg)
	if h.ServedLevel != "operate" || h.ServedConsent != "never" {
		t.Errorf("hello served = %q/%q, want operate/never", h.ServedLevel, h.ServedConsent)
	}
	if h.ClusterID != "acme-prod-01" || h.Fingerprint != "SHA256:abc" || h.ProtocolVersion != tunnelproto.Version {
		t.Errorf("hello lost its identity fields: %+v", h)
	}
}

func TestHelloReportsObserveForANodeWithNoLevelFile(t *testing.T) {
	reg, err := toolplane.New(nil, nopAuditor{}, toolplane.WithLevel(mustReadLevel(t, t.TempDir())))
	if err != nil {
		t.Fatal(err)
	}
	if got := helloFor("c", "f", reg).ServedLevel; got != "observe" {
		t.Errorf("served level = %q, want observe", got)
	}
}

func mustReadLevel(t *testing.T, dir string) toolplane.Level {
	t.Helper()
	l, err := toolplane.ReadLevel(dir)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

type nopAuditor struct{}

func (nopAuditor) RecordToolCall(toolplane.ToolCall) {}
