package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
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

// The Hello names no served level or consent, whatever the node's old files
// say. An Advisor reads the empty fields as "nothing reported" and keeps its
// own record, so an older one does not narrow to the lowest level.
func TestHelloReportsNoServedLevelOrConsent(t *testing.T) {
	h := helloFor("acme-prod-01", "SHA256:abc")
	if h.ServedLevel != "" || h.ServedConsent != "" {
		t.Errorf("hello served = %q/%q, want neither reported", h.ServedLevel, h.ServedConsent)
	}
	if h.ClusterID != "acme-prod-01" || h.Fingerprint != "SHA256:abc" || h.ProtocolVersion != tunnelproto.Version {
		t.Errorf("hello lost its identity fields: %+v", h)
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "served") {
		t.Errorf("the wire frame still carries a served field: %s", b)
	}
}

func TestHelloCarriesTheCapabilities(t *testing.T) {
	defer func() { capabilities = nil }()
	if got := helloFor("c", "f").Capabilities; len(got) != 0 {
		t.Fatalf("Capabilities = %v before any are set", got)
	}
	capabilities = []string{tunnelproto.ConsoleRelay}
	if got := helloFor("c", "f").Capabilities; len(got) != 1 || got[0] != "console-relay" {
		t.Fatalf("Capabilities = %v, want [console-relay]", got)
	}
}
