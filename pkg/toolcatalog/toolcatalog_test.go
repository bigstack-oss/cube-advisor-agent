package toolcatalog

import (
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
)

// The catalogue's whole value is that it cannot disagree with the allowlist, so
// the test asserts the derivation rather than the contents.
func TestEveryAllowlistEntryIsPublished(t *testing.T) {
	got := map[string]Entry{}
	for _, e := range Entries() {
		got[e.Name] = e
	}
	if len(got) != len(toolplane.Allowlist)+len(toolplane.ProbeControls) {
		t.Fatalf("catalogue has %d entries, allowlist has %d",
			len(got), len(toolplane.Allowlist)+len(toolplane.ProbeControls))
	}
	for _, tool := range toolplane.Allowlist {
		e, ok := got[tool.Name]
		if !ok {
			t.Errorf("%s is in the allowlist but not the catalogue", tool.Name)
			continue
		}
		if e.Impact != tool.Impact.String() {
			t.Errorf("%s: catalogue says %s, allowlist says %s", tool.Name, e.Impact, tool.Impact)
		}
		if e.Probe {
			t.Errorf("%s is not a probe control but is published as one", tool.Name)
		}
	}
	for _, tool := range toolplane.ProbeControls {
		if e := got[tool.Name]; !e.Probe {
			t.Errorf("%s is a probe control but is not published as one", tool.Name)
		}
	}
}

// Sorted, so a caller comparing two lists is not comparing map iteration order.
func TestEntriesAreSorted(t *testing.T) {
	entries := Entries()
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Name > entries[i].Name {
			t.Fatalf("not sorted at %d: %v", i, entries)
		}
	}
}

// The words are the contract: a class renamed on one side and not the other is
// a mismatch the SaaS must be able to see, so an impact must never publish as
// the fallback form.
func TestNoEntryPublishesAnUnnamedClass(t *testing.T) {
	known := map[string]bool{"read": true, "scratch": true, "operate": true, "internal": true}
	for _, e := range Entries() {
		if !known[e.Impact] {
			t.Errorf("%s publishes impact %q, which is not a named class", e.Name, e.Impact)
		}
	}
}
