// Package toolcatalog publishes what the executor's allowlist contains, so the
// SaaS can check itself against it instead of against a copy.
//
// It exists because the two repositories previously kept the inventory twice:
// the allowlist in internal/toolplane, and a hand-typed map of the same names
// in the SaaS's test. Two lists that must agree are one list and one liability,
// and the failure it invites has happened here before — cube-ai-advisor#121 and
// cube-advisor-agent#24 were both green while disagreeing about a frame,
// because each was tested against its own idea of the contract.
//
// This is a catalogue, not a control. Nothing here enforces anything: the
// allowlist enforces, on the cluster, and a SaaS that read this and decided to
// ignore it would change nothing about what runs. What it removes is the
// possibility of the two sides believing different things without a test
// noticing.
//
// Impact is published as its word rather than the Go constant so a version skew
// between the modules cannot silently renumber a class: the words are the ones
// Impact.String produces on both sides, and an unrecognised word is a mismatch
// a reader can see.
package toolcatalog

import (
	"sort"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
)

// Entry is one tool the executor serves, as the SaaS needs to know it.
type Entry struct {
	// Name is what the SaaS asks for, matched exactly by the executor.
	Name string
	// Impact is the class as Impact.String names it: read, scratch, operate
	// or internal.
	Impact string
	// Probe reports whether this entry is served only by an agent built with
	// a probe runner. The SaaS registers those under its own option, so a
	// comparison that ignored the distinction would demand the two lists
	// match when they legitimately do not.
	Probe bool
	// Unlisted reports whether this entry is one the SaaS calls on its own
	// account rather than offering to the model — describing the instance
	// profile for an approval prompt, for instance.
	//
	// Published for the same reason Probe is. A SaaS comparing its tool list
	// against this catalogue has to know which absences are deliberate, and
	// the alternative is a list of exceptions typed out over there: a
	// hand-kept copy of a fact this side already knows, which is the shape of
	// failure this package exists to remove.
	Unlisted bool

	// Reads is the sorted set of catalogue keys this entry accepts, empty for
	// a tool that is not a catalogue read.
	//
	// Published for the same reason the names are: the SaaS has to tell the
	// model which reads exist, and a list of keys typed out over there is a
	// copy of this one. The keys remain advice on that side — the executor's
	// map is the enforcement, and a stale SaaS must not veto a key a newer
	// executor serves.
	Reads []string
}

// Entries returns every tool the executor can serve, sorted by name.
//
// Both halves of the allowlist are included — the always-registered tools and
// the probe controls — because "can this executor ever serve this name" is the
// question the SaaS is asking. Whether a given agent does depends on its build
// and on its cluster's action level, and neither is knowable from here.
func Entries() []Entry {
	out := make([]Entry, 0, len(toolplane.Allowlist)+len(toolplane.ProbeControls))
	for _, t := range toolplane.Allowlist {
		out = append(out, Entry{
			Name: t.Name, Impact: t.Impact.String(),
			Unlisted: t.Unlisted, Reads: readsOf(t),
		})
	}
	for _, t := range toolplane.ProbeControls {
		out = append(out, Entry{Name: t.Name, Impact: t.Impact.String(), Probe: true})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// readsOf returns a catalogue tool's keys, sorted. Sorted because a map's
// order is not one, and a published list whose order changes between calls
// makes a comparison on the other side flap for no reason.
func readsOf(t toolplane.Tool) []string {
	if len(t.Catalog) == 0 {
		return nil
	}
	keys := make([]string, 0, len(t.Catalog))
	for k := range t.Catalog {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
