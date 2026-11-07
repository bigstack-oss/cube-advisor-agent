package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
)

// These tests call configure — the function run calls — against a temporary
// directory. That is the whole point of them.
//
// Two layers, because exhaustiveness alone is not enough. The first catches a
// setting nothing loads; the second catches a setting loaded into nothing,
// which would pass the first.

// effect is one declared setting's observable consequence, written here rather
// than derived from settings so that the two must agree with each other.
type effect struct {
	name    string
	file    string
	content string
	mode    os.FileMode
	// observe reads back the part of the registry this setting controls.
	observe func(*toolplane.Registry) string
}

func effects(t *testing.T) []effect {
	t.Helper()
	return []effect{
		{
			name:    "action level",
			file:    toolplane.LevelFileName,
			content: "operate\n",
			// Readable by anyone, writable by nobody else: the level is a
			// policy statement, and ReadLevel refuses a file others may write.
			mode:    0o644,
			observe: func(r *toolplane.Registry) string { return r.Level().String() },
		},
		{
			name:    "consent",
			file:    toolplane.ConsentFileName,
			content: "never\n",
			// The level's rule, for a sharper reason: whoever may write this
			// file can stop the cluster asking a person before it acts.
			mode:    0o644,
			observe: func(r *toolplane.Registry) string { return r.Consent().String() },
		},
	}
}

// A setting configure loads but nothing asserts, or asserts but configure does
// not load, is the failure this catches. Adding a setting to the list without
// an effect case fails here rather than shipping unobserved.
func TestEverySettingIsDeclaredAndAsserted(t *testing.T) {
	declared := map[string]string{}
	for _, s := range settings {
		if _, dup := declared[s.name]; dup {
			t.Errorf("setting %q is declared twice", s.name)
		}
		if s.load == nil {
			t.Errorf("setting %q loads nothing", s.name)
		}
		declared[s.name] = s.file
	}

	asserted := map[string]string{}
	for _, e := range effects(t) {
		asserted[e.name] = e.file
	}

	for name, file := range declared {
		want, ok := asserted[name]
		if !ok {
			t.Errorf("configure loads setting %q but no test asserts it has any effect", name)
			continue
		}
		if want != file {
			t.Errorf("setting %q reads %q, the test writes %q", name, file, want)
		}
	}
	for name, file := range asserted {
		if _, ok := declared[name]; !ok {
			t.Errorf("setting %q has an effect test but configure does not load it: an operator writing %s would change nothing",
				name, file)
		}
	}
}

// Each declared setting must reach the registry through configure. A list
// entry wired to nothing passes the exhaustiveness check above and fails here.
func TestEverySettingReachesTheRegistryThroughConfigure(t *testing.T) {
	for _, e := range effects(t) {
		t.Run(e.name, func(t *testing.T) {
			unset := e.observe(configureIn(t, t.TempDir()))

			dir := t.TempDir()
			writeSetting(t, dir, e)
			set := e.observe(configureIn(t, dir))

			if set == unset {
				t.Fatalf("writing %s changed nothing: %s reads %q with and without it — the setting is declared but wired to nothing",
					e.file, e.name, set)
			}
		})
	}
}

// A setting an operator wrote and this agent cannot honour is marked broken,
// and the agent still configures: a malformed credential must not take
// diagnosis away at the moment it is needed.
func TestABrokenSettingIsMarkedAndStillConfigures(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, toolplane.LevelFileName), []byte("operator\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	reg, states, err := configure(dir, toolplane.Tools, discardAuditor())
	if err != nil {
		t.Fatalf("configure refused to build a registry over a malformed setting: %v", err)
	}
	if reg.Level() != toolplane.DefaultLevel {
		t.Errorf("Level() = %s over a malformed file, want %s", reg.Level(), toolplane.DefaultLevel)
	}

	var broken []string
	for _, st := range states {
		if st.line == "" {
			t.Error("a setting reported no startup line")
		}
		if st.broken {
			broken = append(broken, st.line)
		}
	}
	if len(broken) != 1 {
		t.Fatalf("broken settings = %d, want exactly the malformed action level: %v", len(broken), broken)
	}
	if !strings.Contains(broken[0], "operator") {
		t.Errorf("the line should quote what the operator wrote, so they can see their own typo: %q", broken[0])
	}
}

// Nothing configured is the ordinary state of a cluster that has not opted in:
// every setting still reports, and the agent serves reads.
func TestAnUnconfiguredDirectoryReportsEverySettingAndServesReads(t *testing.T) {
	reg, states, err := configure(t.TempDir(), toolplane.Tools, discardAuditor())
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != len(settings) {
		t.Fatalf("states = %d, want one per declared setting (%d)", len(states), len(settings))
	}
	for i, st := range states {
		if st.line == "" {
			t.Errorf("setting %q reported no startup line", settings[i].name)
		}
		if st.broken {
			t.Errorf("setting %q is broken when nothing is configured: %s", settings[i].name, st.line)
		}
	}
	if reg.Level() != toolplane.DefaultLevel {
		t.Errorf("Level() = %s with nothing configured, want %s", reg.Level(), toolplane.DefaultLevel)
	}
	if len(reg.Names()) == 0 {
		t.Error("an unconfigured agent serves no tools; it should still serve its reads")
	}
}

func configureIn(t *testing.T, dir string) *toolplane.Registry {
	t.Helper()
	reg, _, err := configure(dir, toolplane.Tools, discardAuditor())
	if err != nil {
		t.Fatalf("configure(%s): %v", dir, err)
	}
	return reg
}

func writeSetting(t *testing.T, dir string, e effect) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, e.file), []byte(e.content), e.mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile's mode is masked by the process umask, and every setting checks
	// its own mode. Set it explicitly so the test does not depend on one.
	if err := os.Chmod(filepath.Join(dir, e.file), e.mode); err != nil {
		t.Fatal(err)
	}
}

// discardAuditor is checkAuditor, the one `config check` builds registries
// with: these tests and that command both want a registry and no audit log, so
// they should not disagree about how to get one.
func discardAuditor() toolplane.Auditor { return checkAuditor() }
