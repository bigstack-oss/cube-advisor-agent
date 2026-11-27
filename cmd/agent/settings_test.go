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
	// No settings today: the level and consent are the Advisor's record.
	return []effect{}
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

// The node's old action-level and consent files are not read: whatever they
// say, well-formed or not, changes nothing and is left on disk.
func TestTheNodesLevelAndConsentFilesAreIgnoredAndLeftAlone(t *testing.T) {
	dir := t.TempDir()
	old := map[string]string{"action-level": "operator\n", "consent": "never\n"}
	for name, content := range old {
		// World-writable, which the old reader refused.
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o666); err != nil {
			t.Fatal(err)
		}
	}

	reg, states, err := configure(dir, toolplane.Tools, discardAuditor())
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	for _, st := range states {
		if st.broken || strings.Contains(st.line, "level") || strings.Contains(st.line, "consent") {
			t.Errorf("a leftover file still reaches configure: %+v", st)
		}
	}
	plain := configureIn(t, t.TempDir())
	if got, want := strings.Join(reg.Names(), ","), strings.Join(plain.Names(), ","); got != want {
		t.Errorf("tools served = %s with the old files, %s without", got, want)
	}
	if strings.Contains(summaryLine(reg), "level") {
		t.Errorf("the startup line still names a level: %q", summaryLine(reg))
	}
	for name, content := range old {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(b) != content {
			t.Errorf("%s = %q, %v; want it left as it was", name, b, err)
		}
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
