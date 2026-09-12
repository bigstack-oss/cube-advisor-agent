package toolplane

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeProfile(t *testing.T, dir, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, ProfileFileName)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

const goodProfile = `{"flavor":"m1.large","image":"ubuntu-24.04","network":"tenant-net"}`

// A cluster that has not opted in is not broken. It creates nothing and says
// so, which is a different thing from a profile its operator got wrong.
func TestNoProfileIsNotAnError(t *testing.T) {
	_, err := ReadInstanceProfile(t.TempDir())
	if !errors.Is(err, ErrNoProfile) {
		t.Fatalf("ReadInstanceProfile with no file = %v, want ErrNoProfile", err)
	}
}

func TestAProfileIsReadWhole(t *testing.T) {
	dir := t.TempDir()
	writeProfile(t, dir, goodProfile, 0o644)

	p, err := ReadInstanceProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Flavor != "m1.large" || p.Image != "ubuntu-24.04" || p.Network != "tenant-net" {
		t.Fatalf("ReadInstanceProfile = %+v, want the three fields the file names", p)
	}
}

// Each of the three is required, and the message names the one that is missing
// rather than the file in general: an operator reading it should not have to
// diff their own file against the documentation.
func TestAHalfConfiguredProfileIsRefusedNamingTheMissingField(t *testing.T) {
	for _, tc := range []struct{ name, content, want string }{
		{"no flavor", `{"image":"i","network":"n"}`, "flavor"},
		{"no image", `{"flavor":"f","network":"n"}`, "image"},
		{"no network", `{"flavor":"f","image":"i"}`, "network"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeProfile(t, dir, tc.content, 0o644)

			_, err := ReadInstanceProfile(dir)
			if err == nil {
				t.Fatal("a profile missing a required field was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name the missing %s", err, tc.want)
			}
		})
	}
}

// "flavour" is the spelling this codebase's own prose uses, so it is the typo
// an operator is most likely to make. Ignoring the unknown key would leave
// Flavor empty and refuse every create with a message about a flavour they can
// see in their file.
func TestABritishFlavourIsRejectedRatherThanIgnored(t *testing.T) {
	dir := t.TempDir()
	writeProfile(t, dir, `{"flavour":"m1.large","image":"i","network":"n"}`, 0o644)

	_, err := ReadInstanceProfile(dir)
	if err == nil {
		t.Fatal("an unknown field was ignored; the operator would never learn why their flavour was not used")
	}
	if !strings.Contains(err.Error(), "flavour") {
		t.Errorf("error = %q, want it to quote the key the operator wrote", err)
	}
}

// Whoever may write this file chooses the image, and choosing the image is
// choosing what code runs. Readability is deliberately not constrained.
func TestAProfileOthersCanWriteIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeProfile(t, dir, goodProfile, 0o666)

	if _, err := ReadInstanceProfile(dir); err == nil {
		t.Fatal("a world-writable profile was accepted; anyone local could choose the image")
	}

	other := t.TempDir()
	writeProfile(t, other, goodProfile, 0o644)
	if _, err := ReadInstanceProfile(other); err != nil {
		t.Fatalf("a world-readable profile was refused: %v — it holds no secret", err)
	}
}

// project is optional: nova takes the project from the credential's scope, so
// the field is a declaration for the operator and the approval statement, not
// a value the request carries.
func TestProjectIsOptional(t *testing.T) {
	dir := t.TempDir()
	writeProfile(t, dir, goodProfile, 0o644)
	p, err := ReadInstanceProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Project != "" {
		t.Errorf("Project = %q with none in the file, want empty", p.Project)
	}

	withProject := t.TempDir()
	writeProfile(t, withProject, `{"flavor":"f","image":"i","network":"n","project":"advisor-lab"}`, 0o644)
	p, err = ReadInstanceProfile(withProject)
	if err != nil {
		t.Fatal(err)
	}
	if p.Project != "advisor-lab" {
		t.Errorf("Project = %q, want the file's value", p.Project)
	}
}

// Every placeholder the profile supplies must name the profile file, one by
// one.
//
// The end-to-end test below is not enough on its own and this is why: a Post
// tool's body is a map, so the resolver reaches its placeholders in whatever
// order Go iterates, and any one of the three satisfies "the message names the
// file". Breaking a single placeholder's attribution left that test green —
// found by breaking it, not by reading it. This one is per placeholder and
// deterministic.
func TestEveryProfilePlaceholderNamesTheProfileFile(t *testing.T) {
	for _, ph := range []string{flavorPlaceholder, imagePlaceholder, networkPlaceholder, projectPlaceholder} {
		if got := executorFilled[ph]; got != ProfileFileName {
			t.Errorf("executorFilled[%s] = %q, want %s: an unconfigured create would not say where to write it",
				ph, got, ProfileFileName)
		}
	}
}

// The refusal an operator actually meets when they raise the level and stop.
// ADR 0016's own slice table asks for this: absent refuses a create naming the
// file, because "no flavor configured" leaves them hunting for where to write
// it.
func TestAnUnconfiguredCreateRefusesNamingTheFile(t *testing.T) {
	var create Tool
	for _, tool := range Allowlist {
		if tool.Name == "create_instance" {
			create = tool
		}
	}
	if create.Name == "" {
		t.Fatal("create_instance is not in the allowlist")
	}

	_, _, err := create.resolveWrite(map[string]string{"{name}": "web-03"}, map[string]string{})
	if err == nil {
		t.Fatal("a create resolved with no profile configured")
	}
	if !strings.Contains(err.Error(), ProfileFileName) {
		t.Errorf("error = %q, want it to name %s", err, ProfileFileName)
	}
}
