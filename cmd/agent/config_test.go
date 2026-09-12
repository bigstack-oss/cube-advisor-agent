package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
)

// These tests reach `config check` through dispatch — main's own switch —
// rather than by calling configCheckCmd directly.
//
// A subcommand tested only through its own function is a subcommand that can
// be deleted from the switch and still pass. That is not hypothetical here:
// this track has twice shipped something correct and unreachable, most
// recently a tunnel frame whose approval flag no test crossed, so the
// mechanism was right and guarded by nothing.

// A directory where every setting is written and well-formed is the state an
// operator is trying to reach, and it must exit zero.
func TestConfigCheckExitsZeroWhenEverySettingIsValid(t *testing.T) {
	dir := t.TempDir()
	for _, e := range effects(t) {
		writeSetting(t, dir, e)
	}

	code, out, _ := configCheck(t, "-dir", dir)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d for a fully configured directory:\n%s", code, exitOK, out)
	}
	for _, e := range effects(t) {
		if !strings.Contains(out, e.name+":") {
			t.Errorf("output does not report setting %q:\n%s", e.name, out)
		}
	}
	if !strings.Contains(out, "Not checked:") {
		t.Errorf("a passing check should say what it did not check, or it reads as a stronger claim than it is:\n%s", out)
	}
}

// Absent is the ordinary state of a cluster that has not opted in, and every
// setting but the action level is optional. Nothing configured is not an
// operator error, so it must not exit non-zero.
func TestConfigCheckExitsZeroOnAnUnconfiguredDirectory(t *testing.T) {
	code, out, _ := configCheck(t, "-dir", t.TempDir())
	if code != exitOK {
		t.Fatalf("exit = %d, want %d: nothing configured is a state, not a mistake:\n%s", code, exitOK, out)
	}
	if !strings.Contains(out, "not configured") {
		t.Errorf("an unconfigured directory should say so per setting:\n%s", out)
	}
}

// A setting the operator wrote and this agent cannot honour is what the
// command exists to find: it exits non-zero and names which one.
func TestConfigCheckReportsABrokenSettingAndExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, toolplane.LevelFileName), []byte("operator\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := configCheck(t, "-dir", dir)
	if code != exitConfigBroken {
		t.Fatalf("exit = %d, want %d for a broken setting:\n%s%s", code, exitConfigBroken, out, errOut)
	}
	if !strings.Contains(errOut, "action level") {
		t.Errorf("the failure should name the broken setting, not just fail:\n%s", errOut)
	}
	if !strings.Contains(out, "operator") {
		t.Errorf("the report should quote what the operator wrote, so they can see their own typo:\n%s", out)
	}
	if strings.Contains(out, "Not checked:") {
		t.Error("a failing check must not print the reassurance a passing one does")
	}
}

// The command reports exactly what configure resolved, because it is the same
// states. A second vocabulary describing one registry is this ADR's own defect
// one level up.
func TestConfigCheckReportsTheStatesConfigureReturns(t *testing.T) {
	dir := t.TempDir()
	for _, e := range effects(t) {
		writeSetting(t, dir, e)
	}

	_, states, err := configure(dir, toolplane.Allowlist, checkAuditor())
	if err != nil {
		t.Fatal(err)
	}
	_, out, _ := configCheck(t, "-dir", dir)
	for _, st := range states {
		if !strings.Contains(out, st.line) {
			t.Errorf("configure resolved %q and the check did not print it:\n%s", st.line, out)
		}
	}
}

// The command must not start the agent: it answers on a node that has not
// enrolled, and cannot begin serving by accident.
//
// The behavioural half is that a directory holding settings but no identity
// still exits zero — run would refuse there. The structural half reads this
// file's imports: dialling needs the tunnel, serving needs agent.Server, and a
// console needs console. This is enforcement rather than a guarantee, since a
// helper in another file could still reach them, but it catches the change
// that would actually be written.
func TestConfigCheckStartsNothing(t *testing.T) {
	dir := t.TempDir()
	for _, e := range effects(t) {
		writeSetting(t, dir, e)
	}
	if code, out, _ := configCheck(t, "-dir", dir); code != exitOK {
		t.Fatalf("exit = %d on an unenrolled node, want %d: a check must not need an identity:\n%s", code, exitOK, out)
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "config.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"pkg/tunnel", "internal/agent", "internal/console"}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		for _, bad := range forbidden {
			if strings.HasSuffix(path, bad) {
				t.Errorf("config.go imports %s: a check that can dial or serve is no longer a check", path)
			}
		}
	}
}

// An unknown subcommand under config is a usage error, not a silent success.
func TestConfigRejectsAnUnknownSubcommand(t *testing.T) {
	if code := dispatch([]string{"config", "sniff"}); code != exitUsage {
		t.Errorf("dispatch(config sniff) = %d, want %d", code, exitUsage)
	}
	if code := dispatch([]string{"config"}); code != exitUsage {
		t.Errorf("dispatch(config) = %d, want %d", code, exitUsage)
	}
}

// configCheck runs `config check` the way an operator does — through main's
// switch — and captures what it printed.
func configCheck(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	realOut, realErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	done := make(chan struct{})
	var outBuf, errBuf strings.Builder
	go func() {
		defer close(done)
		copyInto(&outBuf, outR)
	}()
	errDone := make(chan struct{})
	go func() {
		defer close(errDone)
		copyInto(&errBuf, errR)
	}()

	code = dispatch(append([]string{"config", "check"}, args...))

	os.Stdout, os.Stderr = realOut, realErr
	_ = outW.Close()
	_ = errW.Close()
	<-done
	<-errDone
	return code, outBuf.String(), errBuf.String()
}

func copyInto(dst *strings.Builder, r *os.File) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			dst.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}
