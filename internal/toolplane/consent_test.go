package toolplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ADR 0011's "unset means always": the three ways a cluster can say nothing all
// answer the cautious value, and none of them is an error.
func TestAnUnsaidConsentAsksForEverything(t *testing.T) {
	for _, c := range []struct {
		name  string
		write func(dir string)
	}{
		{"no file", func(string) {}},
		{"empty file", func(dir string) { writeConsent(t, dir, "", 0o644) }},
		{"whitespace", func(dir string) { writeConsent(t, dir, "  \n\t\n", 0o644) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			c.write(dir)
			got, err := ReadConsent(dir)
			if err != nil {
				t.Fatalf("ReadConsent = %v, want no error for %s", err, c.name)
			}
			if got != ConsentAlways {
				t.Errorf("ReadConsent = %s, want always", got)
			}
		})
	}
}

// A word nobody in this build recognises is the failure the file exists to
// prevent: an operator who wrote "none" meaning "never" has a cluster asking
// about everything while they believe it asks about nothing. Loud, and still
// falling closed.
func TestAnUnreadableConsentIsLoudAndStillFallsClosed(t *testing.T) {
	dir := t.TempDir()
	writeConsent(t, dir, "none\n", 0o644)

	got, err := ReadConsent(dir)
	if err == nil {
		t.Fatal("ReadConsent accepted a word that is not a consent setting")
	}
	if got != ConsentAlways {
		t.Errorf("ReadConsent = %s alongside its error, want always", got)
	}
	if !strings.Contains(err.Error(), "none") {
		t.Errorf("error %q does not quote what the operator wrote", err)
	}
	if !strings.Contains(err.Error(), ConsentFileName) {
		t.Errorf("error %q does not name the file to correct", err)
	}
}

// Whoever can write this file can stop the cluster asking a person before it
// acts, so a file others may write is not a control.
func TestAConsentFileOthersCanWriteIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeConsent(t, dir, "never\n", 0o666)

	got, err := ReadConsent(dir)
	if err == nil {
		t.Fatal("ReadConsent accepted a world-writable consent file")
	}
	if got != ConsentAlways {
		t.Errorf("ReadConsent = %s alongside its error, want always", got)
	}
	if !strings.Contains(err.Error(), "asking a person") {
		t.Errorf("error %q does not say what the mode would let someone do", err)
	}
}

// Readability is deliberately unconstrained: a policy statement its customer
// should be able to read without root, and it holds no secret.
func TestAReadableConsentFileIsFine(t *testing.T) {
	dir := t.TempDir()
	writeConsent(t, dir, "destructive\n", 0o644)

	got, err := ReadConsent(dir)
	if err != nil {
		t.Fatalf("ReadConsent = %v, want a world-readable file to be accepted", err)
	}
	if got != ConsentDestructive {
		t.Errorf("ReadConsent = %s, want destructive", got)
	}
}

// Each value asks for what it says and no less. The read row is the one that
// holds whatever the dial says: there is nothing to agree to.
func TestEachConsentValueAsksForWhatItNames(t *testing.T) {
	for _, c := range []struct {
		consent     Consent
		impact      Impact
		destructive bool
		want        bool
	}{
		{ConsentAlways, ImpactRead, false, false},
		{ConsentAlways, ImpactOperate, false, true},
		{ConsentAlways, ImpactInternal, false, true},
		{ConsentAlways, ImpactScratch, false, true},

		{ConsentDestructive, ImpactRead, true, false},
		{ConsentDestructive, ImpactOperate, false, false},
		{ConsentDestructive, ImpactOperate, true, true},

		{ConsentNever, ImpactRead, false, false},
		{ConsentNever, ImpactOperate, true, false},
		{ConsentNever, ImpactInternal, true, false},

		// A value from a newer build, or a zero one, asks. The same
		// defence ParseConsent makes by returning the default.
		{Consent(0), ImpactOperate, false, true},
		{Consent(99), ImpactOperate, false, true},
		{Consent(0), ImpactRead, false, false},
	} {
		if got := c.consent.Asks(c.impact, c.destructive); got != c.want {
			t.Errorf("%s.Asks(%s, destructive=%v) = %v, want %v",
				c.consent, c.impact, c.destructive, got, c.want)
		}
	}
}

// The executor's half of the dial. A cluster that requires a person refuses a
// call the caller did not say one approved — which is what makes a stale SaaS
// mirror a visible refusal rather than a silent unattended call.
func TestAClusterRequiringAPersonRefusesAnUnapprovedCall(t *testing.T) {
	r, rec := newConsentRegistry(t, ConsentAlways)

	_, err := r.Call(context.Background(), "create_instance",
		map[string]string{"{name}": "web-03"}, false)
	if !errors.Is(err, ErrRefusedWithoutApproval) {
		t.Fatalf("err = %v, want ErrRefusedWithoutApproval", err)
	}
	if got := lastReason(rec); !strings.Contains(got, "requires a person") {
		t.Errorf("audit reason %q does not say a person was required", got)
	}
}

// The same call, with the caller reporting a person, reaches the tool. Without
// this the test above would pass for a registry that refuses everything.
func TestAnApprovedCallIsNotRefusedByConsent(t *testing.T) {
	r, _ := newConsentRegistry(t, ConsentAlways)

	_, err := r.Call(context.Background(), "create_instance",
		map[string]string{"{name}": "web-03"}, true)
	if errors.Is(err, ErrRefusedWithoutApproval) {
		t.Fatalf("an approved call was refused for want of a person")
	}
}

// A cluster that asks nobody runs unattended within its action level. The
// customer chose it.
func TestAClusterAtNeverRunsWithoutAPerson(t *testing.T) {
	r, _ := newConsentRegistry(t, ConsentNever)

	_, err := r.Call(context.Background(), "create_instance",
		map[string]string{"{name}": "web-03"}, false)
	if errors.Is(err, ErrRefusedWithoutApproval) {
		t.Fatalf("a cluster at consent never still demanded a person")
	}
}

// Reads are never gated on a person, whatever the dial says — otherwise a
// cluster at the default would stop serving its own catalogue.
func TestConsentNeverWithholdsAReadFromAnUnapprovedCaller(t *testing.T) {
	r, _, _ := newGetRegistry(t, []Tool{catalogTool()}, "sky-dc")
	WithConsent(ConsentAlways)(r)

	if _, err := r.Call(context.Background(), "cube_cos_read",
		map[string]string{"resource": "nodes"}, false); err != nil {
		t.Fatalf("an unapproved read was refused: %v", err)
	}
}

// No tool declares itself destructive today, so a cluster set to destructive
// asks about nothing. Stated as a test rather than a comment so it stops being
// true by failing, on the day someone adds one — at which point the startup
// caveat disappears too.
func TestNoToolIsDestructiveYet(t *testing.T) {
	if DestructiveToolsExist() {
		t.Fatal("a tool now declares itself destructive: " +
			"consent destructive has members, so the startup caveat must go and this test with it")
	}
}

func writeConsent(t *testing.T, dir, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, ConsentFileName)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to the process umask, so a mode the test means to
	// be group- or world-writable has to be set explicitly.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// newConsentRegistry is writeRegistry with the dial set: an agent whose
// operator enabled writes and then said how much they want to be asked.
func newConsentRegistry(t *testing.T, c Consent) (*Registry, *recorder) {
	t.Helper()
	r, _, rec := writeRegistry(t, nil)
	WithConsent(c)(r)
	return r, rec
}

func lastReason(rec *recorder) string {
	calls := rec.snapshot()
	if len(calls) == 0 {
		return ""
	}
	return calls[len(calls)-1].Reason
}
