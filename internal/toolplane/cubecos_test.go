package toolplane

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCubeCOS(t *testing.T, dir, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, CubeCOSFileName)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile's mode is masked by the umask, and this setting checks its own.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCubeCOSAccessRoundTrips(t *testing.T) {
	dir := t.TempDir()
	writeCubeCOS(t, dir, `{"datacenter":"cube-combined","base_url":"http://10.32.1.200:8082"}`, 0o644)

	got, err := ReadCubeCOSAccess(dir)
	if err != nil {
		t.Fatalf("ReadCubeCOSAccess: %v", err)
	}
	if got.Datacenter != "cube-combined" || got.BaseURL != "http://10.32.1.200:8082" {
		t.Errorf("got %+v, want the file's own values", got)
	}
}

// Absent is the ordinary state of a cluster that has not opted in, and is not
// an error: the agent starts and its reads refuse.
func TestNoCubeCOSFileIsNotAnError(t *testing.T) {
	if _, err := ReadCubeCOSAccess(t.TempDir()); err != ErrNoCubeCOS {
		t.Errorf("err = %v, want ErrNoCubeCOS", err)
	}
}

// Whoever may write this file chooses where the node token is sent, which is
// the whole of the node's api authority. Readability is deliberately not
// checked: the file holds no secret.
func TestACubeCOSFileOthersCanWriteIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeCubeCOS(t, dir, `{"datacenter":"dc","base_url":"http://h:8082"}`, 0o666)

	_, err := ReadCubeCOSAccess(dir)
	if err == nil {
		t.Fatal("a world-writable file was accepted")
	}
	if !strings.Contains(err.Error(), "node token") {
		t.Errorf("error %q does not say why writability matters", err)
	}
}

func TestACubeCOSFileOthersCanReadIsAccepted(t *testing.T) {
	dir := t.TempDir()
	writeCubeCOS(t, dir, `{"datacenter":"dc","base_url":"http://h:8082"}`, 0o644)

	if _, err := ReadCubeCOSAccess(dir); err != nil {
		t.Fatalf("a readable file was refused: %v", err)
	}
}

// Half-configured access reads nothing, and the startup line names the field
// that is missing rather than the file in general.
func TestAHalfConfiguredCubeCOSFileNamesTheMissingField(t *testing.T) {
	for field, content := range map[string]string{
		"datacenter": `{"base_url":"http://h:8082"}`,
		"base_url":   `{"datacenter":"dc"}`,
	} {
		dir := t.TempDir()
		writeCubeCOS(t, dir, content, 0o644)

		_, err := ReadCubeCOSAccess(dir)
		if err == nil {
			t.Fatalf("%s: a half-configured file was accepted", field)
		}
		if !strings.Contains(err.Error(), field) {
			t.Errorf("error %q does not name the missing %s", err, field)
		}
	}
}

// "datacentre" is the spelling this codebase's own prose uses, and "baseUrl"
// is the shape the rest of the world writes. Ignoring either would leave the
// field empty and refuse every read for a reason the operator cannot see in
// their own file — the same trap "flavour" sets for the instance profile.
func TestAMisspelledCubeCOSFieldIsRefused(t *testing.T) {
	for _, content := range []string{
		`{"datacentre":"dc","base_url":"http://h:8082"}`,
		`{"datacenter":"dc","baseUrl":"http://h:8082"}`,
	} {
		dir := t.TempDir()
		writeCubeCOS(t, dir, content, 0o644)

		if _, err := ReadCubeCOSAccess(dir); err == nil {
			t.Errorf("%s: a misspelled field was ignored rather than refused", content)
		}
	}
}

// Case variants are tolerated, and this records that rather than leaving it to
// be discovered: encoding/json matches field names case-insensitively, so
// "dataCenter" lands on datacenter with its value intact. That is forgiving in
// a harmless direction — the field is filled, not silently empty — and it is
// why the test above uses a different word rather than a different case.
func TestACaseVariantCubeCOSFieldIsAccepted(t *testing.T) {
	dir := t.TempDir()
	writeCubeCOS(t, dir, `{"dataCenter":"dc","base_url":"http://h:8082"}`, 0o644)

	got, err := ReadCubeCOSAccess(dir)
	if err != nil {
		t.Fatalf("a case variant was refused: %v", err)
	}
	if got.Datacenter != "dc" {
		t.Errorf("Datacenter = %q, want the value from the case variant", got.Datacenter)
	}
}

// Every refusal a read can reach names the file that would enable it — the
// argument executorFilled already makes for {flavor}, applied to {dc}.
func TestAnUnconfiguredReadRefusesNamingTheFile(t *testing.T) {
	r, err := New([]Tool{catalogTool()}, &recorder{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.Call(context.Background(), "cube_cos_read", map[string]string{"resource": "healths"}, true)
	if err == nil {
		t.Fatal("a read succeeded with no cube-cos-api access configured")
	}
	if !strings.Contains(err.Error(), CubeCOSFileName) {
		t.Errorf("refusal %q does not name %s, so an operator cannot act on it", err, CubeCOSFileName)
	}
}

// The default getter refuses for the same reason and with the same wording: an
// agent that has a datacenter but no client must not look configured.
func TestTheDefaultGetterNamesTheFile(t *testing.T) {
	_, err := notConfigured{}.Get(context.Background(), "/api/v1/x", 1)
	if err == nil || !strings.Contains(err.Error(), CubeCOSFileName) {
		t.Errorf("err = %v, want a refusal naming %s", err, CubeCOSFileName)
	}
}

// {dc} is the placeholder this setting supplies, and executorFilled must say
// so — otherwise a create refusing on {dc} falls back to wording that names no
// file at all.
func TestTheDatacenterPlaceholderNamesItsFile(t *testing.T) {
	if got := executorFilled[dcPlaceholder]; got != CubeCOSFileName {
		t.Errorf("executorFilled[%s] = %q, want %q", dcPlaceholder, got, CubeCOSFileName)
	}
}
