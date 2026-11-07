package identity

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	caA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEe4bv2j4FtzsksuvuL9LuAyISEvJt0YcT0Zr2iizt9Q cube-advisor-console"
	caB = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCk5w584S2EMXJmYEv0w0GrnbAsRU+hYd/ZnFt8gfIcKwK96FZOk66GQcLHLP8NPI78XxBVOrsWGf9OLdS27pJE= cube-advisor-console"
)

func TestValidConsoleCALine(t *testing.T) {
	for _, ok := range []string{caA, caB} {
		if err := ValidConsoleCALine(ok); err != nil {
			t.Errorf("%q refused: %v", ok[:20], err)
		}
	}
	for name, bad := range map[string]string{
		"two lines":     caA + "\n" + caB,
		"one field":     "ssh-ed25519",
		"unknown type":  "rsa AAAA",
		"not base64":    "ssh-ed25519 !!!!",
		"type mismatch": "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIEe4bv2j4FtzsksuvuL9LuAyISEvJt0YcT0Zr2iizt9Q",
		"options first": `command="sh" ` + caA,
		"private key":   "-----BEGIN OPENSSH PRIVATE KEY-----",
	} {
		if err := ValidConsoleCALine(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Console access is granted at enrolment. A node without the trusted file
// never gets one from a connect.
func TestRotateNeverCreatesTheTrustedCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cube-advisor.pub")
	changed, err := RotateTrustedConsoleCA(path, caA)
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rotation created %s (%v)", path, err)
	}
}

func TestRotateReplacesAnExistingTrustedCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cube-advisor.pub")
	if err := os.WriteFile(path, []byte(caA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := RotateTrustedConsoleCA(path, caB)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != caB+"\n" {
		t.Errorf("trusted CA = %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
	}
	before, _ := os.Stat(path)
	if changed, err := RotateTrustedConsoleCA(path, caB); err != nil || changed {
		t.Errorf("unchanged CA rewrote: changed=%v err=%v", changed, err)
	}
	after, _ := os.Stat(path)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("unchanged CA touched the file")
	}
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Errorf("temp files left behind: %v", ents)
	}
}

func TestRotateRefusesAMalformedCAAndKeepsTheOld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cube-advisor.pub")
	if err := os.WriteFile(path, []byte(caA+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateTrustedConsoleCA(path, caA+"\n"+caB); err == nil {
		t.Fatal("a two-key CA was accepted")
	}
	if b, _ := os.ReadFile(path); string(b) != caA+"\n" {
		t.Errorf("trusted CA changed to %q", b)
	}
}

func TestPeersPendingIsTakenOnce(t *testing.T) {
	dir := t.TempDir()
	if TakePeersPending(dir) {
		t.Fatal("taken before marked")
	}
	if err := MarkPeersPending(dir); err != nil {
		t.Fatal(err)
	}
	if !TakePeersPending(dir) || TakePeersPending(dir) {
		t.Error("mark not taken exactly once")
	}
}
