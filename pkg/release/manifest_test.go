package release

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These shell out to the real openssl and sha256sum on purpose.
//
// The manifest exists to be checked by a shell verifier in cubecos. A Go
// reimplementation of that check would prove the Go agrees with itself and
// nothing about whether the two commands a reviewer will read actually accept
// what we produce.

func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available", name)
	}
}

// releaseDir builds a directory of fake artifacts plus a manifest.
func releaseDir(t *testing.T) (dir string, m Manifest) {
	t.Helper()
	dir = t.TempDir()
	for name, body := range map[string]string{
		"cube-advisor-agent_linux_amd64": "pretend amd64 binary\n",
		"cube-advisor-agent_linux_arm64": "pretend arm64 binary\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	m, err := Build(dir, "0.2.0", "abc1234", 1)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	return dir, m
}

// The whole design rests on this: sha256sum -c must accept the manifest with no
// preprocessing, so the node-side verifier needs no parser of its own.
func TestSha256sumAcceptsTheManifestUnmodified(t *testing.T) {
	requireTool(t, "sha256sum")
	dir, _ := releaseDir(t)

	cmd := exec.Command("sha256sum", "-c", ManifestName)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sha256sum -c rejected the manifest: %v\n%s", err, out)
	}
	if strings.Count(string(out), ": OK") != 2 {
		t.Errorf("expected both artifacts to verify:\n%s", out)
	}
}

// A tampered artifact must fail the digest check.
func TestATamperedArtifactFailsTheDigestCheck(t *testing.T) {
	requireTool(t, "sha256sum")
	dir, _ := releaseDir(t)

	target := filepath.Join(dir, "cube-advisor-agent_linux_amd64")
	if err := os.WriteFile(target, []byte("malicious payload\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sha256sum", "-c", ManifestName)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("a tampered artifact passed:\n%s", out)
	}
	if !strings.Contains(string(out), "FAILED") {
		t.Errorf("output should name the failure:\n%s", out)
	}
}

// The second half of the verifier: the manifest itself must be signed, so
// tampering with the digest list is caught before any digest is trusted.
func TestOpensslVerifiesADetachedSignatureOverTheManifest(t *testing.T) {
	requireTool(t, "openssl")
	dir, _ := releaseDir(t)

	priv, pub := testKeypair(t, dir)
	sig := filepath.Join(dir, SignatureName)
	sign(t, priv, filepath.Join(dir, ManifestName), sig)

	// Exactly the command the cubecos verifier runs.
	cmd := exec.Command("openssl", "dgst", "-sha256",
		"-verify", pub, "-signature", sig, ManifestName)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl rejected a good signature: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Verified OK") {
		t.Errorf("unexpected openssl output: %s", out)
	}
}

// Editing a digest in the manifest must break the signature — otherwise an
// attacker could swap in their own artifact and matching digest.
func TestATamperedManifestFailsSignatureVerification(t *testing.T) {
	requireTool(t, "openssl")
	dir, _ := releaseDir(t)

	priv, pub := testKeypair(t, dir)
	manifest := filepath.Join(dir, ManifestName)
	sig := filepath.Join(dir, SignatureName)
	sign(t, priv, manifest, sig)

	// Swap one digest for another valid-looking one.
	body, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(body), "a", "b", 1)
	if tampered == string(body) {
		t.Fatal("test did not actually modify the manifest")
	}
	if err := os.WriteFile(manifest, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("openssl", "dgst", "-sha256",
		"-verify", pub, "-signature", sig, ManifestName)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("a tampered manifest verified:\n%s", out)
	}
}

// A signature from the wrong key must not verify — the release public key baked
// into the OS image is the trust anchor, and nothing else may stand in for it.
func TestASignatureFromAnotherKeyIsRejected(t *testing.T) {
	requireTool(t, "openssl")
	dir, _ := releaseDir(t)

	attackerPriv, _ := testKeypair(t, filepath.Join(dir, "attacker"))
	_, realPub := testKeypair(t, dir)

	sig := filepath.Join(dir, SignatureName)
	sign(t, attackerPriv, filepath.Join(dir, ManifestName), sig)

	cmd := exec.Command("openssl", "dgst", "-sha256",
		"-verify", realPub, "-signature", sig, ManifestName)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("a signature from the wrong key verified:\n%s", out)
	}
}

// --- format ---------------------------------------------------------------

func TestRenderIsStableForTheSameInputs(t *testing.T) {
	m := Manifest{
		Version: "0.2.0", Commit: "abc", ProtocolVersion: 1,
		Artifacts: []Artifact{
			{Name: "z_arm64", SHA256: strings.Repeat("b", 64)},
			{Name: "a_amd64", SHA256: strings.Repeat("a", 64)},
		},
	}
	first := string(m.Render())
	// Reversed input order must not change the output; a manifest that varies
	// run to run cannot be reproduced by anyone checking our work.
	m.Artifacts[0], m.Artifacts[1] = m.Artifacts[1], m.Artifacts[0]
	if second := string(m.Render()); first != second {
		t.Errorf("Render is not stable:\n%s\nvs\n%s", first, second)
	}
	if !strings.Contains(first, "# protocol: 1") {
		t.Error("the manifest should record the protocol version the agent speaks")
	}
}

func TestRoundTrip(t *testing.T) {
	dir, want := releaseDir(t)
	f, err := os.Open(filepath.Join(dir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := ParseManifest(f)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if got.Version != want.Version || got.Commit != want.Commit || got.ProtocolVersion != 1 {
		t.Errorf("metadata lost: %+v", got)
	}
	if len(got.Artifacts) != len(want.Artifacts) {
		t.Errorf("artifacts = %d, want %d", len(got.Artifacts), len(want.Artifacts))
	}
}

func TestBuildRefusesAnEmptyDirectory(t *testing.T) {
	if _, err := Build(t.TempDir(), "0.1.0", "abc", 1); err == nil {
		t.Error("a release with no artifacts was accepted")
	}
}

// The manifest must not digest itself or its own signature.
func TestBuildSkipsTheManifestAndSignature(t *testing.T) {
	dir, _ := releaseDir(t)
	if err := os.WriteFile(filepath.Join(dir, SignatureName), []byte("sig"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := Build(dir, "0.2.0", "abc", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range m.Artifacts {
		if a.Name == ManifestName || a.Name == SignatureName {
			t.Errorf("manifest lists %s", a.Name)
		}
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	for _, bad := range []string{
		"",                     // nothing at all
		"# version: 1\n",       // metadata but no artifacts
		"nothaadigest  file\n", // digest wrong length
		"aaaa\n",               // no separator
	} {
		if _, err := ParseManifest(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted malformed manifest %q", bad)
		}
	}
}

// --- helpers --------------------------------------------------------------

// testKeypair generates an ECDSA release keypair with openssl itself, so the
// key format is exactly what the signing and verifying commands expect.
func testKeypair(t *testing.T, dir string) (priv, pub string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	priv = filepath.Join(dir, "release.key")
	pub = filepath.Join(dir, "release.pub")
	run(t, "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", priv)
	run(t, "openssl", "ec", "-in", priv, "-pubout", "-out", pub)
	return priv, pub
}

func sign(t *testing.T, privPath, file, sigPath string) {
	t.Helper()
	run(t, "openssl", "dgst", "-sha256", "-sign", privPath, "-out", sigPath, file)
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}
