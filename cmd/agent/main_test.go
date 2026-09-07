package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/enrollproto"
)

// The token-reading rules are worth testing directly: they are the difference
// between a pairing token that appears in ps and one that does not, and an
// installer picks the path.

func TestReadTokenSources(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readToken("flag-token", "", false)
	if err != nil || got != "flag-token" {
		t.Errorf("flag: %q, %v", got, err)
	}

	got, err = readToken("", file, false)
	if err != nil || got != "file-token" {
		t.Errorf("file: %q, %v — surrounding whitespace should be trimmed", got, err)
	}
}

// Exactly one source, so a caller cannot half-supply two and get a surprise.
func TestReadTokenRequiresExactlyOneSource(t *testing.T) {
	if _, err := readToken("", "", false); err == nil {
		t.Error("no token source was accepted")
	}
	if _, err := readToken("a", "b", false); err == nil {
		t.Error("two token sources were accepted")
	}
}

func TestReadTokenRejectsAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken("", empty, false); err == nil {
		t.Error("an empty token file was accepted")
	}
	if _, err := readToken("", filepath.Join(dir, "absent"), false); err == nil {
		t.Error("a missing token file was accepted")
	}
}

// Enrolling twice must not be a side effect of running the command again.
func TestEnrollRefusesWhenAlreadyEnrolled(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"agent.key", "agent.crt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code := enrollCmd([]string{"-server", "https://example", "-cluster", "c", "-dir", dir, "-token", "t"})
	if code != exitAlready {
		t.Errorf("exit = %d, want %d (already enrolled)", code, exitAlready)
	}
}

func TestEnrollRequiresAServer(t *testing.T) {
	if code := enrollCmd([]string{"-token", "t"}); code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
}

func TestStatusReportsNotEnrolled(t *testing.T) {
	if code := statusCmd([]string{"-dir", t.TempDir()}); code != exitAlready {
		t.Errorf("exit = %d, want %d", code, exitAlready)
	}
}

// A present-but-unloadable identity is a different problem from an absent one —
// usually the key's permissions were changed — and an operator needs to be able
// to tell them apart.
func TestStatusDistinguishesAnUnusableIdentity(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"agent.key", "agent.crt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not pem"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code := statusCmd([]string{"-dir", dir}); code != exitFailed {
		t.Errorf("exit = %d, want %d (present but unusable)", code, exitFailed)
	}
}

func TestExitCodesAreDistinct(t *testing.T) {
	seen := map[int]string{}
	for name, code := range map[string]int{
		"ok": exitOK, "usage": exitUsage, "already": exitAlready,
		"tokenRefused": exitTokenRefused, "unreachable": exitUnreachable, "failed": exitFailed,
	} {
		if prev, dup := seen[code]; dup {
			t.Errorf("%s and %s share exit code %d; an installer cannot branch on them", name, prev, code)
		}
		seen[code] = name
	}
}

// --- tunnel address persistence (bigstack-oss/cube-advisor-agent#19) -----

func TestDeriveTunnelAddrUsesTheServerHostOnTheDefaultPort(t *testing.T) {
	got, err := deriveTunnelAddr("https://advisor.bigstack.co")
	if err != nil {
		t.Fatal(err)
	}
	if got != "advisor.bigstack.co:8443" {
		t.Errorf("got %q, want the -server host on the tunnel default port", got)
	}
}

// The enrollment service's own port must not leak into the derived tunnel
// address — they are two different listeners, which is the whole reason an
// operator whose SaaS differs needs -tunnel.
func TestDeriveTunnelAddrIgnoresTheEnrollmentPort(t *testing.T) {
	got, err := deriveTunnelAddr("https://advisor.bigstack.co:9443/enroll")
	if err != nil {
		t.Fatal(err)
	}
	if got != "advisor.bigstack.co:8443" {
		t.Errorf("got %q, want the enrollment port replaced by the tunnel default", got)
	}
}

func TestDeriveTunnelAddrRejectsAServerWithNoHost(t *testing.T) {
	if _, err := deriveTunnelAddr(""); err == nil {
		t.Error("a -server value with no host derived a tunnel address")
	}
}

// fakeEnrollServer plays a minimal SaaS enrollment endpoint: sign whatever CSR
// the agent sends with a throwaway key. Nothing in Enroll validates the
// signer's chain — it only checks the returned certificate matches the private
// key the agent generated — so the signer need not be a consistent CA.
func fakeEnrollServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading enroll request: %v", err)
		}
		var req enrollproto.Request
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("bad enroll request: %v", err)
		}
		blk, _ := pem.Decode([]byte(req.CSR))
		if blk == nil {
			t.Fatal("enroll request carried no CSR")
		}
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err != nil {
			t.Fatalf("bad CSR: %v", err)
		}
		pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("CSR did not carry an ECDSA public key")
		}
		signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject: pkix.Name{
				CommonName:         csr.Subject.CommonName,
				OrganizationalUnit: csr.Subject.OrganizationalUnit,
			},
			NotBefore: time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		_ = json.NewEncoder(w).Encode(enrollproto.Response{Certificate: string(certPEM)})
	}))
}

// The end-to-end proof for issue #19: a successful enrolment leaves behind a
// tunnel address run can use with no argument, derived from -server when the
// operator did not say otherwise.
func TestEnrollPersistsTheDerivedTunnelAddress(t *testing.T) {
	dir := t.TempDir()
	srv := fakeEnrollServer(t)
	defer srv.Close()

	code := enrollCmd([]string{"-server", srv.URL, "-cluster", "c", "-dir", dir, "-token", "t"})
	if code != exitOK {
		t.Fatalf("enrollCmd exit = %d", code)
	}
	got, err := identity.LoadServer(dir)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	u, _ := url.Parse(srv.URL)
	want := u.Hostname() + ":8443"
	if got != want {
		t.Errorf("persisted tunnel address = %q, want %q (derived from -server)", got, want)
	}
}

// An explicit -tunnel must win over the derivation.
func TestEnrollPersistsAnExplicitTunnelAddress(t *testing.T) {
	dir := t.TempDir()
	srv := fakeEnrollServer(t)
	defer srv.Close()

	code := enrollCmd([]string{
		"-server", srv.URL, "-cluster", "c", "-dir", dir, "-token", "t",
		"-tunnel", "tunnel.example:9443",
	})
	if code != exitOK {
		t.Fatalf("enrollCmd exit = %d", code)
	}
	got, err := identity.LoadServer(dir)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if got != "tunnel.example:9443" {
		t.Errorf("persisted tunnel address = %q, want the explicit -tunnel value", got)
	}
}

// The CSR must carry the node as CommonName and the cluster as its single OU;
// what enrollment returns is what gets persisted, so this is the whole path
// from an operator's flags to the identity on disk.
func TestEnrollCarriesTheNodeAndClusterIntoTheIdentity(t *testing.T) {
	dir := t.TempDir()
	srv := fakeEnrollServer(t)
	defer srv.Close()

	code := enrollCmd([]string{
		"-server", srv.URL, "-cluster", "ky3haclust01", "-node", "SKY142",
		"-dir", dir, "-token", "t",
	})
	if code != exitOK {
		t.Fatalf("enrollCmd exit = %d", code)
	}
	id, err := identity.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if id.ClusterID != "ky3haclust01" {
		t.Errorf("ClusterID = %q", id.ClusterID)
	}
	if id.NodeID != "sky142" {
		t.Errorf("NodeID = %q, want the -node value folded to lower case", id.NodeID)
	}
}

func TestUsageMentionsEverySubcommand(t *testing.T) {
	// Cheap guard against adding a subcommand nobody can discover.
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	usage()
	w.Close()
	os.Stderr = old
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	for _, cmd := range []string{"enroll", "status", "version"} {
		if !strings.Contains(out, cmd) {
			t.Errorf("usage does not mention %q", cmd)
		}
	}
}
