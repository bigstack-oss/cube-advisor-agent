package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- the property the package exists for --------------------------------

// The private key is generated on the cluster and must never be transmitted.
// This inspects the bytes actually sent rather than trusting that a CSR flow
// implies it: a flow that accidentally marshalled the key would still work, and
// every other test would still pass.
func TestEnrollmentNeverSendsPrivateKeyMaterial(t *testing.T) {
	var sent []byte
	ca, caKey := testCA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent, _ = readAll(r)
		writeSignedResponse(t, w, sent, ca, caKey)
	}))
	defer srv.Close()

	e := &Enroller{BaseURL: srv.URL, HTTPClient: srv.Client()}
	id, err := e.Enroll(context.Background(), "acme-prod-01", "sky142", "pairing-token")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	body := string(sent)
	for _, forbidden := range []string{
		"PRIVATE KEY",    // any PEM private key block
		"EC PRIVATE KEY", // the specific one this package writes
		"BEGIN PRIVATE",  // PKCS#8 spelling
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("enrollment request contained %q — the key must never leave the node", forbidden)
		}
	}

	// Stronger than string matching: the private scalar itself must not appear
	// in the request in any encoding we can construct from it.
	d := id.key.D.Bytes()
	if len(d) > 8 && containsBytes(sent, d) {
		t.Error("the raw private scalar appeared in the enrollment request")
	}

	// And what *should* be there is.
	if !strings.Contains(body, "CERTIFICATE REQUEST") {
		t.Error("the request carried no CSR")
	}
}

// The token authenticates one request; it travels in a header, not the body,
// so a service logging payloads does not record a credential.
func TestPairingTokenTravelsInAHeaderNotTheBody(t *testing.T) {
	var sent []byte
	var auth string
	ca, caKey := testCA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		sent, _ = readAll(r)
		writeSignedResponse(t, w, sent, ca, caKey)
	}))
	defer srv.Close()

	e := &Enroller{BaseURL: srv.URL, HTTPClient: srv.Client()}
	if _, err := e.Enroll(context.Background(), "acme-prod-01", "sky142", "secret-token-xyz"); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer secret-token-xyz" {
		t.Errorf("Authorization = %q", auth)
	}
	if strings.Contains(string(sent), "secret-token-xyz") {
		t.Error("the pairing token appeared in the request body")
	}
}

// --- key handling --------------------------------------------------------

func TestSaveWritesAKeyOnlyItsOwnerCanRead(t *testing.T) {
	dir := t.TempDir()
	id := freshIdentity(t)
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != keyFileMode {
		t.Errorf("key mode = %04o, want %04o", perm, keyFileMode)
	}
}

// A key others can read is not an identity. Refused, not warned about —
// following ssh's precedent, because a warning gets ignored.
func TestLoadRefusesAKeyOthersCanRead(t *testing.T) {
	dir := t.TempDir()
	if err := freshIdentity(t).Save(dir); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, keyFileName)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("a world-readable key was loaded")
	}
	if !strings.Contains(err.Error(), "0644") || !strings.Contains(err.Error(), "read this key") {
		t.Errorf("the error should say what is wrong and why: %v", err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := freshIdentity(t)
	if err := orig.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	wantFP, _ := orig.Fingerprint()
	gotFP, err := loaded.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if gotFP != wantFP {
		t.Errorf("fingerprint changed across save/load: %s vs %s", gotFP, wantFP)
	}
	if loaded.ClusterID != "acme-prod-01" {
		t.Errorf("ClusterID = %q, recovered from the certificate", loaded.ClusterID)
	}
	if loaded.NodeID != "sky142" {
		t.Errorf("NodeID = %q, recovered from the certificate", loaded.NodeID)
	}
}

// --- tunnel address persistence (bigstack-oss/cube-advisor-agent#19) -----

func TestSaveServerLoadServerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := SaveServer(dir, "advisor.bigstack.co:8443"); err != nil {
		t.Fatalf("SaveServer: %v", err)
	}
	got, err := LoadServer(dir)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if got != "advisor.bigstack.co:8443" {
		t.Errorf("LoadServer = %q, want the address SaveServer wrote", got)
	}
	info, err := os.Stat(filepath.Join(dir, serverFileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("server file mode = %04o, want 0644 — it is not secret", perm)
	}
}

// A node that has never persisted a tunnel address (never enrolled, or
// enrolled before this feature existed) must not fail to load — run needs to
// fall back cleanly to requiring -server.
func TestLoadServerWithNothingPersistedIsNotAnError(t *testing.T) {
	got, err := LoadServer(t.TempDir())
	if err != nil {
		t.Fatalf("LoadServer on an empty dir returned an error: %v", err)
	}
	if got != "" {
		t.Errorf("LoadServer = %q, want empty", got)
	}
}

func TestSaveServerRefusesAnEmptyAddress(t *testing.T) {
	if err := SaveServer(t.TempDir(), ""); err == nil {
		t.Error("an empty tunnel address was persisted")
	}
}

// Save (the identity's own method) must not gain a dependency on the tunnel
// address file: the two are written independently.
func TestSaveDoesNotTouchTheServerFile(t *testing.T) {
	dir := t.TempDir()
	if err := freshIdentity(t).Save(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, serverFileName)); !os.IsNotExist(err) {
		t.Errorf("Save wrote a server file unasked: err = %v", err)
	}
}

// Remove (used before a forced re-enrolment) clears the persisted tunnel
// address along with the rest of the identity, so a re-enrol that fails
// partway does not leave a stale address behind a dead identity.
func TestRemoveClearsThePersistedServerAddress(t *testing.T) {
	dir := t.TempDir()
	if err := SaveServer(dir, "advisor.bigstack.co:8443"); err != nil {
		t.Fatal(err)
	}
	if err := Remove(dir); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, serverFileName)); !os.IsNotExist(err) {
		t.Errorf("server file survived Remove: err = %v", err)
	}
}

// --- fingerprint ---------------------------------------------------------

// The fingerprint is what an operator compares on two screens, so it must
// derive from the key alone — computable before a certificate exists — and be
// stable.
func TestFingerprintIsStableAndKeyDerived(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	a, err := Fingerprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Fingerprint(&key.PublicKey)
	if a != b {
		t.Errorf("fingerprint is not stable: %s vs %s", a, b)
	}
	if !strings.HasPrefix(a, "SHA256:") {
		t.Errorf("fingerprint = %q, want the SHA256: form an operator recognises", a)
	}

	other, _ := NewKey()
	if c, _ := Fingerprint(&other.PublicKey); c == a {
		t.Error("two different keys produced the same fingerprint")
	}
}

// --- CSR -----------------------------------------------------------------

func TestCSRCarriesTheNodeAndClusterIDAndVerifies(t *testing.T) {
	key, _ := NewKey()
	csrPEM, err := CSR(key, "acme-prod-01", "sky142")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(csrPEM)
	if blk == nil {
		t.Fatal("CSR is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature does not verify: %v", err)
	}
	if csr.Subject.CommonName != "sky142" {
		t.Errorf("CommonName = %q, want the node id", csr.Subject.CommonName)
	}
	if len(csr.Subject.OrganizationalUnit) != 1 || csr.Subject.OrganizationalUnit[0] != "acme-prod-01" {
		t.Errorf("OU = %v, want exactly one entry, the cluster id", csr.Subject.OrganizationalUnit)
	}
	if _, err := CSR(key, "", "sky142"); err == nil {
		t.Error("a CSR without a cluster id was accepted")
	}
	if _, err := CSR(key, "acme-prod-01", ""); err == nil {
		t.Error("a CSR without a node id was accepted")
	}
}

// --- enrollment behaviour ------------------------------------------------

// Each failure needs a different action from the operator, so each must be
// distinguishable.
func TestEnrollmentFailuresAreDistinguishable(t *testing.T) {
	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer rejecting.Close()

	e := &Enroller{BaseURL: rejecting.URL, HTTPClient: rejecting.Client()}
	_, err := e.Enroll(context.Background(), "acme-prod-01", "sky142", "stale-token")
	if !errors.Is(err, ErrTokenRejected) {
		t.Errorf("a rejected token gave %v, want ErrTokenRejected", err)
	}
	if !strings.Contains(err.Error(), "fresh pairing token") {
		t.Errorf("the error should say what to do next: %v", err)
	}

	unreachable := &Enroller{BaseURL: "http://127.0.0.1:1", HTTPClient: &http.Client{Timeout: time.Second}}
	if _, err := unreachable.Enroll(context.Background(), "acme-prod-01", "sky142", "t"); err == nil ||
		!strings.Contains(err.Error(), "unreachable") {
		t.Errorf("an unreachable service gave %v", err)
	}

	if _, err := (&Enroller{BaseURL: "http://x"}).Enroll(context.Background(), "c", "n", ""); err == nil {
		t.Error("enrollment without a token was accepted")
	}
}

// Running the command twice must not quietly invalidate the certificate the
// SaaS is currently accepting.
func TestEnrollAndSaveRefusesToReplaceAnIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := freshIdentity(t).Save(dir); err != nil {
		t.Fatal(err)
	}
	e := &Enroller{BaseURL: "http://unused"}
	_, err := e.EnrollAndSave(context.Background(), dir, "acme-prod-01", "sky142", "token")
	if !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("err = %v, want ErrAlreadyEnrolled", err)
	}
	if !strings.Contains(err.Error(), "remove it first") {
		t.Errorf("the error should say how to proceed deliberately: %v", err)
	}
}

// A certificate that does not match the key we just generated means something
// is wrong upstream; fail at enrollment rather than at the first tunnel dial.
func TestEnrollmentRejectsACertificateForADifferentKey(t *testing.T) {
	ca, caKey := testCA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sign a certificate for an unrelated key.
		stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		certPEM := signFor(t, &stranger.PublicKey, "sky142", []string{"acme-prod-01"}, ca, caKey)
		_ = json.NewEncoder(w).Encode(EnrollResponse{Certificate: string(certPEM)})
	}))
	defer srv.Close()

	e := &Enroller{BaseURL: srv.URL, HTTPClient: srv.Client()}
	if _, err := e.Enroll(context.Background(), "acme-prod-01", "sky142", "token"); err == nil {
		t.Fatal("a certificate for a different key was accepted")
	}
}

// --- TLS -----------------------------------------------------------------

// The agent talks to the service that enrolled it, not to anything holding a
// certificate from a public CA.
func TestTLSConfigPinsTheEnrollmentCA(t *testing.T) {
	id := freshIdentity(t)
	cfg, err := id.TLSConfig("advisor.bigstack.co")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs == nil {
		t.Error("no root pool: the agent would trust the public CA set")
	}
	if cfg.MinVersion != 0x0304 { // TLS 1.3
		t.Errorf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Error("no client certificate: the tunnel would be unauthenticated")
	}
	if cfg.ServerName != "advisor.bigstack.co" {
		t.Errorf("ServerName = %q", cfg.ServerName)
	}
}

// --- helpers -------------------------------------------------------------

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-enrollment-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return crt, key
}

func signFor(t *testing.T, pub *ecdsa.PublicKey, cn string, ou []string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: ou},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// writeSignedResponse plays the SaaS: parse the CSR, sign it, return the pair.
func writeSignedResponse(t *testing.T, w http.ResponseWriter, reqBody []byte, ca *x509.Certificate, caKey *ecdsa.PrivateKey) {
	t.Helper()
	var req EnrollRequest
	if err := json.Unmarshal(reqBody, &req); err != nil {
		t.Fatalf("server could not parse the request: %v", err)
	}
	blk, _ := pem.Decode([]byte(req.CSR))
	if blk == nil {
		t.Fatal("server received no CSR")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatalf("server could not parse the CSR: %v", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("CSR did not carry an ECDSA public key")
	}
	certPEM := signFor(t, pub, csr.Subject.CommonName, csr.Subject.OrganizationalUnit, ca, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	_ = json.NewEncoder(w).Encode(EnrollResponse{
		Certificate: string(certPEM), CA: string(caPEM),
	})
}

// freshIdentity builds a complete, self-consistent identity for tests.
func freshIdentity(t *testing.T) *Identity {
	t.Helper()
	ca, caKey := testCA(t)
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	certPEM := signFor(t, &key.PublicKey, "sky142", []string{"acme-prod-01"}, ca, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	return &Identity{ClusterID: "acme-prod-01", NodeID: "sky142", key: key, certPEM: certPEM, caPEM: caPEM}
}
