// Package identity holds the agent's per-cluster mTLS identity.
//
// The private key is generated on the cluster and never leaves it. Enrollment
// sends a certificate signing request; the SaaS signs it and returns a
// certificate. That is the difference between a vendor who can impersonate a
// customer's cluster and one who demonstrably cannot — and it is a property of
// where the key is made, not of anyone's good intentions.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Default locations on a CubeCOS node.
const (
	DefaultDir     = "/etc/cube/advisor-agent"
	keyFileName    = "agent.key"
	crtFileName    = "agent.crt"
	caFileName     = "enrollment-ca.crt"
	serverFileName = "server"
)

// keyFileMode is the only mode a private key may have. Enforced rather than
// warned about, following ssh's precedent: a warning gets ignored, a refusal
// gets fixed.
const keyFileMode os.FileMode = 0o600

// Identity is the agent's cluster identity: a private key that never leaves,
// the certificate the SaaS signed for it, and the CA that certificate chains to.
type Identity struct {
	ClusterID string
	key       *ecdsa.PrivateKey
	certPEM   []byte
	caPEM     []byte
}

// NewKey generates a fresh keypair on this machine.
//
// P-256 rather than Ed25519: it is what every TLS stack and every FIPS module
// on the target platforms already accepts, and enrollment is not the place to
// spend novelty budget.
func NewKey() (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate key: %w", err)
	}
	return k, nil
}

// CSR returns a PEM certificate signing request for clusterID.
//
// It carries the public key and the cluster's name. It does not, and must not,
// carry the private key — see the test that inspects the bytes.
func CSR(key *ecdsa.PrivateKey, clusterID string) ([]byte, error) {
	if clusterID == "" {
		return nil, fmt.Errorf("identity: a CSR needs a cluster id")
	}
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: clusterID},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("identity: create csr: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// Fingerprint is the SHA-256 of the public key in SPKI form, base64 encoded and
// prefixed — the same shape ssh prints.
//
// This is the value an operator compares on screen during enrollment verify, so
// it must derive from the key alone: it has to be computable before a
// certificate exists, and identical on both sides.
func Fingerprint(pub *ecdsa.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("identity: marshal public key: %w", err)
	}
	sum := sha256.Sum256(spki)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// Fingerprint of this identity.
func (i *Identity) Fingerprint() (string, error) { return Fingerprint(&i.key.PublicKey) }

// Save writes the identity to dir with the key mode-restricted.
func (i *Identity) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("identity: create dir: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(i.key)
	if err != nil {
		return fmt.Errorf("identity: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	// The key is written with its final mode from the start rather than
	// chmod-ed afterwards, so it is never briefly readable.
	if err := os.WriteFile(filepath.Join(dir, keyFileName), keyPEM, keyFileMode); err != nil {
		return fmt.Errorf("identity: write key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, crtFileName), i.certPEM, 0o644); err != nil {
		return fmt.Errorf("identity: write certificate: %w", err)
	}
	if len(i.caPEM) > 0 {
		if err := os.WriteFile(filepath.Join(dir, caFileName), i.caPEM, 0o644); err != nil {
			return fmt.Errorf("identity: write ca: %w", err)
		}
	}
	return nil
}

// Load reads an identity from dir.
//
// It refuses a private key whose mode is looser than 0600. A key other users
// can read is not an identity, and continuing with a warning would make the
// agent's own logs the only record that its identity was readable.
func Load(dir string) (*Identity, error) {
	keyPath := filepath.Join(dir, keyFileName)
	info, err := os.Stat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("identity: no key at %s: %w", keyPath, err)
	}
	if perm := info.Mode().Perm(); perm&^keyFileMode != 0 {
		return nil, fmt.Errorf(
			"identity: %s has mode %04o; it must be %04o — others can read this key",
			keyPath, perm, keyFileMode)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("identity: read key: %w", err)
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, fmt.Errorf("identity: %s is not PEM", keyPath)
	}
	key, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity: parse key: %w", err)
	}

	certPEM, err := os.ReadFile(filepath.Join(dir, crtFileName))
	if err != nil {
		return nil, fmt.Errorf("identity: read certificate: %w", err)
	}
	caPEM, _ := os.ReadFile(filepath.Join(dir, caFileName)) // optional

	id := &Identity{key: key, certPEM: certPEM, caPEM: caPEM}
	if cn, err := id.commonName(); err == nil {
		id.ClusterID = cn
	}
	return id, nil
}

func (i *Identity) commonName() (string, error) {
	blk, _ := pem.Decode(i.certPEM)
	if blk == nil {
		return "", fmt.Errorf("identity: certificate is not PEM")
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "", err
	}
	return crt.Subject.CommonName, nil
}

// SaveServer persists the tunnel address enrolment resolved, so a later `run`
// needs no operator argument. Mode 0644, unlike the key: this is not secret,
// it is the same host:port an operator could read straight off the SaaS.
//
// It is a separate write from Save rather than a field on it, so an existing
// caller of Save is unaffected and a failure to persist the address (a
// read-only /etc, say) never looks like a failure to persist the identity.
func SaveServer(dir, addr string) error {
	if addr == "" {
		return fmt.Errorf("identity: refusing to persist an empty tunnel address")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("identity: create dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, serverFileName), []byte(addr), 0o644); err != nil {
		return fmt.Errorf("identity: write server address: %w", err)
	}
	return nil
}

// LoadServer reads the tunnel address SaveServer persisted. A missing file is
// not an error — it just means enrolment predates this feature, or never
// resolved an address — so the caller (run) can fall back to requiring
// -server explicitly instead of failing to load an identity that is otherwise
// fine.
func LoadServer(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, serverFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("identity: read server address: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// Exists reports whether dir already holds a key and certificate. Enrollment
// consults this so a second run cannot silently replace a working identity —
// re-enrolling is a deliberate act, not an accident of running a command twice.
func Exists(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, keyFileName)); err != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, crtFileName))
	return err == nil
}

// TLSConfig builds the client configuration for the tunnel dial.
//
// The CA obtained at enrollment is the only root trusted for this connection:
// the agent talks to the service that enrolled it, not to anything holding a
// certificate from a public CA.
func (i *Identity) TLSConfig(serverName string) (*tls.Config, error) {
	der, err := x509.MarshalECPrivateKey(i.key)
	if err != nil {
		return nil, fmt.Errorf("identity: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	pair, err := tls.X509KeyPair(i.certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("identity: key and certificate do not match: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
		ServerName:   serverName,
	}
	if len(i.caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(i.caPEM) {
			return nil, fmt.Errorf("identity: enrollment CA is not usable")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// Remove deletes a stored identity.
//
// Used only by an explicit re-enrolment. It is a separate function rather than
// something Save does implicitly, because silently replacing an identity is how
// a cluster loses the certificate the SaaS is currently accepting.
func Remove(dir string) error {
	for _, name := range []string{keyFileName, crtFileName, caFileName, serverFileName} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("identity: removing %s: %w", name, err)
		}
	}
	return nil
}
