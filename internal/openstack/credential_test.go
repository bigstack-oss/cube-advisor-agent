package openstack

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSecret = "s3cr3t-application-credential"

func writeCred(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, CredentialFileName)
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("write credential: %v", err)
	}
	// WriteFile is subject to umask; set the mode explicitly so the test
	// asserts the mode it means rather than the one the environment allowed.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return dir
}

func goodCred() string {
	return fmt.Sprintf(`{
	  "auth_url": "https://10.0.0.1:5000/v3",
	  "application_credential_id": "abc123",
	  "application_credential_secret": %q,
	  "project": "acme-prod"
	}`, testSecret)
}

// An agent with no credential is the ordinary state of every cluster that has
// not opted in. It must be distinguishable from a broken one, because one is
// configuration not yet done and the other is configuration done wrongly.
func TestAnAbsentCredentialIsNotAnError(t *testing.T) {
	_, err := ReadCredential(t.TempDir())
	if !errors.Is(err, ErrNoCredential) {
		t.Fatalf("err = %v, want ErrNoCredential", err)
	}
}

func TestACredentialOthersCanReadIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666} {
		dir := writeCred(t, goodCred(), mode)
		_, err := ReadCredential(dir)
		if err == nil {
			t.Errorf("mode %04o was accepted; it holds a secret", mode)
			continue
		}
		if errors.Is(err, ErrNoCredential) {
			t.Errorf("mode %04o reported as absent rather than refused", mode)
		}
	}
	// The owner-only case must still work, or the check has locked everyone out.
	if _, err := ReadCredential(writeCred(t, goodCred(), 0o600)); err != nil {
		t.Errorf("mode 0600 was refused: %v", err)
	}
}

// A half-configured credential creates nothing, and says which field is
// missing — the operator has to be able to finish the job.
func TestAHalfConfiguredCredentialIsRefusedByName(t *testing.T) {
	for _, field := range []string{
		"auth_url", "application_credential_id",
		"application_credential_secret", "project",
	} {
		body := strings.Replace(goodCred(), field, "unused_"+field, 1)
		_, err := ReadCredential(writeCred(t, body, 0o600))
		if err == nil {
			t.Errorf("a credential with no %s was accepted", field)
			continue
		}
		if !strings.Contains(err.Error(), field) {
			t.Errorf("error for missing %s does not name it: %v", field, err)
		}
	}
}

// The secret must not reach an error message. A JSON syntax error can quote
// the line it failed on, and that line may be the secret.
func TestAMalformedCredentialDoesNotEchoItsContents(t *testing.T) {
	body := `{"application_credential_secret": "` + testSecret + `", oops}`
	_, err := ReadCredential(writeCred(t, body, 0o600))
	if err == nil {
		t.Fatal("malformed JSON was accepted")
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Errorf("the error quotes the secret: %v", err)
	}
}

// Formatting a Credential must never print the secret. This is the defence
// that survives someone adding a %+v to a log line later, which is why it is
// a method and not a convention.
func TestFormattingACredentialNeverPrintsTheSecret(t *testing.T) {
	c, err := ReadCredential(writeCred(t, goodCred(), 0o600))
	if err != nil {
		t.Fatalf("ReadCredential: %v", err)
	}
	for _, rendered := range []string{
		fmt.Sprintf("%v", c),
		fmt.Sprintf("%s", c),
		fmt.Sprintf("%+v", c),
		fmt.Sprintf("%#v", c),
		fmt.Sprint(c),
		fmt.Sprintf("%v", []Credential{c}),
		fmt.Sprintf("%v", map[string]Credential{"k": c}),
	} {
		if strings.Contains(rendered, testSecret) {
			t.Errorf("a formatted Credential leaked the secret: %s", rendered)
		}
		if !strings.Contains(rendered, "REDACTED") {
			t.Errorf("a formatted Credential does not say it redacted: %s", rendered)
		}
	}
	// The struct still carries the secret — redaction is about rendering, not
	// about losing the value.
	if c.Secret != testSecret {
		t.Errorf("the secret did not survive loading")
	}
}
