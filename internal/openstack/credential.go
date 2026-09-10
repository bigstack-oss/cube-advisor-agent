// Package openstack reaches the cluster's own OpenStack APIs on behalf of the
// tool plane.
//
// It exists because instances are nova's and not cube-cos-api's, and because
// the tool plane deliberately holds no base URL, credential or TLS trust: a
// client owns those so they cannot reach the allowlist, the audit log or the
// model. This package is that client for OpenStack.
//
// Everything here is local to the cluster. The Keystone endpoint is on the
// management network, the catalog it returns names services on the same
// network, and nothing in this path reaches the internet — which is what an
// air-gapped install requires.
package openstack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// CredentialFileName is the operator-configured credential, beside the
// enrollment identity and the action level in the agent's configuration
// directory.
//
// Same directory and same custody as the private key, for the same reason:
// it is per-cluster state the customer's operator owns, already exists with
// enforced modes, and needs no new distribution mechanism.
const CredentialFileName = "openstack-credential.json"

// Credential is an OpenStack application credential and where to redeem it.
//
// An application credential rather than a user password, and it is worth
// saying why, because this choice sets the pattern for every backend after it
// — Rancher will need its own, and the same argument will apply.
//
//   - It is scoped to one project at creation time. The agent cannot create
//     in another project because it cannot ask to: there is no project field
//     in the request, and the token it gets back carries the scope the
//     operator chose.
//   - It carries only the roles the operator granted it, so "may create a
//     server" need not imply "may delete the cluster's networks".
//   - It is revocable on its own, without changing anyone's password and
//     without disturbing any other integration.
//   - It is issued by the operator, in their own Keystone, on their own
//     cluster. Nothing about it depends on Bigstack, which is what makes it
//     work on an air-gapped install.
//
// The secret is read from disk into this struct and handed to Keystone. It is
// never logged, never returned in an error, and never put in an audit record;
// String is defined below to make the accidental case impossible rather than
// merely discouraged.
type Credential struct {
	// AuthURL is the cluster's Keystone, e.g. https://10.0.0.1:5000/v3.
	AuthURL string `json:"auth_url"`
	// ID and Secret are the application credential's.
	ID     string `json:"application_credential_id"`
	Secret string `json:"application_credential_secret"`
	// Project is what the operator says this credential is scoped to. It is
	// not sent anywhere: it is checked against the scope Keystone reports, so
	// a credential that turns out to be scoped somewhere else is refused
	// rather than quietly creating in a project nobody chose.
	Project string `json:"project"`
	// CACertPEM optionally trusts the cluster's own CA. Empty means the host
	// trust store, which is the normal case on a CubeCOS node.
	CACertPEM string `json:"ca_cert_pem,omitempty"`
}

// String redacts. A Credential reaching a log line by way of %v or %+v is the
// mistake this prevents; the fields that matter are unexported nowhere, so the
// only defence that survives refactoring is this one.
func (c Credential) String() string {
	return fmt.Sprintf("openstack.Credential{AuthURL:%q, ID:%q, Project:%q, Secret:REDACTED}",
		c.AuthURL, c.ID, c.Project)
}

// GoString redacts under %#v too.
func (c Credential) GoString() string { return c.String() }

// ErrNoCredential is returned when no credential file exists.
//
// Distinguished from a malformed one because they are different operator
// problems: one is configuration not yet done, the other is configuration
// done wrongly. Both refuse; only the second is worth shouting about at
// startup.
var ErrNoCredential = fmt.Errorf("no OpenStack credential is configured")

// ReadCredential loads the credential from dir.
//
// Absent is ErrNoCredential and not a failure: an agent with no credential is
// the ordinary state of every cluster that has not opted in, and it refuses
// writes cleanly rather than refusing to start.
//
// A group- or world-writable file is refused outright. Unlike the action
// level, which is policy anyone may read, this holds a secret — so mode is
// checked in both directions: anyone who can write it can redirect the agent
// at their own Keystone, and anyone who can read it holds the credential.
func ReadCredential(dir string) (Credential, error) {
	path := filepath.Join(dir, CredentialFileName)

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return Credential{}, ErrNoCredential
	}
	if err != nil {
		return Credential{}, fmt.Errorf("openstack: stat %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return Credential{}, fmt.Errorf(
			"openstack: %s has mode %04o; it must be readable and writable by its owner alone — it holds an application credential secret",
			path, perm)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return Credential{}, fmt.Errorf("openstack: read %s: %w", path, err)
	}

	var c Credential
	if err := json.Unmarshal(b, &c); err != nil {
		// The error is not wrapped with the content: a JSON syntax error can
		// quote the line it failed on, and that line may be the secret.
		return Credential{}, fmt.Errorf("openstack: %s is not valid JSON", path)
	}

	for _, f := range []struct {
		name, value string
	}{
		{"auth_url", c.AuthURL},
		{"application_credential_id", c.ID},
		{"application_credential_secret", c.Secret},
		{"project", c.Project},
	} {
		if f.value == "" {
			return Credential{}, fmt.Errorf("openstack: %s has no %s; a half-configured credential creates nothing", path, f.name)
		}
	}
	return c, nil
}
