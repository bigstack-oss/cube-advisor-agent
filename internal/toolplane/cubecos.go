package toolplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// CubeCOSFileName is the file in the agent's own directory that says where this
// node's cube-cos-api is and which datacenter to ask it about (ADR 0016,
// slice 4). Beside the action level, the instance profile and the enrollment
// identity, for the reason that directory holds all of them.
const CubeCOSFileName = "cube-cos-api.json"

// ErrNoCubeCOS is returned when no cube-cos-api file exists.
//
// Distinguished from a malformed one for the same reason ErrNoProfile and
// ErrNoCredential are: configuration not yet done and configuration done
// wrongly are different operator problems, and only the second is worth
// shouting about at startup.
var ErrNoCubeCOS = fmt.Errorf("no cube-cos-api access is configured")

// CubeCOSAccess is where this node's cube-cos-api is and what to call the
// cluster when asking it.
//
// Writing the file is the opt-in: an agent without one reads nothing from the
// management API, which is the ordinary state of a cluster that has not asked
// for it. That is deliberate rather than incidental — enrolling an agent and
// granting it the cluster's own inventory are different decisions, and the
// second should be one an operator makes on purpose.
type CubeCOSAccess struct {
	// Datacenter fills {dc} in every catalogue path. cube-cos-api calls it
	// the hostname on a single node and the cubesys controller on an HA
	// cluster, so it is not something this agent can derive without reaching
	// for hex_sdk — the internal path the runbook rule keeps it out of.
	Datacenter string
	// BaseURL is this node's own api. cube-cos-api binds its management ip
	// rather than loopback or 0.0.0.0, so there is no address this agent
	// could assume; and pointing it at another node's api would send a token
	// minted for this hostname, which that api would reject.
	BaseURL string
}

// cubeCOSFile is the on-disk shape, stated once here rather than as tags on a
// type that also travels through the registry.
type cubeCOSFile struct {
	Datacenter string `json:"datacenter"`
	BaseURL    string `json:"base_url"`
}

// ReadCubeCOSAccess loads cube-cos-api access from dir.
//
// A group- or world-writable file is refused, and readability deliberately is
// not. The file holds no secret — a datacenter name and a URL on the customer's
// own management network — but whoever can write it chooses where this agent
// sends the node token, and a token posted to an attacker's listener is the
// whole of the node's api authority. That is the instance profile's rule and
// the same argument: write access is the escalation, read access reveals
// nothing.
//
// Unknown fields are rejected rather than ignored, so "dataCenter" or "baseUrl"
// — both plausible, both wrong — fail loudly at startup instead of leaving a
// field empty and refusing every read for a reason the operator cannot see in
// their own file.
func ReadCubeCOSAccess(dir string) (CubeCOSAccess, error) {
	path := filepath.Join(dir, CubeCOSFileName)

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return CubeCOSAccess{}, ErrNoCubeCOS
	}
	if err != nil {
		return CubeCOSAccess{}, fmt.Errorf("toolplane: stat %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return CubeCOSAccess{}, fmt.Errorf(
			"toolplane: %s has mode %04o; it must not be group- or world-writable — anyone who can write it chooses where this agent sends its node token",
			path, perm)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return CubeCOSAccess{}, fmt.Errorf("toolplane: read %s: %w", path, err)
	}

	var f cubeCOSFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return CubeCOSAccess{}, fmt.Errorf("toolplane: %s: %v", path, err)
	}

	for _, field := range []struct{ name, value string }{
		{"datacenter", f.Datacenter},
		{"base_url", f.BaseURL},
	} {
		if field.value == "" {
			return CubeCOSAccess{}, fmt.Errorf(
				"toolplane: %s has no %s; half-configured api access reads nothing", path, field.name)
		}
	}

	return CubeCOSAccess{Datacenter: f.Datacenter, BaseURL: f.BaseURL}, nil
}

// Datacenter is what this registry fills into {dc}, empty when cube-cos-api
// access is not configured.
//
// ConfigureCubeCOS's observable counterpart, for the reason Writers and Profile
// exist: without it, a datacenter on disk reaching this registry is visible
// only by performing a read against a real management api, so nothing could
// assert the wiring without a network — which is how ConfigureCubeCOS shipped
// documented, tested and never called.
func (r *Registry) Datacenter() string { return r.datacenter }

// errNoCubeCOSAccess is what a read gets when nothing configured this agent's
// api access.
//
// Stated once because three call sites need it — the default getter, the
// catalogue read and the templated read — and three copies of a message is
// three places for one of them to stop naming the file. Naming it is the
// difference between a refusal an operator can read and one they can act on,
// which is the argument executorFilled already makes for {flavor}.
func errNoCubeCOSAccess() error {
	return fmt.Errorf("cube-cos-api access is not configured on this agent; write %s to enable it", CubeCOSFileName)
}
