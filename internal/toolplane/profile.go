package toolplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ProfileFileName is the file in the agent's own directory that describes what
// this cluster creates (ADR 0011, ADR 0016). Beside the action level and the
// enrollment identity, for the reason that directory holds all of them: it is
// per-cluster state the customer's operator owns, already exists, and already
// has its modes enforced.
const ProfileFileName = "instance-profile.json"

// ErrNoProfile is returned when no profile file exists.
//
// Distinguished from a malformed one because they are different operator
// problems: one is configuration not yet done, the other is configuration done
// wrongly. Both refuse a create; only the second is worth shouting about at
// startup. Same split as ErrNoCredential.
var ErrNoProfile = fmt.Errorf("no instance profile is configured")

// profileFile is the on-disk shape. Separate from InstanceProfile so the JSON
// names are stated once, here, rather than as tags on a type that also travels
// through the resolver.
type profileFile struct {
	Flavor  string `json:"flavor"`
	Image   string `json:"image"`
	Network string `json:"network"`
	Project string `json:"project,omitempty"`
}

// ReadInstanceProfile loads the instance profile from dir.
//
// Absent is ErrNoProfile and not a failure: an agent with no profile is the
// ordinary state of every cluster that has not opted in, and it refuses creates
// cleanly rather than refusing to start.
//
// A group- or world-writable file is refused, and readability deliberately is
// not. This is the action level's rule rather than the credential's, and the
// asymmetry is the point: the profile holds no secret — flavour, image and
// network are ids of shared cloud resources, and an operator should be able to
// read what their own agent creates without root. But whoever can write it
// chooses the image, and choosing the image is choosing what code runs on the
// instance this agent will be asked to create. Write access is the escalation;
// read access reveals nothing.
//
// Unknown fields are rejected rather than ignored. The obvious typo here is
// "flavour" — the spelling this codebase's own prose uses — and ignoring it
// would leave the field empty, refusing every create with a message about a
// flavour the operator believes they configured.
func ReadInstanceProfile(dir string) (InstanceProfile, error) {
	path := filepath.Join(dir, ProfileFileName)

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return InstanceProfile{}, ErrNoProfile
	}
	if err != nil {
		return InstanceProfile{}, fmt.Errorf("toolplane: stat %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return InstanceProfile{}, fmt.Errorf(
			"toolplane: %s has mode %04o; it must not be group- or world-writable — anyone who can write it chooses the image this cluster boots",
			path, perm)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return InstanceProfile{}, fmt.Errorf("toolplane: read %s: %w", path, err)
	}

	var f profileFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return InstanceProfile{}, fmt.Errorf("toolplane: %s: %v", path, err)
	}

	for _, field := range []struct{ name, value string }{
		{"flavor", f.Flavor},
		{"image", f.Image},
		{"network", f.Network},
	} {
		if field.value == "" {
			return InstanceProfile{}, fmt.Errorf(
				"toolplane: %s has no %s; a half-configured profile creates nothing", path, field.name)
		}
	}

	return InstanceProfile{
		Flavor:  f.Flavor,
		Image:   f.Image,
		Network: f.Network,
		Project: f.Project,
	}, nil
}
