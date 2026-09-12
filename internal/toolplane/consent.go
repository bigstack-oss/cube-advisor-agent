package toolplane

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConsentFileName is the file in the agent's own directory that says how much
// this cluster asks a person before acting (ADR 0011, amended).
//
// Beside the action level, and for the same reasons: the directory already
// exists per cluster, is owned by the customer, and has its modes enforced. The
// two dials are separate files rather than one because they are separate
// decisions — an operator raising what the assistant may do and an operator
// deciding when to be asked are different acts, and a single file would make
// changing one a rewrite of both.
const ConsentFileName = "consent"

// Consent names how much this cluster asks a person before a call runs.
//
// It mirrors the SaaS-side vocabulary (cube-ai-advisor internal/consent),
// declared here independently for the reason Level and Impact are: this side is
// the enforcement, and a compromised SaaS is the case this package exists to
// survive. Like Level, these words *are* a recorded format — the file below
// holds one — so ParseConsent must accept exactly what String produces.
//
// The values ascend by how much they ask, and that ordering is a scale: every
// value differs from its neighbour only in how many calls reach a human. Unlike
// Level and Impact, comparing them is meaningful — though nothing here needs
// to, because the fold lives in the SaaS where the tenant chain is known.
type Consent int

const (
	// ConsentNever asks nobody. The cluster acts within its action level
	// unattended.
	ConsentNever Consent = iota + 1
	// ConsentDestructive asks only for calls whose tool declares itself
	// destructive. No tool in this allowlist does, so today this asks for
	// nothing — see DestructiveToolsExist.
	ConsentDestructive
	// ConsentAlways asks for every call above a read. What an unconfigured
	// cluster gets.
	ConsentAlways
)

// DefaultConsent is what this agent requires when the cluster has said nothing.
// ADR 0011's "unset means always", named so the fail-closed choice is greppable
// rather than inferred from a zero value.
const DefaultConsent = ConsentAlways

func (c Consent) String() string {
	switch c {
	case ConsentNever:
		return "never"
	case ConsentDestructive:
		return "destructive"
	case ConsentAlways:
		return "always"
	}
	return fmt.Sprintf("consent(%d)", int(c))
}

// ParseConsent reads a recorded value, returning DefaultConsent alongside any
// error so a caller that logs and continues continues asking for everything
// rather than at an invalid setting.
func ParseConsent(s string) (Consent, error) {
	switch s {
	case "never":
		return ConsentNever, nil
	case "destructive":
		return ConsentDestructive, nil
	case "always":
		return ConsentAlways, nil
	}
	return DefaultConsent, fmt.Errorf("toolplane: %q is not a consent setting; expected never, destructive or always", s)
}

// Asks reports whether this setting requires a person to have agreed before a
// call of the given class runs.
//
// A read never asks whatever the setting says: there is nothing to agree to.
// Above that the setting decides, and an unrecognised one asks — the same
// defence ParseConsent makes by returning the default, repeated here because a
// value could reach this function without passing through that one.
func (c Consent) Asks(i Impact, destructive bool) bool {
	if i == ImpactRead {
		return false
	}
	switch c {
	case ConsentNever:
		return false
	case ConsentDestructive:
		return destructive
	case ConsentAlways:
		return true
	}
	return true
}

// ReadConsent reads the cluster's consent setting from dir.
//
// Absent, empty and whitespace all mean DefaultConsent and are not errors, for
// the reason ReadLevel gives: nobody expressed an intent, an empty file is what
// a half-finished write leaves, and the answer they get is the cautious one.
//
// A word that is not a setting *is* an error, and loudly. An operator who wrote
// "none" meaning "never" has a cluster that asks about everything while they
// believe it asks about nothing — the reverse of the level's failure, and just
// as much a surprise. The value returned alongside is still DefaultConsent.
//
// A file others may write is refused, for a sharper reason than the level's:
// whoever can write this file can stop a cluster asking a person before it
// acts. Readability is deliberately unconstrained — like the level this is a
// policy statement its customer should be able to read without root, and it
// holds no secret.
func ReadConsent(dir string) (Consent, error) {
	path := filepath.Join(dir, ConsentFileName)
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return DefaultConsent, nil
	}
	if err != nil {
		return DefaultConsent, fmt.Errorf("toolplane: stat %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return DefaultConsent, fmt.Errorf(
			"toolplane: %s has mode %04o; it must not be group- or world-writable — anyone who can write it can stop this cluster asking a person before it acts",
			path, perm)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return DefaultConsent, fmt.Errorf("toolplane: read %s: %w", path, err)
	}
	word := strings.TrimSpace(string(b))
	if word == "" {
		return DefaultConsent, nil
	}
	c, err := ParseConsent(word)
	if err != nil {
		return DefaultConsent, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}
