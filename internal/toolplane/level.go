package toolplane

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LevelFileName is the file in the agent's own directory that names this
// cluster's action level (ADR 0011). It sits beside the enrollment identity
// because that directory already exists per cluster, is owned by the customer,
// and already has its modes enforced — so the authoritative level needs no new
// distribution mechanism and arrives with the same custody as the key.
const LevelFileName = "action-level"

// Level names how far the SaaS may go on this cluster.
//
// It mirrors the Advisor's vocabulary (cube-ai-advisor internal/actionlevel).
// These words are a recorded format, so ParseLevel must accept exactly what
// String produces. The values start at 1 so the zero value is "unset".
type Level int

const (
	// The Advisor caps what it remembers by these levels (ADR 0019); the agent
	// only reports the word.
	LevelObserve Level = iota + 1
	LevelOperate
	LevelInternal
)

// DefaultLevel is what this agent serves when the cluster has said nothing.
// ADR 0011's "unset means observe", named so the fail-closed choice is
// greppable rather than inferred from a zero value.
const DefaultLevel = LevelObserve

func (l Level) String() string {
	switch l {
	case LevelObserve:
		return "observe"
	case LevelOperate:
		return "operate"
	case LevelInternal:
		return "internal"
	}
	return fmt.Sprintf("level(%d)", int(l))
}

// ParseLevel reads a recorded level, returning DefaultLevel alongside any
// error so a caller that logs and continues continues at the most restrictive
// level rather than an invalid one.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "observe":
		return LevelObserve, nil
	case "operate":
		return LevelOperate, nil
	case "internal":
		return LevelInternal, nil
	}
	return DefaultLevel, fmt.Errorf("toolplane: %q is not an action level; expected observe, operate or internal", s)
}

// ReadLevel reads the cluster's action level from dir.
//
// Three absences are not errors, and all three answer DefaultLevel: no file,
// an empty file, and a file of whitespace. Nobody expressed an intent in any of
// them — an empty file is what a half-finished write leaves — and the answer
// they get is the restrictive one, so treating them as configuration would add
// noise without adding safety. This mirrors LoadServer in internal/identity,
// where a missing file means "not configured yet" rather than "broken".
//
// A word that is not a level *is* an error, and the loudest thing this function
// can do is return one. Someone wrote something meaning something and it is not
// being honoured: a cluster whose file says "operator" is serving reads while
// its operator believes otherwise, and silence there is the failure mode a
// level exists to prevent. The value returned alongside is still DefaultLevel,
// so a caller that mishandles the error is mishandling it safely.
//
// A file others may write is refused for the same reason the private key's mode
// is: this is a control, and a control any local account can raise is not one.
// Readability is deliberately not constrained — the level is a policy statement
// the customer should be able to inspect, not a secret.
func ReadLevel(dir string) (Level, error) {
	path := filepath.Join(dir, LevelFileName)
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return DefaultLevel, nil
	}
	if err != nil {
		return DefaultLevel, fmt.Errorf("toolplane: stat %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return DefaultLevel, fmt.Errorf(
			"toolplane: %s has mode %04o; it must not be group- or world-writable — anyone who can write it can raise this cluster's action level",
			path, perm)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return DefaultLevel, fmt.Errorf("toolplane: read %s: %w", path, err)
	}
	word := strings.TrimSpace(string(b))
	if word == "" {
		return DefaultLevel, nil
	}
	l, err := ParseLevel(word)
	if err != nil {
		return DefaultLevel, fmt.Errorf("%s: %w", path, err)
	}
	return l, nil
}
