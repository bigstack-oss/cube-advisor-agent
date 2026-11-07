package main

import (
	"fmt"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
)

// A setting is one thing the cluster's operator configures, as a file in the
// agent's own directory (ADR 0016).
//
// The list below is the whole set. configure walks it and nothing else reads
// operator configuration, so a setting absent from the list does not exist.
// That is the point: startup used to be a sequence of hand-written blocks
// where adding one was optional, and two settings that never got their block
// shipped documented, tested and unreachable.
type setting struct {
	// name is what an operator sees in the startup line.
	name string
	// file is the setting's file in the agent's directory, named in messages
	// so that "not configured" says which configuration.
	file string
	// load reads the setting from dir. It always returns a line, and returns
	// an opt or an apply when the setting is usable.
	load func(dir string) settingState
}

// settingState is what one setting resolved to.
type settingState struct {
	// line is the one startup line this setting owes, whatever happened: its
	// value, that it is not configured, or why it was rejected.
	line string
	// broken marks a setting an operator wrote that this agent could not
	// honour, as distinct from one they never wrote. Only the first is worth
	// shouting about.
	broken bool
	// opt applies the setting when the registry is built; apply applies it
	// afterwards. A setting uses whichever its target needs.
	opt   toolplane.Option
	apply func(*toolplane.Registry)
}

// settings is every per-cluster setting this agent reads. Adding one is adding
// an entry here, and there is no second place to forget.
var settings = []setting{actionLevel, consentDial}

// actionLevel is the cluster's own action level (ADR 0011).
//
// Read once at startup so a malformed value is one loud line rather than a
// mystery repeated per call. Absent, empty and whitespace all mean observe and
// are not errors; a word that is not a level is an error, and the level is
// still applied, because ReadLevel answers observe alongside it and serving
// reads beats refusing to start.
var actionLevel = setting{
	name: "action level",
	file: toolplane.LevelFileName,
	load: func(dir string) settingState {
		level, err := toolplane.ReadLevel(dir)
		st := settingState{opt: toolplane.WithLevel(level)}
		if err != nil {
			st.broken = true
			st.line = fmt.Sprintf("action level: %v; serving %s until it is corrected", err, level)
			return st
		}
		st.line = fmt.Sprintf("action level: %s", level)
		return st
	},
}

// consentDial is how much this cluster asks a person before acting
// (ADR 0011, amended).
//
// Read once at startup, like the level and for the same reason. Absent, empty
// and whitespace mean always and are not errors; a word that is not a setting
// is an error, and the setting is still applied because ReadConsent answers
// always alongside it — asking too much beats refusing to start.
//
// The agent reports it in the Hello; the Advisor applies it.
var consentDial = setting{
	name: "consent",
	file: toolplane.ConsentFileName,
	load: func(dir string) settingState {
		c, err := toolplane.ReadConsent(dir)
		st := settingState{opt: toolplane.WithConsent(c)}
		if err != nil {
			st.broken = true
			st.line = fmt.Sprintf("consent: %v; asking for %s until it is corrected", err, c)
			return st
		}
		st.line = fmt.Sprintf("consent: %s", c)
		return st
	},
}

// configure builds the tool plane from the operator's configuration in dir.
//
// The one path every setting takes. run calls it and reads no operator
// configuration itself; `config check` will call the same function, because a
// second validator would be this design's own defect one level up.
func configure(dir string, tools []toolplane.Tool, audit toolplane.Auditor, extra ...toolplane.Option) (*toolplane.Registry, []settingState, error) {
	states := make([]settingState, len(settings))
	opts := make([]toolplane.Option, 0, len(extra)+len(settings))
	opts = append(opts, extra...)
	for i, s := range settings {
		states[i] = s.load(dir)
		if states[i].opt != nil {
			opts = append(opts, states[i].opt)
		}
	}
	reg, err := toolplane.New(tools, audit, opts...)
	if err != nil {
		return nil, states, err
	}
	for _, st := range states {
		if st.apply != nil {
			st.apply(reg)
		}
	}
	return reg, states, nil
}
