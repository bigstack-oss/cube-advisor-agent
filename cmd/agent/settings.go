package main

import (
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
//
// Empty today: the action level and consent are the Advisor's record alone,
// and the node's old action-level and consent files are not read.
var settings = []setting{}

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
