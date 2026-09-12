package main

import (
	"errors"
	"fmt"

	"github.com/bigstack-oss/cube-advisor-agent/internal/cubecosapi"
	"github.com/bigstack-oss/cube-advisor-agent/internal/openstack"
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
var settings = []setting{actionLevel, consentDial, cubeCOSAccess, instanceProfile, openStackCredential}

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
// The line says what the setting means as well as what it is, because one of
// the three values currently means something an operator would not guess:
// destructive asks only about tools that declare themselves so, and no tool in
// this allowlist does. A cluster set to destructive acts unattended today. That
// is a trap worth one clause at startup rather than a discovery later.
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
		st.line = fmt.Sprintf("consent: %s%s", c, consentCaveat(c))
		return st
	},
}

// consentCaveat names the gap between what a value promises and what this build
// can deliver.
//
// Only destructive has one, and only while no tool declares itself destructive.
// When one does this returns nothing and the line is just the value — which is
// the point of computing it from the allowlist rather than writing the caveat
// into the string: it disappears on its own when it stops being true, instead
// of becoming the next comment that outlived its subject.
func consentCaveat(c toolplane.Consent) string {
	if c == toolplane.ConsentDestructive && !toolplane.DestructiveToolsExist() {
		return " — but no tool in this build declares itself destructive, so nothing will be asked about"
	}
	return ""
}

// cubeCOSAccess is where this node's cube-cos-api is and what to call the
// cluster when asking it (ADR 0016, slice 4).
//
// Absent is the ordinary state and not an error: the read catalogue's 21 paths
// refuse, naming the file that would enable them. Enrolling an agent and
// granting it the cluster's own inventory are separate decisions, so this one
// is made by writing a file rather than by enrolling.
//
// The client is built here rather than inside toolplane because the base URL
// and the node token are its own: the getter interface exists precisely so
// neither reaches the package that writes the audit log.
var cubeCOSAccess = setting{
	name: "cube-cos-api access",
	file: toolplane.CubeCOSFileName,
	load: func(dir string) settingState {
		access, err := toolplane.ReadCubeCOSAccess(dir)
		switch {
		case errors.Is(err, toolplane.ErrNoCubeCOS):
			return settingState{line: "cube-cos-api access: not configured; reads will refuse until it is"}
		case err != nil:
			return settingState{
				broken: true,
				line:   fmt.Sprintf("cube-cos-api access: %v; reads will refuse until it is corrected", err),
			}
		}
		client, err := cubecosapi.New(access.BaseURL)
		if err != nil {
			return settingState{
				broken: true,
				line:   fmt.Sprintf("cube-cos-api access: %v; reads will refuse until it is corrected", err),
			}
		}
		return settingState{
			line: fmt.Sprintf("cube-cos-api access: datacenter %s at %s", access.Datacenter, access.BaseURL),
			apply: func(r *toolplane.Registry) {
				r.ConfigureCubeCOS(access.Datacenter, client)
			},
		}
	},
}

// instanceProfile is what this cluster creates: flavour, image and network
// (ADR 0016, slice 3).
//
// Absent is the ordinary state and not an error — a cluster that has not opted
// in creates nothing, and says which file would change that. A file the
// operator wrote and this agent cannot honour is broken and not applied, so a
// half-configured profile creates nothing rather than something half-chosen:
// the empty field would otherwise reach the resolver, which refuses anyway,
// but one loud line at startup beats the same refusal discovered per call.
var instanceProfile = setting{
	name: "instance profile",
	file: toolplane.ProfileFileName,
	load: func(dir string) settingState {
		profile, err := toolplane.ReadInstanceProfile(dir)
		switch {
		case errors.Is(err, toolplane.ErrNoProfile):
			return settingState{line: "instance profile: not configured; creates will refuse until one is"}
		case err != nil:
			return settingState{
				broken: true,
				line:   fmt.Sprintf("instance profile: %v; creates will refuse until it is corrected", err),
			}
		}
		return settingState{
			line: fmt.Sprintf("instance profile: flavor %s, image %s, network %s",
				profile.Flavor, profile.Image, profile.Network),
			apply: func(r *toolplane.Registry) { r.ConfigureInstanceProfile(profile) },
		}
	},
}

// openStackCredential is the application credential creates are made with.
//
// Absent is the ordinary state of every cluster that has not opted in: it
// refuses creates with a message naming the missing configuration, which is a
// different refusal from the action level's and says so. Wired only when
// present, so opting in is writing a file.
var openStackCredential = setting{
	name: "OpenStack credential",
	file: openstack.CredentialFileName,
	load: func(dir string) settingState {
		cred, err := openstack.ReadCredential(dir)
		switch {
		case errors.Is(err, openstack.ErrNoCredential):
			return settingState{line: "OpenStack credential: not configured; creates will refuse until one is"}
		case err != nil:
			return settingState{
				broken: true,
				line:   fmt.Sprintf("OpenStack credential: %v; creates will refuse until it is corrected", err),
			}
		}
		compute, err := openstack.NewCompute(cred)
		if err != nil {
			return settingState{
				broken: true,
				line:   fmt.Sprintf("OpenStack credential: %v; creates will refuse until it is corrected", err),
			}
		}
		return settingState{
			line: fmt.Sprintf("OpenStack credential: loaded for project %s", cred.Project),
			apply: func(r *toolplane.Registry) {
				r.ConfigureWriter(toolplane.BackendOpenStackCompute, compute)
			},
		}
	},
}

// configure builds the tool plane from the operator's configuration in dir.
//
// The one path every setting takes. run calls it and reads no operator
// configuration itself; `config check` will call the same function, because a
// second validator would be this design's own defect one level up.
//
// extra carries options that are not operator configuration — the probe plane,
// which a flag enables.
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
