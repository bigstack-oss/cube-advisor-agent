package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
)

// exitConfigBroken says a setting an operator wrote could not be honoured, as
// distinct from exitFailed, which says the check itself could not run.
//
// The two want different actions — correct a file, versus report a bug — and
// an installer that can only see "non-zero" has to parse messages to tell
// them apart, which is how messages become an interface nobody meant to
// define.
const exitConfigBroken = 6

// configCmd is `advisor-agent config <subcommand>`.
func configCmd(args []string) int {
	if len(args) < 1 {
		configUsage()
		return exitUsage
	}
	switch args[0] {
	case "check":
		return configCheckCmd(args[1:])
	default:
		configUsage()
		return exitUsage
	}
}

func configUsage() {
	fmt.Fprintf(os.Stderr, `cube-advisor-agent config

  check [-dir <path>] [-probes]   report what each setting resolves to
`)
}

// configCheckCmd answers "is this cluster configured the way I meant?" before
// anything starts (ADR 0016).
//
// It calls configure — the function run calls — and reads no operator
// configuration itself. A second validator would be this design's own defect
// one level up: the settings list would have two readers, and the one nobody
// ran would drift from the one that decides.
//
// It never loads the identity, dials the tunnel, or builds an agent.Server, so
// it answers on a node that has not enrolled and cannot start serving by
// accident. The imports of this file are the short version of that argument,
// and TestConfigCheckStartsNothing asserts them.
func configCheckCmd(args []string) int {
	fs := flag.NewFlagSet("config check", flag.ContinueOnError)
	dir := fs.String("dir", identity.DefaultDir,
		"the agent directory whose settings to check; a staging copy is checked by pointing this at it")
	probes := fs.Bool("probes", false,
		"check what `run -probes` would serve: the probe plane changes the tool count, not any setting")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	// Mirrors run's own probe option so the tool count answers for the agent
	// the operator will actually start. Building a ProbeRunner validates the
	// probe list and touches nothing else; the sweeper that does touch scratch
	// is started by run, separately, and never here.
	var opts []toolplane.Option
	if *probes {
		runner, err := toolplane.NewProbeRunner(toolplane.Probes, checkAuditor())
		if err != nil {
			fmt.Fprintf(os.Stderr, "config check: %v\n", err)
			return exitFailed
		}
		opts = append(opts, toolplane.WithProbes(runner))
	}

	reg, states, err := configure(*dir, toolplane.Allowlist, checkAuditor(), opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config check: %v\n", err)
		return exitFailed
	}

	// The same lines run prints at startup, because they are the same states.
	// They go to stdout here and to stderr there: in run they are log context
	// beside everything else the process says, and here they are the answer.
	var broken []string
	for i, st := range states {
		fmt.Println(st.line)
		if st.broken {
			broken = append(broken, settings[i].name)
		}
	}
	fmt.Println(summaryLine(reg))

	if len(broken) > 0 {
		fmt.Fprintf(os.Stderr, "config check: %s broken (%s); the agent would start and refuse what they enable\n",
			plural(len(broken), "setting is", "settings are"), strings.Join(broken, ", "))
		return exitConfigBroken
	}
	fmt.Println(uncheckedNotice)
	return exitOK
}

// uncheckedNotice is printed on success because "every setting is fine" is a
// narrower claim than it reads as.
//
// The line ADR 0016 drew is syntactic at load, semantic at use: these files
// parse, their modes are safe and their values are well-formed, but whether a
// flavour id exists on this cloud needs the credential and a network call, and
// a checker that sometimes talks to a cluster is a different tool with
// different failure modes — one an operator learns to ignore the first time it
// fails because the cloud was busy.
const uncheckedNotice = "checked: every file parses, its mode is safe and its values are well-formed. " +
	"Not checked: that these ids exist on this cluster, that the credential redeems, " +
	"or that the api answers — the first create and the first read are what prove those."

// checkAuditor is the auditor a check builds its registry with.
//
// A check serves no tool call, so nothing is ever written. A FileAuditor would
// create or open the audit log, which is a change made by a command whose
// whole purpose is to change nothing.
func checkAuditor() toolplane.Auditor {
	return toolplane.NewWriterAuditor(discardWriteCloser{io.Discard})
}

type discardWriteCloser struct{ io.Writer }

func (discardWriteCloser) Close() error { return nil }

// summaryLine is what this agent would serve, for run's startup log and for a
// check's last line. One formatting, so the two cannot describe the same
// registry differently.
func summaryLine(reg *toolplane.Registry) string {
	return fmt.Sprintf("action level %s; serving %d tool(s)", reg.Level(), len(reg.Names()))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
