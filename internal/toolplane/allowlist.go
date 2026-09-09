// Package toolplane serves the AI plane: today, read-only tools the SaaS may
// invoke over a tool channel.
//
// "Read-only" is the current state rather than a permanent property. ADR 0011
// gives each cluster an action level — observe / operate / internal — that
// decides which impact classes this side will serve, and the classes it will
// admit are already named below. Until a later slice reads that level, every
// configuring class is refused here, so the read-only description is accurate
// for what ships and wrong for what the package is becoming.
//
// The allowlist below is enforced here, on the customer's cluster, and is the
// single artifact a security review needs to read. The SaaS validating a
// request first is a courtesy; this package refuses regardless of what the SaaS
// claims, because a compromised or prompt-injected SaaS is exactly the case it
// exists to survive. That stays true when levels arrive: the authoritative
// level is the one on this node, and where the two disagree this side wins.
//
// Three properties hold together to bound the blast radius to "read health and
// logs":
//
//  1. Lookup is exact match. An unknown name is refused, never fuzzily resolved.
//  2. A tool declares the exact argv it runs; arguments are substituted only
//     into declared slots, and only from a declared value set. There is no
//     shell, so metacharacters are inert rather than filtered — filtering is a
//     blocklist, and blocklists are how these things go wrong.
//  3. Every call, allowed or refused, is written to a local append-only log the
//     customer can read.
package toolplane

import (
	"fmt"
	"strings"
	"time"
)

// Impact is what a tool does to the cluster it runs against. It mirrors the
// SaaS-side classification (cube-ai-advisor internal/tools), declared here
// independently because this side is the enforcement: the SaaS's copy is
// advice, and a compromised SaaS is the case this package exists to survive.
//
// The classes start at 1 so the zero value means "undeclared" and is refused —
// the boolean this replaced also refused its own zero value, and that property
// is what makes forgetting the field safe.
//
// The vocabulary is kept in step with the SaaS by hand, not by a shared type:
// nothing on the wire carries an impact, so there is no contract to check
// against. Changing a class here means changing cube-ai-advisor
// internal/tools/tools.go too, and the reverse.
type Impact int

const (
	// ImpactRead observes and changes nothing. Every allowlisted tool is
	// this today.
	ImpactRead Impact = iota + 1
	// ImpactScratch creates and destroys its own scratch resources, or
	// generates load, while touching no configuration — the probe class.
	// No tool declares it yet and Register refuses it until one does.
	ImpactScratch
	// ImpactOperate changes the cluster through an interface a supported
	// end-user path already exposes — the UI, the public API, or hex_cli.
	// Never served today; ADR 0011's per-cluster action level is what will
	// admit it, and that level is read from this node, not from the SaaS.
	ImpactOperate
	// ImpactInternal changes the cluster by reaching past those interfaces —
	// hex_sdk, a config file, a service internal. Never served today, and
	// the last class to be admitted. It does not mean free-form execution:
	// an allowlisted argv reaching an internal path is expressible here, a
	// caller-supplied command is not, and that stays true at every level.
	ImpactInternal
)

func (i Impact) String() string {
	switch i {
	case 0:
		return "undeclared"
	case ImpactRead:
		return "read"
	case ImpactScratch:
		return "scratch"
	case ImpactOperate:
		return "operate"
	case ImpactInternal:
		return "internal"
	}
	return fmt.Sprintf("impact(%d)", int(i))
}

// ControlOp identifies a built-in probe-plane operation. Like Impact it starts
// at 1, so a tool that sets nothing is not accidentally a control tool.
type ControlOp int

const (
	// ControlProbeStart begins a probe run and returns its id.
	ControlProbeStart ControlOp = iota + 1
	// ControlProbeStatus reports a run's state and, when finished, its metrics.
	ControlProbeStatus
)

func (c ControlOp) String() string {
	switch c {
	case ControlProbeStart:
		return "probe_start"
	case ControlProbeStatus:
		return "probe_status"
	}
	return fmt.Sprintf("control(%d)", int(c))
}

// Tool is one read-only operation the AI plane may invoke.
type Tool struct {
	// Name is what the SaaS asks for, matched exactly.
	Name string

	// Description is for the operator reading the allowlist, not the model.
	Description string

	// Argv is the exact command to run. Elements equal to a parameter
	// placeholder (see Params) are replaced; everything else is literal.
	// The first element is the executable — resolved from PATH, never a shell.
	//
	// Exactly one of Argv or Get is set: a tool is a local command or a
	// cube-cos-api read, never both.
	Argv []string

	// Control names a built-in operation of the probe plane rather than a
	// command or a read. A control tool substitutes nothing into a command
	// line — it hands its argument to the probe runner, which checks it
	// against the probes it serves or the runs it has started — so the
	// finite-value-set rule that guards argv substitution does not apply and
	// would be theatre if it did. What guards a control tool instead is that
	// its argument reaches no execve: a probe name is a map lookup, and a run
	// id is one this process generated.
	//
	// Exactly one of Argv, Get or Control is set.
	Control ControlOp

	// Get is a cube-cos-api path template for a read-only HTTP GET, e.g.
	// "/api/v1/datacenters/{dc}/healths". The method is GET, always — there is
	// no field to make it anything else, so a write to the management API is
	// not expressible in this allowlist.
	//
	// {dc} is the agent's own datacenter, filled by the executor from its
	// configuration — never a model parameter, so the SaaS cannot point a read
	// at another cluster. Every other placeholder is a model parameter and must
	// be declared in Params, exactly like Argv.
	Get string

	// Params declares each placeholder in Argv or Get and the finite set of
	// values it accepts. A parameter with no declared values is a bug, not a
	// wildcard: Register rejects it. {dc} is never declared here — it is
	// executor context, not a caller argument.
	Params map[string][]string

	// Impact declares what this tool does to the cluster. It must be
	// ImpactRead today, or ImpactScratch where a probe plane is wired;
	// Register refuses every other class, and refuses the zero value too, so
	// a tool that declares nothing is not served. The AI plane has no write
	// path, and gaining one should take a deliberate edit here and a cluster
	// that asked for it — ADR 0011 — rather than a field somebody filled in
	// differently.
	Impact Impact

	// MaxOutputBytes caps what a single call may return. Zero means the
	// registry default. A tool that can return a whole log file must not be
	// able to exhaust the node's memory.
	MaxOutputBytes int

	// Timeout bounds one execution of this tool. Zero means the registry
	// default. It must stay under the server's per-call cap (and, with margin,
	// under the SaaS's channel deadline): the timeout that fires must be THIS
	// one, so the model receives the executor's honest "tool timed out" result
	// instead of a SaaS-side channel error it can only guess about.
	Timeout time.Duration
}

// Allowlist is the complete set of tools the agent will serve.
//
// Adding an entry here is the security-relevant act. Keep it short, keep every
// argv literal, and keep every parameter's value set finite.
var Allowlist = []Tool{
	{
		Name:        "cluster_check",
		Description: "Cluster-wide health check: every service group and its status.",
		Argv:        []string{"hex_cli", "-c", "cluster", "-c", "check"},
		Impact:      ImpactRead,
		// ~55s measured on a healthy 3-node cluster (cube-ai-advisor#52 lab
		// run); the old 60s default left 8% headroom. 100s keeps this the
		// first timeout to fire: under the server's 110s call cap, well under
		// the SaaS's 120s channel deadline.
		Timeout: 100 * time.Second,
	},
	{
		Name:        "cluster_health",
		Description: "Health detail for one service group.",
		Argv:        []string{"hex_cli", "-c", "cluster", "-c", "health", "{group}"},
		Params: map[string][]string{
			// The service groups `cluster check` reports. A group outside this
			// set is refused rather than passed through — the point is that the
			// SaaS cannot choose the argument, only select from what we allow.
			"{group}": {
				"ApiService", "Baremetal", "BlockStor", "BusinessLogic",
				"ClusterLink", "ClusterSettings", "ClusterSys", "Compute",
				"DataPipe", "DNSaaS", "FileStor", "HaCluster", "IaasDb",
				"Image", "InstanceHa", "K8SaaS", "LBaaS", "LogAnalytics",
				"Metrics", "MsgQueue", "Network", "Notifications",
				"ObjectStor", "Orchestration", "SingleSignOn", "Storage",
				"VirtualIp",
			},
		},
		Impact: ImpactRead,
	},
	{
		Name:        "service_log_tail",
		Description: "Last lines of one service's journal.",
		Argv:        []string{"journalctl", "-u", "{unit}", "-n", "{lines}", "--no-pager"},
		Params: map[string][]string{
			// Units the advisor may read. Deliberately narrow: this is the tool
			// most likely to be asked to widen, and widening it is how a
			// read-only plane starts reading things it should not.
			"{unit}": {
				"cube-cos-api", "hex_config", "hex_crashd", "pacemaker",
				"corosync", "mariadb", "rabbitmq-server", "ceph-mon@",
				"neutron-server", "nova-api", "keystone",
			},
			// Bounded line counts rather than a free integer, so the value set
			// stays finite and the cap is visible in the allowlist itself.
			"{lines}": {"50", "200", "1000"},
		},
		Impact:         ImpactRead,
		MaxOutputBytes: 512 << 10,
		// journalctl over a bounded line count is quick; a tail that takes
		// longer than this is a node problem the timeout should surface.
		Timeout: 30 * time.Second,
	},
	// cube-cos-api reads. GET only, structurally — the resolved path is the
	// whole request, and {dc} is filled by the executor, so the SaaS chooses
	// which overview to fetch and nothing else. Start with the three
	// zero-parameter overviews; per-resource reads (a named node, a service's
	// health) are added the same way once their value sets are pinned down.
	{
		Name:        "cube_cos_healths",
		Description: "Cluster health summary from cube-cos-api: every service and its state.",
		Get:         "/api/v1/datacenters/{dc}/healths",
		Impact:      ImpactRead,
	},
	{
		Name:        "cube_cos_nodes",
		Description: "The cluster's nodes and their roles/state from cube-cos-api.",
		Get:         "/api/v1/datacenters/{dc}/nodes",
		Impact:      ImpactRead,
	},
	{
		Name:        "cube_cos_events",
		Description: "Recent cluster events from cube-cos-api — the timeline of what changed.",
		Get:         "/api/v1/datacenters/{dc}/events",
		Impact:      ImpactRead,
	},
}

// ProbeControls is the probe plane's half of the allowlist, kept separate
// because it is served only by an agent that has a probe runner.
//
// New appends these itself when WithProbes is given, so enabling the plane and
// advertising it are one act: an agent cannot end up offering probe_start with
// nothing behind it, nor running a probe plane nobody can reach.
var ProbeControls = []Tool{
	// Both entries are short calls: starting a probe returns as soon as the
	// run is launched, and polling one is a map read. Neither holds a tunnel
	// channel open while a measurement runs, which is why the timeout ladder
	// did not have to grow to accommodate a 30-second fio.
	{
		Name: "probe_start",
		Description: "Start a bounded measurement that creates and deletes its own scratch " +
			"storage. Returns a run id immediately; poll probe_status for the result.",
		Control: ControlProbeStart,
		// Scratch class: starting a probe is the act that generates load.
		// Registration refuses this unless the agent was built with a probe
		// runner, so an executor without one advertises nothing it cannot do.
		Impact: ImpactScratch,
	},
	{
		Name:        "probe_status",
		Description: "State and, once finished, the parsed metrics of a probe run.",
		Control:     ControlProbeStatus,
		// Polling reads a result this process already has. It starts nothing
		// and touches no cluster resource, so it is a read even though the run
		// it reports on was not.
		Impact: ImpactRead,
	},
}

// dcPlaceholder is the one placeholder the executor fills from its own config
// rather than from a caller argument: the agent's datacenter.
const dcPlaceholder = "{dc}"

// validate checks a tool is well-formed for registration.
//
// probes reports whether this executor has a probe runner wired. Without one,
// the scratch class is refused exactly as it was before the probe plane
// existed: an agent that cannot run a probe must not advertise that it can.
func (t Tool) validate(probes bool) error {
	if t.Name == "" {
		return fmt.Errorf("tool has no name")
	}
	switch t.Impact {
	case ImpactRead:
		// Always served.
	case ImpactScratch:
		if !probes {
			return fmt.Errorf("tool %q declares impact scratch but this agent has no probe plane", t.Name)
		}
	case ImpactOperate, ImpactInternal:
		// Named rather than left to the default so the log distinguishes a
		// class this agent knows and will not serve from one it has never
		// heard of. When action levels arrive, this is the branch that
		// consults the level file; until then the answer is always no.
		return fmt.Errorf("tool %q declares impact %s; this agent serves no configuring class at any level yet", t.Name, t.Impact)
	default:
		return fmt.Errorf("tool %q declares impact %s; the AI plane serves reads and probes only", t.Name, t.Impact)
	}
	if t.Timeout < 0 {
		return fmt.Errorf("tool %q has a negative timeout", t.Name)
	}
	kinds := 0
	for _, set := range []bool{len(t.Argv) > 0, t.Get != "", t.Control != 0} {
		if set {
			kinds++
		}
	}
	if kinds != 1 {
		return fmt.Errorf("tool %q must be exactly one of a command (Argv), a cube-cos-api read (Get) or a probe-plane control (Control)", t.Name)
	}
	switch {
	case t.Control != 0:
		return t.validateControl()
	case t.Get != "":
		return t.validateGet()
	default:
		return t.validateCommand()
	}
}

// validateControl checks a probe-plane control entry.
//
// A control tool declares no Params: its argument is handed to the probe
// runner, which validates it against what it serves, and never substituted
// into anything. Declaring a value set here would suggest the argument is
// checked by this file when it is not, and a guard that looks stronger than
// it is is worse than no guard at all.
func (t Tool) validateControl() error {
	if len(t.Params) > 0 {
		return fmt.Errorf("tool %q is a control tool and must declare no parameters; its argument is checked by the probe runner, not substituted", t.Name)
	}
	if t.Control != ControlProbeStart && t.Control != ControlProbeStatus {
		return fmt.Errorf("tool %q declares an unknown control operation", t.Name)
	}
	return nil
}

func (t Tool) validateCommand() error {
	if isPlaceholder(t.Argv[0]) {
		return fmt.Errorf("tool %q parameterises its executable; the program to run must be literal", t.Name)
	}
	// Every placeholder in argv must be a declared model parameter, and every
	// declaration must be used. A command tool has no executor-filled slots.
	return t.checkPlaceholders(t.Argv, nil)
}

func (t Tool) validateGet() error {
	if !strings.HasPrefix(t.Get, "/") {
		return fmt.Errorf("tool %q GET path must be absolute", t.Name)
	}
	// {dc} is executor context, not a caller argument: it may appear in the
	// path without a Params declaration, and it must not be declared as one.
	if _, declared := t.Params[dcPlaceholder]; declared {
		return fmt.Errorf("tool %q declares %s; it is executor context, not a parameter", t.Name, dcPlaceholder)
	}
	return t.checkPlaceholders(pathSegments(t.Get), map[string]bool{dcPlaceholder: true})
}

// checkPlaceholders enforces that every placeholder in tokens is either an
// exempt executor slot or a declared model parameter, and that every declared
// parameter is used with a finite value set.
func (t Tool) checkPlaceholders(tokens []string, exempt map[string]bool) error {
	seen := map[string]bool{}
	for _, tok := range tokens {
		if !isPlaceholder(tok) {
			continue
		}
		if exempt[tok] {
			continue
		}
		if _, ok := t.Params[tok]; !ok {
			return fmt.Errorf("tool %q uses %s but does not declare it", t.Name, tok)
		}
		seen[tok] = true
	}
	for p, values := range t.Params {
		if !seen[p] {
			return fmt.Errorf("tool %q declares %s but never uses it", t.Name, p)
		}
		if len(values) == 0 {
			return fmt.Errorf("tool %q declares %s with no permitted values; a parameter is not a wildcard", t.Name, p)
		}
	}
	return nil
}

// pathSegments splits a GET path into its slash-separated segments, so a
// placeholder is matched as a whole segment and never as part of one.
func pathSegments(path string) []string {
	return strings.Split(strings.Trim(path, "/"), "/")
}

// isPlaceholder reports whether a token is a parameter slot.
func isPlaceholder(s string) bool {
	return len(s) > 2 && s[0] == '{' && s[len(s)-1] == '}'
}
