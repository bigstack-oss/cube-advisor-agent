// Package toolplane serves the AI plane: read-only tools the SaaS may invoke
// over a tool channel.
//
// The allowlist below is enforced here, on the customer's cluster, and is the
// single artifact a security review needs to read. The SaaS validating a
// request first is a courtesy; this package refuses regardless of what the SaaS
// claims, because a compromised or prompt-injected SaaS is exactly the case it
// exists to survive.
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

import "fmt"

// Tool is one read-only operation the AI plane may invoke.
type Tool struct {
	// Name is what the SaaS asks for, matched exactly.
	Name string

	// Description is for the operator reading the allowlist, not the model.
	Description string

	// Argv is the exact command to run. Elements equal to a parameter
	// placeholder (see Params) are replaced; everything else is literal.
	// The first element is the executable — resolved from PATH, never a shell.
	Argv []string

	// Params declares each placeholder in Argv and the finite set of values it
	// accepts. A parameter with no declared values is a bug, not a wildcard:
	// Register rejects it.
	Params map[string][]string

	// ReadOnly must be true. It exists so that adding a mutating tool requires
	// deliberately writing `ReadOnly: false`, which Register then refuses —
	// the AI plane has no write path, and that should be hard to change by
	// accident.
	ReadOnly bool

	// MaxOutputBytes caps what a single call may return. Zero means the
	// registry default. A tool that can return a whole log file must not be
	// able to exhaust the node's memory.
	MaxOutputBytes int
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
		ReadOnly:    true,
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
		ReadOnly: true,
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
		ReadOnly:       true,
		MaxOutputBytes: 512 << 10,
	},
}

// validate checks a tool is well-formed for registration.
func (t Tool) validate() error {
	if t.Name == "" {
		return fmt.Errorf("tool has no name")
	}
	if !t.ReadOnly {
		return fmt.Errorf("tool %q is not declared read-only; the AI plane has no write path", t.Name)
	}
	if len(t.Argv) == 0 {
		return fmt.Errorf("tool %q has an empty argv", t.Name)
	}
	if isPlaceholder(t.Argv[0]) {
		return fmt.Errorf("tool %q parameterises its executable; the program to run must be literal", t.Name)
	}
	// Every placeholder in argv must be declared, and every declaration must be
	// used. An undeclared placeholder would be passed through literally; an
	// unused declaration means the allowlist no longer says what it does.
	seen := map[string]bool{}
	for _, a := range t.Argv {
		if !isPlaceholder(a) {
			continue
		}
		if _, ok := t.Params[a]; !ok {
			return fmt.Errorf("tool %q uses %s but does not declare it", t.Name, a)
		}
		seen[a] = true
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

// isPlaceholder reports whether an argv element is a parameter slot.
func isPlaceholder(s string) bool {
	return len(s) > 2 && s[0] == '{' && s[len(s)-1] == '}'
}
