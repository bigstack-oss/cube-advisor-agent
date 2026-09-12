// Package toolplane serves the AI plane: the tools the SaaS may invoke over a
// tool channel, bounded by what this cluster said it allows.
//
// What it allows is a word in a file on this node (ADR 0011): observe serves
// reads, operate adds tools that change the cluster through a supported
// end-user interface, internal adds tools that reach past those. Unset means
// observe, so a cluster whose operator has said nothing serves reads only —
// which is every cluster until someone writes the file. The level is read at
// startup and applied to every call, and Names advertises only what it serves.
//
// The allowlist below is enforced here, on the customer's cluster, and is the
// single artifact a security review needs to read. The SaaS validating a
// request first is a courtesy; this package refuses regardless of what the SaaS
// claims, because a compromised or prompt-injected SaaS is exactly the case it
// exists to survive. That stays true when levels arrive: the authoritative
// level is the one on this node, and where the two disagree this side wins.
//
// Five properties hold together to bound what a call can do:
//
//  1. Lookup is exact match. An unknown name is refused, never fuzzily resolved.
//  2. A tool declares the exact argv it runs, or the exact path and body it
//     sends; arguments are substituted only into declared slots, and only from
//     a declared value set — or, where a value cannot be enumerated, a declared
//     Shape. There is no shell, so metacharacters are inert rather than
//     filtered — filtering is a blocklist, and blocklists are how these things
//     go wrong.
//  3. The cluster's own action level decides which impact classes are served,
//     and it is read from this node. The SaaS keeps a mirror to shape what it
//     offers the model; where the two disagree this side refuses.
//  4. A write cannot be repeated by a retry: an identical request inside a
//     short window is recognised by what it would do and answered from the
//     first one. A read costs nothing to repeat; a create costs an instance.
//  5. Every call — allowed, refused or suppressed as a replay — is written to a
//     local append-only log the customer can read.
package toolplane

import (
	"fmt"
	"strings"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
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

// Shape names a finite grammar for a parameter whose values cannot be
// enumerated in advance.
//
// A finite value set (Params) is the strong form and stays the default: the
// allowlist says every value a tool may be given, and a reviewer reads them.
// Creating a resource breaks that, because a name is chosen by the person
// asking and no list written today contains it.
//
// The answer is a *closed vocabulary of shapes*, not a pattern field. A pattern
// field would let a future entry write ".*", which is precisely the wildcard
// Params already refuses as a bug; a shape cannot express a wildcard unless
// someone adds one to this file, and adding one is the reviewable act. Each
// shape is defined once, tested once, and named at the call site, so the
// question a reviewer asks stays "which shape?" and never "what does this
// regexp admit?".
//
// Every shape must, at minimum: reject the empty string, bound the length,
// exclude shell metacharacters (inert here, since there is no shell, but a
// value that leaves this process may reach one), exclude "/" and "." so a value
// cannot compose a path segment or escape one, and reject a leading "-" so a
// value cannot be read as a flag by the program it is passed to. That last one
// is the argument-injection case, and a finite value set made it impossible for
// free.
type Shape int

const (
	// ShapeDNSLabel is a single DNS label: lowercase letters, digits and
	// interior hyphens, 1-63 characters, starting and ending alphanumeric.
	// OpenStack, Kubernetes and DNS all accept it as a name, so a value this
	// shape admits is one every layer downstream can hold.
	ShapeDNSLabel Shape = iota + 1
)

func (s Shape) String() string {
	switch s {
	case ShapeDNSLabel:
		return "dns-label"
	}
	return fmt.Sprintf("shape(%d)", int(s))
}

// maxDNSLabel is the DNS limit, and doubles as the length bound.
const maxDNSLabel = 63

// catalogArg is the one argument a catalogue read takes: which entry to fetch.
// Named once here rather than written as a literal in the registry and again
// in the SaaS's schema, because the two have to agree and a string typed twice
// is a string that eventually differs.
const catalogArg = "resource"

// admits reports whether v satisfies the shape.
//
// Written as explicit character classes rather than a compiled regexp, so the
// grammar is readable in the same file as the rule it enforces and there is no
// pattern string a later edit could quietly widen.
func (s Shape) admits(v string) bool {
	switch s {
	case ShapeDNSLabel:
		if v == "" || len(v) > maxDNSLabel {
			return false
		}
		for i := 0; i < len(v); i++ {
			c := v[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			case c == '-' && i > 0 && i < len(v)-1:
			default:
				return false
			}
		}
		return true
	}
	// A shape this build does not know admits nothing, for the same reason an
	// unrecognised impact is refused: absence of a rule is not permission.
	return false
}

// Backend names the API a Get or Post is addressed to.
//
// It exists because a cluster's resources do not all live behind one API.
// cube-cos-api serves the appliance — nodes, health, events, images, volumes —
// and knows nothing of virtual machines, which are nova's. A tool therefore has
// to say where it is going, and the executor has to hold one client per
// destination.
//
// The zero value is cube-cos-api, so every tool written before this existed
// keeps its destination without restating it, and a new tool that forgets to
// say lands on the management API rather than somewhere it could create
// something.
//
// Deliberately a small enum rather than an interface. There are two
// destinations today and a third is foreseen — k8s clusters are Rancher's —
// but an abstraction designed against one real case and two imagined ones is
// worse than a second concrete case later. What this must not do is bake "a
// write means nova" into anything shared; naming the field for the role rather
// than for one of its occupants is how it avoids that.
type Backend int

const (
	// BackendCubeCOS is the local cube-cos-api. The zero value, so it is what
	// a tool gets by saying nothing.
	BackendCubeCOS Backend = iota
	// BackendOpenStackCompute is nova, reached through the Keystone catalog.
	BackendOpenStackCompute
)

func (b Backend) String() string {
	switch b {
	case BackendCubeCOS:
		return "cube-cos-api"
	case BackendOpenStackCompute:
		return "openstack-compute"
	}
	return fmt.Sprintf("backend(%d)", int(b))
}

// ControlOp identifies a built-in operation — one this process answers from
// its own state rather than by running a command or calling an API. Like
// Impact it starts at 1, so a tool that sets nothing is not accidentally a
// control tool.
type ControlOp int

const (
	// ControlProbeStart begins a probe run and returns its id.
	ControlProbeStart ControlOp = iota + 1
	// ControlProbeStatus reports a run's state and, when finished, its metrics.
	ControlProbeStatus
	// ControlInstanceProfile reports what a create would make, for the
	// sentence a person approves.
	ControlInstanceProfile
)

func (c ControlOp) String() string {
	switch c {
	case ControlProbeStart:
		return "probe_start"
	case ControlProbeStatus:
		return "probe_status"
	case ControlInstanceProfile:
		return "describe_instance_profile"
	}
	return fmt.Sprintf("control(%d)", int(c))
}

// Tool is one read-only operation the AI plane may invoke.
type Tool struct {
	// Name is what the SaaS asks for, matched exactly.
	Name string

	// Description is for the operator reading the allowlist, not the model.
	Description string

	// Unlisted marks a tool the SaaS calls on its own account and never
	// offers to the model.
	//
	// It is not a security boundary — the executor serves the name to whoever
	// holds the tunnel, listed or not, and the level and impact checks are
	// what decide whether a call runs. It is an honesty flag for the
	// catalogue: without it, a SaaS that compares its model-facing tool list
	// against this allowlist must either advertise a tool the model has no
	// use for, or carry an exception typed out on that side — which is the
	// hand-kept copy toolcatalog exists to abolish.
	Unlisted bool

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

	// Backend is the API that Get or Post addresses. The zero value is
	// cube-cos-api, so only a tool that goes elsewhere has to say so.
	Backend Backend

	// Get is a path template for a read-only HTTP GET against Backend, e.g.
	// "/api/v1/datacenters/{dc}/healths". The method is GET, always — there is
	// no field to make it anything else, so a write to the management API is
	// not expressible in this allowlist.
	//
	// {dc} is the agent's own datacenter, filled by the executor from its
	// configuration — never a model parameter, so the SaaS cannot point a read
	// at another cluster. Every other placeholder is a model parameter and must
	// be declared in Params, exactly like Argv.
	Get string

	// Post is a cube-cos-api path template for a request that changes the
	// cluster, e.g. "/api/v1/datacenters/{dc}/instances". Body carries what is
	// sent. It exists because ADR 0011's operate level needs a write path and
	// Get is structurally GET-only; every guard that made Get safe is restated
	// for it, and two are added — a body whose every field is declared here,
	// and an idempotency key, because a repeated read is free and a repeated
	// create is not.
	//
	// Exactly one of Argv, Get, Post, Catalog or Control is set.
	Post string

	// Catalog is a finite set of cube-cos-api GET paths this one tool may
	// fetch: the value the caller supplies, mapped to the path template it
	// selects. The caller names a key; anything else is refused. The method is
	// GET, always, for the same structural reason Get is — there is no field
	// on a catalog entry that could make it anything else.
	//
	// It exists because Get costs one tool per path, and a diagnosis assistant
	// is asked to look at things we did not think of when we shipped. Three
	// hand-written reads against an API that declares dozens is not a security
	// property, it is a release cycle: every "can you also check X" was a new
	// entry, a build and a deploy.
	//
	// A key is not a Shape and not a pattern — it is a map lookup, which is the
	// same finite-value-set rule Params applies, in its strongest form. What a
	// caller can express is exactly the set below and nothing else, so widening
	// the read surface is still an edit to this file that a reviewer reads.
	//
	// Exactly one of Argv, Get, Post, Catalog or Control is set.
	Catalog map[string]string

	// Body is the JSON object sent with Post: a field name to either a literal
	// or a placeholder declared in Params or Free. There is no free-form body
	// and no pass-through of caller JSON, so the request this allowlist
	// performs is fully described by this file — the same property Argv has for
	// a command.
	Body map[string]string

	// Params declares each placeholder in Argv, Get, Post or Body and the
	// finite set of values it accepts. A parameter with no declared values is a
	// bug, not a wildcard: Register rejects it. {dc} is never declared here —
	// it is executor context, not a caller argument.
	Params map[string][]string

	// Free declares the placeholders whose values cannot be enumerated, each
	// with the Shape it must satisfy. A placeholder belongs to Params or to
	// Free, never both: one says "these values", the other "this grammar", and
	// a placeholder in both would leave a reviewer unsure which was checked.
	//
	// Keep this map small. Every entry is a value a reviewer can no longer read
	// in the allowlist, and the shape is all that stands between the caller and
	// the program.
	Free map[string]Shape

	// Impact declares what this tool does to the cluster, and the cluster's
	// action level decides whether that class is served (ADR 0011). Register
	// still refuses the zero value and any class this build cannot name, so a
	// tool that declares nothing is never served; what changed is that a
	// configuring class is now refused by the level at call time rather than
	// refused outright, and the level comes from a file on this node.
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

// CubeCOSReads is the set of cube-cos-api GET paths cube_cos_read may fetch,
// keyed by the value a caller supplies.
//
// Admission is opt-in. A path is reachable because it is written here, not
// because the API happens to serve it — so an endpoint cube-cos-api gains
// tomorrow is unreachable until someone reads it and adds it. The opposite
// rule, a list of paths to exclude, fails the wrong way: the next sensitive
// endpoint upstream would be reachable the day it shipped, and nobody here
// would know it existed.
//
// What is left out, and why, is in cubeCOSReadsHeldBack. Together the two
// account for every zero-parameter GET the API declares, and a test says so —
// so a new upstream read cannot be quietly unreachable either. It has to be
// classified, one way or the other, by a person.
//
// Three rules decided the split:
//
//   - A read that can carry a credential is out. Settings, integrations and
//     licenses hold SMTP passwords, storage-vendor logins, webhook URLs with
//     tokens in them and license keys. None of it helps diagnose a cluster,
//     and a diagnosis assistant reading them puts them in a transcript.
//   - A read whose size is unbounded by anything here is out. Support bundles
//     are the case: the result cap would truncate one to 32 KiB of an archive,
//     which is worse than not offering it.
//   - A duplicate is out. The .csv variants return what the JSON reads already
//     return; two ways to ask the same question is a worse tool list, not a
//     wider one.
//
// Query parameters are not expressible — the key selects a path and nothing
// else — so watch=true, which turns several of these into an event stream, is
// unreachable by construction rather than by exclusion.
var CubeCOSReads = map[string]string{
	"datacenter":              "/api/v1/datacenters/{dc}",
	"datacenters":             "/api/v1/datacenters",
	"events/filterConditions": "/api/v1/datacenters/{dc}/events/filterConditions",
	"events/predefined":       "/api/v1/datacenters/{dc}/events/predefined",
	"firmwares":               "/api/v1/datacenters/{dc}/firmwares",
	"firmwares/upgrade":       "/api/v1/datacenters/{dc}/firmwares/upgradeProgress",
	"fixpacks":                "/api/v1/datacenters/{dc}/fixpacks",
	"healths":                 "/api/v1/datacenters/{dc}/healths",
	"images":                  "/api/v1/datacenters/{dc}/images",
	"images/materials":        "/api/v1/datacenters/{dc}/images/materials",
	"metrics":                 "/api/v1/datacenters/{dc}/metrics",
	"nodes":                   "/api/v1/datacenters/{dc}/nodes",
	"services":                "/api/v1/datacenters/{dc}/services",
	"triggers":                "/api/v1/datacenters/{dc}/triggers",
	"triggers/materials":      "/api/v1/datacenters/{dc}/triggers/materials",
	"tunings/parameters":      "/api/v1/datacenters/{dc}/tunings/parameters",
	"tunings/specs":           "/api/v1/datacenters/{dc}/tunings/specs",
	"volumes":                 "/api/v1/datacenters/{dc}/volumes",
}

// cubeCOSReadsHeldBack is every other zero-parameter GET cube-cos-api declares,
// with the reason it is not in CubeCOSReads.
//
// It is data rather than prose so a test can require the two sets to cover the
// API between them. That is what makes admission opt-in and still visible: a
// read this agent will not perform is a decision written down, not an absence
// somebody has to notice.
// eventsNeedAType is why three of the events reads are held back.
//
// They are zero-parameter GETs in the OpenAPI document and 400s on a real
// cluster: cube-cos-api answers "'type' can't be null and should be one of
// 'system', 'host', or 'instance'". A required query parameter is not
// something the spec check can see — the path exists and the method is GET —
// and not something this catalogue can supply, because a key selects a path
// and nothing else. Admitting them would offer the model three reads that can
// only ever fail.
//
// Found by reading a live cluster, which is the only thing that could have
// found it. events/filterConditions and events/predefined need no parameter
// and stay admitted.
const eventsNeedAType = "needs a type query parameter the catalogue cannot express; returns 400 without one"

var cubeCOSReadsHeldBack = map[string]string{
	"/api/v1/datacenters/{dataCenter}/events":                    eventsNeedAType,
	"/api/v1/datacenters/{dataCenter}/events/abstract":           eventsNeedAType,
	"/api/v1/datacenters/{dataCenter}/events/rank":               eventsNeedAType,
	"/api/v1/datacenters/{dataCenter}/settings":                  "configuration, and the delivery settings under it carry credentials",
	"/api/v1/datacenters/{dataCenter}/settings/email/recipients": "email delivery configuration",
	"/api/v1/datacenters/{dataCenter}/settings/email/senders":    "email delivery configuration, sender credentials included",
	"/api/v1/datacenters/{dataCenter}/settings/slack/channels":   "chat delivery configuration, webhook URLs included",
	"/api/v1/datacenters/{dataCenter}/integrations/applications": "external-system integration, credentials included",
	"/api/v1/datacenters/{dataCenter}/integrations/storages":     "storage-vendor integration, logins included",
	"/api/v1/datacenters/{dataCenter}/integrations/storages/models": "integration catalogue; only useful alongside the " +
		"integration reads that are held back",
	"/api/v1/datacenters/{dataCenter}/integrations/storages/vendors": "integration catalogue; same",
	"/api/v1/datacenters/{dataCenter}/licenses":                      "license keys",
	"/api/v1/datacenters/{dataCenter}/licenses/attachments":          "license material",
	"/api/v1/datacenters/{dataCenter}/me":                            "the executor's own API identity, not a fact about the cluster",
	"/api/v1/datacenters/{dataCenter}/notifications":                 "notification payloads and their delivery targets",
	"/api/v1/datacenters/{dataCenter}/notifications/last":            "same",
	"/api/v1/datacenters/{dataCenter}/supportFiles":                  "support bundles; unbounded, and a 32 KiB slice of an archive is not a read",
	"/api/v1/datacenters/{dataCenter}/grafana/networkDevices":        "dashboard payload, may embed an access token; not diagnostic text",
	"/api/v1/datacenters/{dataCenter}/grafana/networks":              "same",
	"/api/v1/datacenters/{dataCenter}/grafana/storages":              "same",
	"/api/v1/datacenters/{dataCenter}/grafana/topHosts":              "same",
	"/api/v1/datacenters/{dataCenter}/grafana/topInstances":          "same",
	"/api/v1/datacenters/{dataCenter}/images.csv":                    "CSV duplicate of the images read",
	"/api/v1/datacenters/{dataCenter}/volumes.csv":                   "CSV duplicate of the volumes read",
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
	// which overview to fetch and nothing else.
	//
	// One tool over a catalogue rather than one tool per path. Twenty-one
	// entries as twenty-one tools would be twenty-one names and descriptions
	// in front of the model on every turn, for reads that differ only in which
	// noun they return; and because tool specs are what the SaaS fingerprints
	// as its prompt stamp, the list would move that stamp every time the
	// catalogue grew. One tool with a finite key set costs one name and one
	// enum, and adding a read moves nothing but the enum.
	{
		Name: "cube_cos_read",
		Description: "Read one overview from cube-cos-api: health, nodes, events, images, " +
			"volumes, services, firmwares, fixpacks, tunings, triggers or metrics.",
		Catalog: CubeCOSReads,
		Impact:  ImpactRead,
	},
	// The first entry that changes the cluster (ADR 0011, slice 3). Served
	// only where the node's action-level file says operate or internal; every
	// cluster refuses it until someone writes that file.
	//
	// The caller chooses one thing: the name. Flavour, image, network and
	// project come from the instance profile the cluster's operator configured,
	// filled here the way {dc} always has been — so the widest choice the SaaS
	// can make is a 63-character DNS label, and how much quota the instance
	// spends and what code it runs are the customer's decisions, made in
	// advance and not per call.
	//
	// The path was confirmed against cube-cos-api's OpenAPI document, and it
	// is wrong: there is no POST /api/v1/datacenters/{dataCenter}/instances,
	// in the document, in the copy embedded at build time, or as a handler in
	// that API's source. Its resource families are nodes, images, volumes,
	// settings, tunings and the rest; VM lifecycle is not among them. So the
	// body field names below are unconfirmable too — there is no schema to
	// confirm them against.
	//
	// The entry stays because the mechanism around it is what slice 3 built
	// and tested — the level gate, the approval statement, the write ledger,
	// the refusal a caller can read — and none of that is wrong. What is
	// missing is somewhere to send the request. Whoever supplies that decides
	// the shape: an endpoint on cube-cos-api, or a transport that reaches
	// whatever owns instances. Until then the write cannot succeed, and it
	// cannot be attempted either, since a cluster at observe never offers it.
	//
	// conformance_test.go holds this as a named debt rather than a comment,
	// so it is checked every run and cannot be forgotten the way this
	// sentence's predecessor nearly was.
	{
		Name: "create_instance",
		Description: "Create one virtual machine from this cluster's configured instance profile. " +
			"The caller chooses only the name.",
		// Instances are nova's, not cube-cos-api's: that API serves the
		// appliance and has no VM lifecycle at all (cube-advisor-agent#33).
		// The path is nova's own, relative to the compute service — the base
		// URL comes from the Keystone catalog at call time, so no host, port
		// or project id is written here and none can drift out of date.
		Backend: BackendOpenStackCompute,
		Post:    "/servers",
		// The canonical fields, not nova's wire shape. nova wants them nested
		// under "server", with flavorRef and imageRef, and networks as a list
		// of objects; that translation is the compute backend's job, in
		// novaServerBody. Keeping this map flat is what stops Body needing to
		// express nested JSON — a capability the allowlist is safer without,
		// since the whole point of this file is that the request it makes is
		// fully described by it.
		//
		// project is absent, and its absence is the control: in nova a
		// server is created in whatever project the credential is scoped to.
		// There is no project field to get wrong, and no way to name another
		// tenant's project, because naming is not how it is chosen.
		Body: map[string]string{
			"name":    "{name}",
			"flavor":  "{flavor}",
			"image":   "{image}",
			"network": "{network}",
		},
		Free: map[string]Shape{
			// The one value the allowlist cannot enumerate. A DNS label
			// cannot begin with "-", so it cannot be read as a flag; it
			// contains no "/" or ".", so it cannot compose or escape a path
			// segment; and it holds no shell metacharacter, which matters
			// not here — there is no shell — but downstream, where there
			// may be one.
			"{name}": ShapeDNSLabel,
		},
		Impact: ImpactOperate,
		// A create returns as soon as the API has accepted it; the instance
		// boots afterwards. This bounds the acceptance, not the boot.
		Timeout: 60 * time.Second,
	},
	// The create above takes its flavour, image and network from a file on
	// this node, and until now the SaaS had no way to learn them. So the
	// sentence a person approved said the values were "the cluster's own
	// settings" — true, and not something anyone can consent to. This reports
	// them, so the sentence can name what will exist.
	//
	// Read class: it discloses configuration this node's own operator wrote,
	// creates nothing and changes nothing. Unlisted, because the model cannot
	// choose these values and has no use for them; the SaaS calls it while
	// composing an approval prompt.
	{
		Name:        tunnelproto.DescribeInstanceProfile,
		Description: "Report the flavour, image and network a create would use, for the approval prompt.",
		Control:     ControlInstanceProfile,
		Impact:      ImpactRead,
		Unlisted:    true,
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
		// Well-formed, and not necessarily served. Registration is about the
		// tool; the cluster's action level is about this cluster, is read from
		// a file on this node, and is applied in Call — so a level raised or
		// lowered after startup takes effect without a restart, and a call the
		// level refuses is refused legibly rather than reported as an unknown
		// tool. Names() hides what the level does not serve, so an agent still
		// advertises only what it will do.
	default:
		return fmt.Errorf("tool %q declares impact %s; the AI plane serves reads and probes only", t.Name, t.Impact)
	}
	if t.Timeout < 0 {
		return fmt.Errorf("tool %q has a negative timeout", t.Name)
	}
	kinds := 0
	for _, set := range []bool{len(t.Argv) > 0, t.Get != "", t.Post != "", len(t.Catalog) > 0, t.Control != 0} {
		if set {
			kinds++
		}
	}
	if kinds != 1 {
		return fmt.Errorf("tool %q must be exactly one of a command (Argv), a cube-cos-api read (Get), a cube-cos-api catalogue read (Catalog), a cube-cos-api write (Post) or a probe-plane control (Control)", t.Name)
	}
	// A placeholder is either enumerated or shaped, never both: two answers to
	// "what may this value be" is the same as none.
	for ph := range t.Free {
		if _, dup := t.Params[ph]; dup {
			return fmt.Errorf("tool %q declares %s in both Params and Free; a placeholder has one rule", t.Name, ph)
		}
		if t.Free[ph] == 0 {
			return fmt.Errorf("tool %q declares %s with no shape; an unshaped free parameter is a wildcard", t.Name, ph)
		}
		if t.Free[ph].String() == fmt.Sprintf("shape(%d)", int(t.Free[ph])) {
			return fmt.Errorf("tool %q declares %s with a shape this build does not know", t.Name, ph)
		}
	}
	// A read may be shaped too, but nothing needs it yet, and a free parameter
	// on a read is a widening nobody asked for. Refused until a tool wants it,
	// so the surface grows deliberately rather than by inheritance.
	if len(t.Free) > 0 && t.Post == "" {
		return fmt.Errorf("tool %q declares free parameters but is not a write; only a write path admits an unenumerable value today", t.Name)
	}
	switch {
	case t.Control != 0:
		return t.validateControl()
	case t.Get != "":
		return t.validateGet()
	case len(t.Catalog) > 0:
		return t.validateCatalog()
	case t.Post != "":
		return t.validatePost()
	default:
		return t.validateCommand()
	}
}

// validateCatalog checks a catalogue read entry.
//
// Every rule validateGet applies to one path is applied to each of them, plus
// two the catalogue form makes possible: no parameters, because the key is the
// only thing a caller supplies and a second argument would be a second thing
// to check; and no placeholder other than {dc}, because a key selecting a
// template that still needed an argument would put a value back in the caller's
// hands through the side door.
func (t Tool) validateCatalog() error {
	if t.Impact != ImpactRead {
		return fmt.Errorf("tool %q is a cube-cos-api catalogue read but declares impact %s; a GET changes nothing", t.Name, t.Impact)
	}
	if len(t.Params) > 0 || len(t.Free) > 0 {
		return fmt.Errorf("tool %q is a catalogue read and declares parameters; the key is the only argument", t.Name)
	}
	for key, path := range t.Catalog {
		if key == "" {
			return fmt.Errorf("tool %q has a catalogue entry with an empty key", t.Name)
		}
		if !strings.HasPrefix(path, "/") {
			return fmt.Errorf("tool %q catalogue entry %q has a path that is not absolute", t.Name, key)
		}
		for _, seg := range pathSegments(path) {
			if isPlaceholder(seg) && seg != dcPlaceholder {
				return fmt.Errorf("tool %q catalogue entry %q leaves %s unfilled; a catalogue path takes no argument but %s",
					t.Name, key, seg, dcPlaceholder)
			}
		}
	}
	return nil
}

// validatePost checks a cube-cos-api write entry.
//
// Everything validateGet requires of a path, plus the body. A write is refused
// unless it declares one: a POST with no body is either a read wearing the
// wrong method or an action whose effect is invisible in this file, and both
// should be written differently.
func (t Tool) validatePost() error {
	if !strings.HasPrefix(t.Post, "/") {
		return fmt.Errorf("tool %q POST path must be absolute", t.Name)
	}
	// Declaring an executor-filled placeholder as a caller argument is how it
	// would stop being executor context, so it is a registration error rather
	// than something resolveWrite quietly ignores.
	for ph := range executorFilled {
		if _, declared := t.Params[ph]; declared {
			return fmt.Errorf("tool %q declares %s; it is executor context, not a parameter", t.Name, ph)
		}
		if _, declared := t.Free[ph]; declared {
			return fmt.Errorf("tool %q declares %s as a free parameter; it is executor context, and the caller must not choose it", t.Name, ph)
		}
	}
	if len(t.Body) == 0 {
		return fmt.Errorf("tool %q is a write and declares no body; what it sends must be visible here", t.Name)
	}
	if t.Impact == ImpactRead {
		return fmt.Errorf("tool %q writes to the management API but declares impact read", t.Name)
	}
	tokens := pathSegments(t.Post)
	for field, v := range t.Body {
		if field == "" {
			return fmt.Errorf("tool %q declares a body field with no name", t.Name)
		}
		tokens = append(tokens, v)
	}
	return t.checkPlaceholders(tokens, executorFilled)
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
	switch t.Control {
	case ControlProbeStart, ControlProbeStatus, ControlInstanceProfile:
	default:
		return fmt.Errorf("tool %q declares an unknown control operation", t.Name)
	}
	// A control tool answers from this process's own state — a probe run it
	// started, a setting its operator wrote. None of that reaches a cluster's
	// configuration, so a control tool claiming a configuring class is
	// claiming to be something no control op can do.
	if t.Impact != ImpactRead && t.Impact != ImpactScratch {
		return fmt.Errorf("tool %q is a control tool but declares impact %s; a control operation changes no configuration", t.Name, t.Impact)
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
	// A GET changes nothing, so a configuring class on one is a mis-declaration
	// rather than a policy question, and a cluster at the internal level would
	// otherwise serve it as though it changed something. Refused at
	// registration, where the contradiction is between two fields of the same
	// entry and a reviewer can see both.
	if t.Impact != ImpactRead {
		return fmt.Errorf("tool %q is a cube-cos-api read but declares impact %s; a GET changes nothing", t.Name, t.Impact)
	}
	// {dc} is executor context, not a caller argument: it may appear in the
	// path without a Params declaration, and it must not be declared as one.
	if _, declared := t.Params[dcPlaceholder]; declared {
		return fmt.Errorf("tool %q declares %s; it is executor context, not a parameter", t.Name, dcPlaceholder)
	}
	return t.checkPlaceholders(pathSegments(t.Get), map[string]string{dcPlaceholder: ""})
}

// checkPlaceholders enforces that every placeholder in tokens is either an
// exempt executor slot or a declared model parameter, and that every declared
// parameter is used with a finite value set.
func (t Tool) checkPlaceholders(tokens []string, exempt map[string]string) error {
	seen := map[string]bool{}
	for _, tok := range tokens {
		if !isPlaceholder(tok) {
			continue
		}
		if _, ok := exempt[tok]; ok {
			continue
		}
		_, enumerated := t.Params[tok]
		_, shaped := t.Free[tok]
		if !enumerated && !shaped {
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
	for p := range t.Free {
		if !seen[p] {
			return fmt.Errorf("tool %q declares %s but never uses it", t.Name, p)
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
