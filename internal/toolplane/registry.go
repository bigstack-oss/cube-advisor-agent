package toolplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// Errors a caller may distinguish. They are deliberately coarse: the SaaS is
// told that a call was refused, never which check refused it, because a precise
// refusal is a probe oracle.
var (
	ErrUnknownTool = errors.New("toolplane: no such tool")
	ErrBadArgument = errors.New("toolplane: argument not permitted")
)

// ErrToolTimedOut distinguishes a tool that ran out of time from one that
// crashed. Without it, a killed process reports "signal: killed" — the same
// shape as a real failure — and neither the audit log nor an operator can
// tell a slow cluster from a broken one.
var ErrToolTimedOut = errors.New("toolplane: tool exceeded its time limit")

// ErrRefusedAtLevel is a call this cluster's action level does not serve.
//
// Distinguishable from ErrBadArgument because the two mean opposite things to
// whoever reads them: a bad argument is the caller's mistake and retrying with
// a different value may work, while a level refusal is the cluster's policy and
// no argument changes it. Collapsing them would have the SaaS advise the model
// to try again at a cluster that will refuse it every time.
var ErrRefusedAtLevel = errors.New("toolplane: refused at this cluster's action level")

// ErrOutputTruncated is how a runner reports that a command emitted more than
// the cap. Call converts it into a successful, marked result rather than a
// failure: the first half-megabyte of a log is evidence, silence is not.
var ErrOutputTruncated = errors.New("toolplane: output truncated")

// truncationNotice is appended to a capped result so the model reports the cut
// instead of hallucinating the tail. Wording mirrors the SaaS-side budget
// marker; there is no trajectory here, so it claims none.
const truncationNotice = "\n[truncated after %d bytes by the executor's output cap]"

// Defaults bounding a single call. A tool call is a diagnostic read, not a job.
//
// The timeout ladder matters more than any single value: a tool's own timeout
// (per-tool or this default) < the server's per-call cap < the SaaS's channel
// deadline. The innermost timeout must fire first, because it is the one that
// produces an honest "tool timed out" result the model can read — every layer
// above it can only report a dead channel. Today the rungs are ≤100s here,
// 110s in internal/agent, 120s SaaS-side.
const (
	defaultMaxOutputBytes = 256 << 10
	defaultTimeout        = 60 * time.Second
)

// Registry serves an allowlist. Construct it with New, which refuses anything
// malformed at registration rather than at call time.
type Registry struct {
	tools   map[string]Tool
	audit   Auditor
	timeout time.Duration

	// run executes a command; swapped in tests so the suite never shells out.
	run func(ctx context.Context, argv []string, maxBytes int) ([]byte, error)

	// probes runs the scratch-class tools. Nil on an agent built without a
	// probe plane, and then the scratch class is refused at registration, so a
	// nil here is never reached at call time.
	probes *ProbeRunner

	// level is what this cluster serves (ADR 0011), read from a file on this
	// node at construction. It is the authoritative copy: the SaaS keeps a
	// mirror to shape what it offers the model, and where the two disagree
	// this one refuses.
	level Level

	// datacenter is the agent's own cluster identity, filled into a Get tool's
	// {dc}. Empty until deployment wires it, which is why an unconfigured Get
	// tool refuses rather than reading the wrong cluster.
	datacenter string

	// profile is everything about a created instance except its name. Empty
	// until deployment sets it, which is why an unconfigured write refuses
	// rather than creating something the operator did not specify.
	profile InstanceProfile

	// writers performs the authenticated write, one client per backend.
	// Nil-safe via writerFor, which returns a refusing default naming the
	// configuration that is missing — exactly as cubeCOS is for reads.
	writers map[Backend]Poster

	// writes suppresses a repeat of a completed write. See writeLedger.
	writes *writeLedger
	// cubeCOS performs the authenticated read-only GET; nil-safe via a default
	// that refuses, so a Get tool on an unconfigured agent is a clean refusal
	// rather than a panic.
	cubeCOS CubeCOSGetter
}

// CubeCOSGetter performs an authenticated read-only GET against the local
// cube-cos-api and returns up to maxBytes of the response body. The
// implementation owns the base URL, the node token and the TLS trust; none of
// those ever reach this package, so none can reach the audit log.
type CubeCOSGetter interface {
	Get(ctx context.Context, path string, maxBytes int) ([]byte, error)
}

// notConfigured is the default getter: an agent that never had its cube-cos-api
// client wired refuses a Get tool cleanly.
type notConfigured struct{}

func (notConfigured) Get(context.Context, string, int) ([]byte, error) {
	return nil, fmt.Errorf("cube-cos-api access is not configured on this agent")
}

// New builds a registry from tools, refusing to start if any is malformed.
//
// Registration is where a bad tool is caught. A malformed entry discovered at
// call time would mean an agent that looked healthy until the SaaS happened to
// invoke the broken tool.
func New(tools []Tool, audit Auditor, opts ...Option) (*Registry, error) {
	if audit == nil {
		return nil, fmt.Errorf("toolplane: an auditor is required; every call must be inspectable by the customer")
	}
	r := &Registry{
		tools:   make(map[string]Tool, len(tools)),
		audit:   audit,
		timeout: defaultTimeout,
		run:     runCommand,
		cubeCOS: notConfigured{},
		// Fail closed before any option runs: a registry built without
		// WithLevel serves reads, which is ADR 0011's "unset means observe"
		// at the one place a caller could forget to say it.
		level:   DefaultLevel,
		writers: map[Backend]Poster{},
		writes:  newWriteLedger(),
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.probes != nil {
		// Enabling the plane and advertising it are one act. Appending here
		// rather than asking the caller to compose the two lists removes the
		// half-configured agent: probe controls with no runner, or a runner
		// nothing can reach.
		tools = append(append([]Tool{}, tools...), ProbeControls...)
	}
	for _, t := range tools {
		if err := t.validate(r.probes != nil); err != nil {
			return nil, fmt.Errorf("toolplane: %w", err)
		}
		if _, dup := r.tools[t.Name]; dup {
			return nil, fmt.Errorf("toolplane: tool %q registered twice", t.Name)
		}
		r.tools[t.Name] = t
	}
	return r, nil
}

// Option configures a registry at construction.
type Option func(*Registry)

// WithProbes enables the scratch class by giving the registry a probe runner.
//
// Without it the scratch class is refused at registration, so enabling probes
// is a deliberate act at the one place a reviewer already looks — and an agent
// that was not built for probes cannot be talked into running one.
func WithProbes(pr *ProbeRunner) Option {
	return func(r *Registry) { r.probes = pr }
}

// WithLevel sets the action level this agent serves.
//
// Deployment reads it from the node with ReadLevel and passes it here, so the
// file is parsed once, at startup, where a malformed value can be logged
// loudly — rather than on each call, where the same error would be a mystery
// repeated. A registry given no level serves reads.
func WithLevel(l Level) Option {
	return func(r *Registry) { r.level = l }
}

// refusedByLevel reports whether the cluster's action level withholds a class.
//
// It asks the question only of the configuring classes, and that restriction is
// the whole point. The classes ascend by what they touch and that ordering is
// not a permission scale: ImpactScratch is gated by whether this agent has a
// probe runner, decided at registration, and ImpactRead is gated by nothing.
// Handing the level authority over all four — the shape "does this level serve
// this impact", asked unconditionally — silently stops every probe, because no
// level serves scratch. That regression is what this function exists to make
// impossible to write by accident.
func (r *Registry) refusedByLevel(i Impact) bool {
	switch i {
	case ImpactOperate, ImpactInternal:
		return !r.level.Serves(i)
	}
	return false
}

// Level reports what this agent serves. Deployment logs it at startup; the
// SaaS never asks, because asking would make the answer something a compromised
// SaaS could be told.
func (r *Registry) Level() Level { return r.level }

// ConfigureInstanceProfile sets everything about a created instance except its
// name. Called once at startup from deployment configuration; until then a
// write refuses, so an operator who enabled the operate level but described no
// instance gets a clean refusal rather than a surprising default.
func (r *Registry) ConfigureInstanceProfile(p InstanceProfile) { r.profile = p }

// ConfigureWriter wires the authenticated write client for one backend.
// Separate from ConfigureCubeCOS so an agent can read the management API
// without being able to write anywhere: an operator who wires only the reader
// has a plane that cannot create anything, whatever its level says.
//
// Per backend rather than one writer, because the destinations have separate
// credentials and separate custody — wiring nova must not silently grant
// whatever comes next.
func (r *Registry) ConfigureWriter(b Backend, pw Poster) {
	if pw != nil {
		r.writers[b] = pw
	}
}

// Writers reports the backends with an authenticated write client wired, in a
// stable order.
//
// ConfigureWriter's observable counterpart. Without it, a credential on disk
// reaching this registry is only visible by making a call, so nothing could
// assert the wiring without a network — which is how ConfigureInstanceProfile
// and ConfigureCubeCOS shipped documented, tested and never called.
func (r *Registry) Writers() []Backend {
	out := make([]Backend, 0, len(r.writers))
	for b := range r.writers {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// writerFor returns the client for a backend, or a refusing default.
//
// The default is per backend and says what is missing, because "not
// configured" is only actionable if it names which configuration. An
// unrecognised backend refuses too: absence of a client is not permission,
// the same rule an unrecognised impact follows.
func (r *Registry) writerFor(b Backend) Poster {
	if w, ok := r.writers[b]; ok {
		return w
	}
	if b == BackendOpenStackCompute {
		return notConfiguredCompute{}
	}
	return notConfiguredPoster{}
}

// contextValues is every placeholder the executor fills from its own
// configuration, resolved at call time so a profile set after construction is
// picked up.
func (r *Registry) contextValues() map[string]string {
	v := r.profile.values()
	v[dcPlaceholder] = r.datacenter
	return v
}

// SetWriterForTest is ConfigureWriter's test-named twin, and also fixes the
// ledger's clock so a suite can age an entry out without sleeping.
func (r *Registry) SetWriterForTest(b Backend, pw Poster, now func() time.Time) {
	r.ConfigureWriter(b, pw)
	if now != nil {
		r.writes.now = now
	}
}

// SetRunnerForTest replaces the executor.
//
// Named for its only legitimate use. Tests in other packages need to exercise
// the registry without shelling out, and the alternative — exporting the
// executor as a field — would make "what actually runs a tool" configurable in
// production, which is precisely what should not be.
func (r *Registry) SetRunnerForTest(fn func(ctx context.Context, argv []string, maxBytes int) ([]byte, error)) {
	r.run = fn
}

// ConfigureCubeCOS wires the agent's datacenter and its cube-cos-api client,
// enabling the Get tools. Called once at agent startup from deployment
// configuration; until then a Get tool refuses. The getter holds the base URL,
// token and TLS trust — none of which enter this package.
func (r *Registry) ConfigureCubeCOS(datacenter string, g CubeCOSGetter) {
	r.datacenter = datacenter
	if g != nil {
		r.cubeCOS = g
	}
}

// SetCubeCOSForTest is ConfigureCubeCOS's test-named twin, for suites in other
// packages that inject a fake cube-cos-api.
func (r *Registry) SetCubeCOSForTest(datacenter string, g CubeCOSGetter) {
	r.ConfigureCubeCOS(datacenter, g)
}

// timeoutFor returns the bound for one execution of tool: its own declared
// timeout, or the registry default. Per-tool wins — cluster_check legitimately
// needs longer than a journal tail, and one shared number would either starve
// the slow tool or slacken every fast one.
func (r *Registry) timeoutFor(tool Tool) time.Duration {
	if tool.Timeout > 0 {
		return tool.Timeout
	}
	return r.timeout
}

// asTimeout replaces err with a distinguishable ErrToolTimedOut when ctx's own
// deadline is what ended the call — the same failure a killed process reports
// as an opaque "signal: killed". Checking ctx.Err() rather than the error's
// text works regardless of what the runner or the cube-cos-api client
// happened to return for a killed/cancelled call.
func asTimeout(ctx context.Context, name string, timeout time.Duration, err error) error {
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%w: %q ran past its %s limit", ErrToolTimedOut, name, timeout)
	}
	return err
}

// Names returns the tool names this agent will serve at its level, sorted —
// what it advertises.
//
// A registered tool the level does not serve is absent here rather than listed
// and refused: advertising a call that always fails wastes a turn and teaches
// the model that refusals are normal. Call still refuses it, because the list
// is advice and the check is the control.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.tools))
	for n, t := range r.tools {
		if r.refusedByLevel(t.Impact) {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Call runs a tool by name with the given arguments.
//
// Every outcome is audited before it is returned, including refusals: a refused
// call is precisely what a customer reviewing vendor access wants to see, and
// dropping it silently would hide the interesting half of the log.
func (r *Registry) Call(ctx context.Context, name string, args map[string]string) ([]byte, error) {
	tool, ok := r.tools[name]
	if !ok {
		r.audit.RecordToolCall(ToolCall{
			Tool: name, Args: args, Allowed: false,
			Reason: "no such tool", At: time.Now().UTC(),
		})
		return nil, fmt.Errorf("%w: %q", ErrUnknownTool, name)
	}

	// The level check comes before anything the tool does, and before argument
	// resolution: whether this cluster serves the class is a question about the
	// cluster, and answering it first means a refused call never touches a
	// value it was not going to use.
	//
	// The reason is the one refusal permitted to be specific (tunnelproto
	// .RefusedAtLevelReason). It names no tool and no value, so it is not an
	// oracle; it is the cluster's own policy, which its operator wrote.
	if r.refusedByLevel(tool.Impact) {
		r.audit.RecordToolCall(ToolCall{
			Tool: name, Args: args, Allowed: false,
			Reason: fmt.Sprintf("action level %s does not serve impact %s", r.level, tool.Impact),
			At:     time.Now().UTC(),
		})
		return nil, fmt.Errorf("%w: %s", ErrRefusedAtLevel, tunnelproto.RefusedAtLevelReason)
	}

	if tool.Control != 0 {
		return r.callControl(ctx, tool, args)
	}

	if tool.Get != "" {
		return r.callGet(ctx, tool, args)
	}

	if len(tool.Catalog) > 0 {
		return r.callCatalogGet(ctx, tool, args)
	}

	if tool.Post != "" {
		return r.callPost(ctx, tool, args)
	}

	argv, err := tool.resolve(args)
	if err != nil {
		r.audit.RecordToolCall(ToolCall{
			Tool: name, Args: args, Allowed: false,
			Reason: err.Error(), At: time.Now().UTC(),
		})
		return nil, fmt.Errorf("%w: %v", ErrBadArgument, err)
	}

	max := tool.MaxOutputBytes
	if max <= 0 {
		max = defaultMaxOutputBytes
	}
	timeout := r.timeoutFor(tool)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	out, runErr := r.run(ctx, argv, max)
	runErr = asTimeout(ctx, name, timeout, runErr)
	truncated := errors.Is(runErr, ErrOutputTruncated)
	if truncated {
		// A capped result is data, not a failure. The runner cut at a byte
		// count, which may have split a rune; back off to a boundary so the
		// marker never follows half a character, and say where the cut fell.
		out = trimPartialRune(truncateAtRune(out, max))
		out = append(out, fmt.Sprintf(truncationNotice, len(out))...)
		runErr = nil
	}
	rec := ToolCall{
		Tool: name, Args: args, Argv: argv, Allowed: true,
		At: started.UTC(), Duration: time.Since(started), Bytes: len(out),
		Truncated: truncated,
	}
	if runErr != nil {
		rec.Reason = runErr.Error()
	}
	r.audit.RecordToolCall(rec)
	return out, runErr
}

// callControl dispatches a probe-plane control call.
//
// Both operations are short by construction — starting a probe returns once
// the goroutine is launched, polling one reads a map — so neither needs the
// timeout ladder stretched to fit the measurement it controls. Results go back
// as JSON so the SaaS forwards numbers rather than prose.
func (r *Registry) callControl(ctx context.Context, tool Tool, args map[string]string) ([]byte, error) {
	if r.probes == nil {
		// Unreachable: the scratch class is refused at registration without a
		// runner. Kept so a future control tool that is not scratch-class
		// cannot reach a nil runner unnoticed.
		return nil, fmt.Errorf("%w: %q", ErrUnknownTool, tool.Name)
	}
	for k := range args {
		if k != "probe" && k != "run" {
			r.audit.RecordToolCall(ToolCall{
				Tool: tool.Name, Args: args, Allowed: false,
				Reason: fmt.Sprintf("unexpected argument %q", k), At: time.Now().UTC(),
			})
			return nil, fmt.Errorf("%w: unexpected argument %q", ErrBadArgument, k)
		}
	}

	switch tool.Control {
	case ControlProbeStart:
		name, ok := args["probe"]
		if !ok {
			return nil, fmt.Errorf("%w: probe_start needs a probe name", ErrBadArgument)
		}
		id, err := r.probes.Start(ctx, name)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"run": id, "state": string(ProbeRunning)})

	case ControlProbeStatus:
		id, ok := args["run"]
		if !ok {
			return nil, fmt.Errorf("%w: probe_status needs a run id", ErrBadArgument)
		}
		res, err := r.probes.Status(id)
		if err != nil {
			r.audit.RecordToolCall(ToolCall{
				Tool: tool.Name, Args: args, Allowed: false,
				Reason: "no such run", At: time.Now().UTC(),
			})
			return nil, err
		}
		out, err := json.Marshal(res)
		if err != nil {
			return nil, err
		}
		r.audit.RecordToolCall(ToolCall{
			Tool: tool.Name, Args: args, Allowed: true,
			At: time.Now().UTC(), Bytes: len(out),
		})
		return out, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownTool, tool.Name)
}

// callGet resolves a Get tool's path and fetches it from cube-cos-api.
//
// The path is the whole request: the method is GET (the getter offers nothing
// else), {dc} is the agent's own datacenter, and every other segment is either
// literal or an enum-checked model parameter. The audit records the resolved
// path and never the token, which lives in the getter.
func (r *Registry) callGet(ctx context.Context, tool Tool, args map[string]string) ([]byte, error) {
	path, err := tool.resolvePath(args, r.datacenter)
	if err != nil {
		r.audit.RecordToolCall(ToolCall{
			Tool: tool.Name, Args: args, Allowed: false,
			Reason: err.Error(), At: time.Now().UTC(),
		})
		return nil, fmt.Errorf("%w: %v", ErrBadArgument, err)
	}

	return r.fetch(ctx, tool, path, args)
}

// callCatalogGet dispatches a catalogue read: the caller names a key, the
// allowlist owns the path.
//
// The key is checked by map lookup, which is the finite-value-set rule in its
// strongest form — there is no grammar to get wrong and no value outside the
// set to reject, because a value outside the set simply is not a key. A miss
// is refused the same way an out-of-set parameter is, and audited, so a caller
// probing for paths writes a line per attempt in the customer's own log.
func (r *Registry) callCatalogGet(ctx context.Context, tool Tool, args map[string]string) ([]byte, error) {
	refuse := func(err error) ([]byte, error) {
		r.audit.RecordToolCall(ToolCall{
			Tool: tool.Name, Args: args, Allowed: false,
			Reason: err.Error(), At: time.Now().UTC(),
		})
		return nil, fmt.Errorf("%w: %v", ErrBadArgument, err)
	}
	for k := range args {
		if k != catalogArg {
			return refuse(fmt.Errorf("unexpected argument %q", k))
		}
	}
	key, given := args[catalogArg]
	if !given {
		return refuse(fmt.Errorf("missing argument %s", catalogArg))
	}
	template, ok := tool.Catalog[key]
	if !ok {
		// Naming the argument but not the catalogue: which reads exist is in
		// the tool's schema, where the model already saw it, and echoing the
		// set on every miss would turn a refusal into a directory listing.
		return refuse(fmt.Errorf("value for %s is not one this tool reads", catalogArg))
	}
	if r.datacenter == "" {
		return refuse(fmt.Errorf("cube-cos-api access is not configured on this agent"))
	}
	path := strings.ReplaceAll(template, dcPlaceholder, r.datacenter)
	return r.fetch(ctx, tool, path, args)
}

// fetch performs a resolved cube-cos-api GET, caps it, and audits the outcome.
//
// Both read forms end here so the cap, the truncation marker and the audit
// record are written once. A second copy of this would be a second place for
// the marker to go missing, and tool-0010 measures whether the model reports a
// cut — which it cannot do if the executor forgot to say there was one.
func (r *Registry) fetch(ctx context.Context, tool Tool, path string, args map[string]string) ([]byte, error) {
	max := tool.MaxOutputBytes
	if max <= 0 {
		max = defaultMaxOutputBytes
	}
	timeout := r.timeoutFor(tool)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	out, runErr := r.cubeCOS.Get(ctx, path, max)
	runErr = asTimeout(ctx, tool.Name, timeout, runErr)
	truncated := errors.Is(runErr, ErrOutputTruncated)
	if truncated {
		out = trimPartialRune(truncateAtRune(out, max))
		out = append(out, fmt.Sprintf(truncationNotice, len(out))...)
		runErr = nil
	}
	rec := ToolCall{
		Tool: tool.Name, Args: args, Path: path, Allowed: true,
		At: started.UTC(), Duration: time.Since(started), Bytes: len(out),
		Truncated: truncated,
	}
	if runErr != nil {
		rec.Reason = runErr.Error()
	}
	r.audit.RecordToolCall(rec)
	return out, runErr
}

// resolvePath substitutes {dc} and the model parameters into a Get template.
//
// {dc} comes from the agent's config, never from args, so the SaaS cannot
// redirect a read at another cluster. Every other placeholder is enum-checked
// exactly like an argv parameter, and a substituted value may not contain a
// path separator or a dot-dot segment — defence in depth, so even a careless
// allowlist enum cannot compose a segment that escapes the intended resource.
func (t Tool) resolvePath(args map[string]string, datacenter string) (string, error) {
	for k := range args {
		if _, ok := t.Params[k]; !ok {
			return "", fmt.Errorf("unexpected argument %q", k)
		}
	}
	segs := pathSegments(t.Get)
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		if !isPlaceholder(seg) {
			out = append(out, seg)
			continue
		}
		if seg == dcPlaceholder {
			if datacenter == "" {
				return "", fmt.Errorf("cube-cos-api access is not configured on this agent")
			}
			out = append(out, datacenter)
			continue
		}
		v, given := args[seg]
		if !given {
			return "", fmt.Errorf("missing argument %s", seg)
		}
		if !permitted(t.Params[seg], v) {
			return "", fmt.Errorf("value for %s is not in the permitted set", seg)
		}
		if strings.ContainsAny(v, "/") || v == ".." {
			return "", fmt.Errorf("value for %s is not a single path segment", seg)
		}
		out = append(out, v)
	}
	return "/" + strings.Join(out, "/"), nil
}

// truncateAtRune cuts b to at most limit bytes without splitting a rune.
func truncateAtRune(b []byte, limit int) []byte {
	if len(b) <= limit {
		return b
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return b[:cut]
}

// trimPartialRune drops an incomplete trailing rune left by a byte-level cut.
// At most UTFMax-1 bytes go: bounded, so a genuinely binary tail is not eaten.
func trimPartialRune(b []byte) []byte {
	for i := 0; i < utf8.UTFMax-1 && len(b) > 0; i++ {
		r, size := utf8.DecodeLastRune(b)
		if r != utf8.RuneError || size != 1 {
			return b
		}
		b = b[:len(b)-1]
	}
	return b
}

// resolve substitutes declared parameters into the tool's argv.
//
// Substitution happens only into declared slots and only from the declared
// value set, so an argument the allowlist did not anticipate cannot reach the
// command line at all. There is no shell in the path, which is why this needs
// no escaping: metacharacters are ordinary bytes in an exec argument.
func (t Tool) resolve(args map[string]string) ([]string, error) {
	for k := range args {
		if _, ok := t.Params[k]; !ok {
			return nil, fmt.Errorf("unexpected argument %q", k)
		}
	}
	argv := make([]string, 0, len(t.Argv))
	for _, a := range t.Argv {
		if !isPlaceholder(a) {
			argv = append(argv, a)
			continue
		}
		v, given := args[a]
		if !given {
			return nil, fmt.Errorf("missing argument %s", a)
		}
		if !permitted(t.Params[a], v) {
			// The value is not echoed: an error that repeats what was asked for
			// makes a convenient oracle out of the audit log.
			return nil, fmt.Errorf("value for %s is not in the permitted set", a)
		}
		argv = append(argv, v)
	}
	return argv, nil
}

func permitted(values []string, v string) bool {
	for _, ok := range values {
		if ok == v {
			return true
		}
	}
	return false
}

// runCommand executes argv directly — no shell — capturing bounded output.
func runCommand(ctx context.Context, argv []string, maxBytes int) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// Read at most maxBytes+1 so truncation is detectable, then keep draining
	// so the child is never blocked writing into a full pipe — a blocked child
	// would hold the deadline open rather than being killed by it.
	out, readErr := io.ReadAll(io.LimitReader(stdout, int64(maxBytes)+1))
	go func() { _, _ = io.Copy(io.Discard, stdout) }()
	waitErr := cmd.Wait()

	truncated := false
	if len(out) > maxBytes {
		out = out[:maxBytes]
		truncated = true
	}
	if readErr != nil {
		return out, readErr
	}
	if waitErr != nil {
		return out, waitErr
	}
	if truncated {
		return out, fmt.Errorf("%w at %d bytes", ErrOutputTruncated, maxBytes)
	}
	return out, nil
}
