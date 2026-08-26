package toolplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
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

	// datacenter is the agent's own cluster identity, filled into a Get tool's
	// {dc}. Empty until deployment wires it, which is why an unconfigured Get
	// tool refuses rather than reading the wrong cluster.
	datacenter string
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
func New(tools []Tool, audit Auditor) (*Registry, error) {
	if audit == nil {
		return nil, fmt.Errorf("toolplane: an auditor is required; every call must be inspectable by the customer")
	}
	r := &Registry{
		tools:   make(map[string]Tool, len(tools)),
		audit:   audit,
		timeout: defaultTimeout,
		run:     runCommand,
		cubeCOS: notConfigured{},
	}
	for _, t := range tools {
		if err := t.validate(); err != nil {
			return nil, fmt.Errorf("toolplane: %w", err)
		}
		if _, dup := r.tools[t.Name]; dup {
			return nil, fmt.Errorf("toolplane: tool %q registered twice", t.Name)
		}
		r.tools[t.Name] = t
	}
	return r, nil
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

// Names returns the registered tool names, sorted — what the agent advertises.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.tools))
	for n := range r.tools {
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

	if tool.Get != "" {
		return r.callGet(ctx, tool, args)
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
