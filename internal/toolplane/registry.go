package toolplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"time"
)

// Errors a caller may distinguish. They are deliberately coarse: the SaaS is
// told that a call was refused, never which check refused it, because a precise
// refusal is a probe oracle.
var (
	ErrUnknownTool = errors.New("toolplane: no such tool")
	ErrBadArgument = errors.New("toolplane: argument not permitted")
)

// Defaults bounding a single call. A tool call is a diagnostic read, not a job.
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
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	started := time.Now()
	out, runErr := r.run(ctx, argv, max)
	rec := ToolCall{
		Tool: name, Args: args, Argv: argv, Allowed: true,
		At: started.UTC(), Duration: time.Since(started), Bytes: len(out),
	}
	if runErr != nil {
		rec.Reason = runErr.Error()
	}
	r.audit.RecordToolCall(rec)
	return out, runErr
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
		return out, fmt.Errorf("toolplane: output truncated at %d bytes", maxBytes)
	}
	return out, nil
}
