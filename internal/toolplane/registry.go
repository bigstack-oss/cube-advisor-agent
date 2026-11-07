package toolplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
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

// Registry serves the tools. Construct it with New, which refuses anything
// malformed at registration rather than at call time.
type Registry struct {
	tools   map[string]Tool
	audit   Auditor
	timeout time.Duration

	// run executes a command; swapped in tests so the suite never shells out.
	run func(ctx context.Context, argv []string, maxBytes int) ([]byte, error)

	// level and consent are this node's files, reported in the Hello.
	level   Level
	consent Consent
}

// New builds a registry over tools.
func New(tools []Tool, audit Auditor, opts ...Option) (*Registry, error) {
	if audit == nil {
		return nil, fmt.Errorf("toolplane: an auditor is required; every call must be inspectable by the customer")
	}
	r := &Registry{
		tools:   make(map[string]Tool, len(tools)),
		audit:   audit,
		timeout: defaultTimeout,
		run:     runCommand,
		level:   DefaultLevel,
		consent: DefaultConsent,
	}
	for _, opt := range opts {
		opt(r)
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

// Option configures a Registry at construction.
type Option func(*Registry)

// WithLevel sets the action level this node reports.
func WithLevel(l Level) Option {
	return func(r *Registry) { r.level = l }
}

// Level is the action level this node reports.
func (r *Registry) Level() Level { return r.level }

// WithConsent sets the consent setting this node reports.
func WithConsent(c Consent) Option {
	return func(r *Registry) { r.consent = c }
}

// Consent is the consent setting this node reports.
func (r *Registry) Consent() Consent { return r.consent }

// SetRunnerForTest replaces the executor.
//
// Named for its only legitimate use. Tests in other packages need to exercise
// the registry without shelling out, and the alternative — exporting the
// executor as a field — would make "what actually runs a tool" configurable in
// production, which is precisely what should not be.
func (r *Registry) SetRunnerForTest(fn func(ctx context.Context, argv []string, maxBytes int) ([]byte, error)) {
	r.run = fn
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

// Names lists the tools served, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.tools))
	for n := range r.tools {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Call runs one tool and records it in the audit log.
func (r *Registry) Call(ctx context.Context, name string, args map[string]string) ([]byte, error) {
	tool, ok := r.tools[name]
	if !ok {
		r.audit.RecordToolCall(ToolCall{
			Tool: name, Args: args, Allowed: false,
			Reason: "no such tool", At: time.Now().UTC(),
		})
		return nil, fmt.Errorf("%w: %q", ErrUnknownTool, name)
	}

	command, err := sandboxCommand(args)
	if err != nil {
		r.audit.RecordToolCall(ToolCall{
			Tool: name, Args: args, Allowed: false,
			Reason: err.Error(), At: time.Now().UTC(),
		})
		return nil, fmt.Errorf("%w: %v", ErrBadArgument, err)
	}
	callID := newCallID()
	timeout := r.timeoutFor(tool)
	argv := SandboxArgvFor(command, timeout, callID)

	max := tool.MaxOutputBytes
	if max <= 0 {
		max = defaultMaxOutputBytes
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	out, runErr := r.run(ctx, argv, max)
	runErr = asTimeout(ctx, name, timeout, runErr)
	truncated := errors.Is(runErr, ErrOutputTruncated)
	if truncated {
		out = trimPartialRune(truncateAtRune(out, max))
		out = append(out, fmt.Sprintf(truncationNotice, len(out))...)
		runErr = nil
	}
	rec := ToolCall{
		Tool: name, Args: withCall(args, callID), Argv: argv, Allowed: true,
		At: started.UTC(), Duration: time.Since(started), Bytes: len(out),
		Truncated: truncated,
	}
	if runErr != nil {
		rec.Reason = runErr.Error()
	}
	r.audit.RecordToolCall(rec)
	// A sandboxed command's failure is its result: the caller reads it.
	if runErr != nil {
		out = append(out, fmt.Sprintf("\n[%v]\n", runErr)...)
	}
	return out, nil
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
