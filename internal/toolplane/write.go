package toolplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Poster performs an authenticated write against one backend. Like
// CubeCOSGetter it owns the base URL, the credential and the TLS trust, so
// none of those reach this package or its audit log.
//
// Named for the role and not for cube-cos-api, because the registry now holds
// one of these per Backend: a create goes to nova, and a k8s cluster will go
// to Rancher. path is relative to whatever base URL the implementation owns —
// for nova that is the compute endpoint from the Keystone catalog, which is
// why "/servers" is the whole of what the allowlist writes down.
//
// idempotencyKey is passed for the transport to send as a request header. A
// server that honours it collapses a retry; a server that ignores it loses
// nothing, because the duplicate suppression this package performs (see
// writeLedger) does not depend on it.
type Poster interface {
	Post(ctx context.Context, path string, body []byte, idempotencyKey string, maxBytes int) ([]byte, error)
}

// notConfiguredPoster is the default: an agent whose cube-cos-api client was
// never wired refuses a write cleanly rather than panicking.
type notConfiguredPoster struct{}

func (notConfiguredPoster) Post(context.Context, string, []byte, string, int) ([]byte, error) {
	return nil, fmt.Errorf("cube-cos-api access is not configured on this agent")
}

// Placeholders the executor fills from its own configuration rather than from
// a caller argument.
//
// {dc} was the first, and the reason generalises: a value the SaaS cannot
// choose is a value a prompt injection cannot choose either. Creating an
// instance needs a flavour, an image, a network and a project, none of which
// can be enumerated in a compiled allowlist because they differ per cluster —
// so rather than letting the caller supply them, the cluster's operator
// declares them once as an instance profile and the caller chooses only the
// name. What the SaaS picks shrinks to one string of one shape; everything
// else about the resource is the cluster's own policy.
const (
	dcPlaceholder      = "{dc}"
	flavorPlaceholder  = "{flavor}"
	imagePlaceholder   = "{image}"
	networkPlaceholder = "{network}"
	projectPlaceholder = "{project}"
)

// executorFilled is the set above, as a lookup from placeholder to the
// operator file that supplies it. A placeholder in it must not appear in
// Params or Free: declaring it as a caller argument is how it would stop being
// executor context.
//
// The file name is carried so an unconfigured create can say which file to
// write. "This agent has no flavor configured" is true and leaves an operator
// hunting; naming the file is the difference between a message they can read
// and one they can act on. An empty value means no file supplies it yet, and
// the refusal falls back to the shorter wording rather than inventing a path;
// {dc} was the last such placeholder until cube-cos-api access became a
// setting of its own.
var executorFilled = map[string]string{
	dcPlaceholder:      CubeCOSFileName,
	flavorPlaceholder:  ProfileFileName,
	imagePlaceholder:   ProfileFileName,
	networkPlaceholder: ProfileFileName,
	projectPlaceholder: ProfileFileName,
}

// InstanceProfile is the cluster's answer to "created how?" — everything about
// a new instance except its name.
//
// It is configuration, not a caller argument, for the same reason {dc} is: the
// SaaS choosing a flavour is the SaaS choosing how much of the customer's quota
// to spend, and an injected prompt choosing an image is an injected prompt
// choosing what code runs. An empty field makes the write refuse, so a
// half-configured profile creates nothing.
type InstanceProfile struct {
	Flavor  string
	Image   string
	Network string
	// Project is no longer sent. nova takes the project from the credential's
	// scope, so there is no field to fill and none to get wrong — see the
	// note on create_instance. It stays because it is what the operator
	// declares this agent creates in, and it is what an approval statement
	// tells a person before they agree.
	//
	// That makes it a second statement of something the credential also
	// knows, and two statements can disagree. The credential is the one that
	// decides: internal/openstack refuses outright if Keystone reports a
	// scope other than the one its own configuration names. Cross-checking
	// this field against that one is worth doing where both are wired
	// together, which is not yet anywhere.
	Project string
}

// values renders the profile as the placeholder map the resolver consumes.
func (p InstanceProfile) values() map[string]string {
	return map[string]string{
		flavorPlaceholder:  p.Flavor,
		imagePlaceholder:   p.Image,
		networkPlaceholder: p.Network,
		projectPlaceholder: p.Project,
	}
}

// writeReplayWindow is how long a completed write is remembered for duplicate
// suppression.
//
// It must comfortably exceed every retry horizon above it: the SaaS's two
// minute channel deadline, the approval gate's two minute expiry, and a turn's
// wall-clock ceiling. Fifteen minutes covers all three with room, and is short
// enough that an operator who deliberately re-runs a create after fixing
// something is not told "already done" for the rest of the day.
const writeReplayWindow = 15 * time.Minute

// writeLedger remembers recently completed writes so a retry cannot repeat one.
//
// This is the answer to the duplicate-on-retry problem, and it lives here
// rather than in the model's instructions because a model being careful is not
// a control. A create that succeeded and whose response was lost — a dropped
// channel, a turn that hit its ceiling, an approval that expired mid-flight —
// is retried by machinery above this package, and without a ledger that retry
// makes a second instance: billable, running, and invisible until someone
// notices.
//
// The key is derived from the tool and the fully resolved request, so a repeat
// is recognised by what it would do rather than by anything the caller says.
// Two different names are two different keys and both proceed; the same name
// twice inside the window is one create and one replay.
//
// It is deliberately in memory. An agent restart forgets, which is the right
// trade: the durable alternative is state on the customer's node that must be
// pruned, migrated and reasoned about, and the window this protects is minutes
// long inside one process's lifetime.
type writeLedger struct {
	mu   sync.Mutex
	seen map[string]writeRecord
	now  func() time.Time
}

type writeRecord struct {
	at     time.Time
	output []byte
}

func newWriteLedger() *writeLedger {
	return &writeLedger{seen: map[string]writeRecord{}, now: time.Now}
}

// lookup returns a previous outcome for key if one is still inside the window.
func (l *writeLedger) lookup(key string) ([]byte, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.seen[key]
	if !ok {
		return nil, false
	}
	if l.now().Sub(rec.at) > writeReplayWindow {
		delete(l.seen, key)
		return nil, false
	}
	return rec.output, true
}

// record remembers an outcome, and drops anything that has aged out. Pruning
// on write keeps the map bounded by the number of distinct writes in one
// window rather than by uptime.
func (l *writeLedger) record(key string, out []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, rec := range l.seen {
		if now.Sub(rec.at) > writeReplayWindow {
			delete(l.seen, k)
		}
	}
	l.seen[key] = writeRecord{at: now, output: out}
}

// idempotencyKey derives a stable key from what the request will actually do.
//
// Path and body, not the caller's arguments: two calls that resolve to the same
// request are the same request whatever they were asked with, and a caller
// cannot dodge the ledger by spelling its arguments differently. Body fields
// are sorted so map iteration order cannot make one request look like two.
func idempotencyKey(tool, path string, body map[string]string) string {
	fields := make([]string, 0, len(body))
	for k := range body {
		fields = append(fields, k)
	}
	sort.Strings(fields)
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n", tool, path)
	for _, f := range fields {
		fmt.Fprintf(h, "%s=%s\n", f, body[f])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// resolveWrite fills a Post tool's path and body.
//
// Caller arguments reach only the placeholders the tool declared, and only
// after passing their value set or their shape. Executor-filled placeholders
// come from ctxValues and are never read from args — a caller that supplies one
// is refused rather than ignored, because ignoring it would let a request look
// like it chose something it did not.
func (t Tool) resolveWrite(args map[string]string, ctxValues map[string]string) (string, map[string]string, error) {
	for k := range args {
		if _, filled := executorFilled[k]; filled {
			return "", nil, fmt.Errorf("argument %s is executor context, not a caller argument", k)
		}
		_, enumerated := t.Params[k]
		_, shaped := t.Free[k]
		if !enumerated && !shaped {
			return "", nil, fmt.Errorf("unexpected argument %q", k)
		}
	}

	resolve := func(tok string) (string, error) {
		if !isPlaceholder(tok) {
			return tok, nil
		}
		if file, filled := executorFilled[tok]; filled {
			v := ctxValues[tok]
			if v == "" {
				if file != "" {
					return "", fmt.Errorf("this agent has no %s configured in %s; it cannot create anything until its operator sets one",
						strings.Trim(tok, "{}"), file)
				}
				return "", fmt.Errorf("this agent has no %s configured; it cannot create anything until its operator sets one", strings.Trim(tok, "{}"))
			}
			return v, nil
		}
		v, given := args[tok]
		if !given {
			return "", fmt.Errorf("missing argument %s", tok)
		}
		if values, enumerated := t.Params[tok]; enumerated {
			if !permitted(values, v) {
				return "", fmt.Errorf("value for %s is not in the permitted set", tok)
			}
			return v, nil
		}
		// Shaped. The value is not echoed back for the same reason an
		// out-of-set value is not: an error that repeats the input is an
		// oracle, and here it would also put caller text in the audit reason.
		if !t.Free[tok].admits(v) {
			return "", fmt.Errorf("value for %s is not a %s", tok, t.Free[tok])
		}
		return v, nil
	}

	segs := pathSegments(t.Post)
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		v, err := resolve(seg)
		if err != nil {
			return "", nil, err
		}
		if isPlaceholder(seg) && (strings.ContainsAny(v, "/") || v == "..") {
			return "", nil, fmt.Errorf("value for %s is not a single path segment", seg)
		}
		out = append(out, v)
	}

	body := make(map[string]string, len(t.Body))
	for field, tok := range t.Body {
		v, err := resolve(tok)
		if err != nil {
			return "", nil, err
		}
		body[field] = v
	}
	return "/" + strings.Join(out, "/"), body, nil
}

// callPost performs a write, suppressing a repeat of one already done.
//
// The ledger is consulted before the request and written after it succeeds, so
// a failed write is retryable and a successful one is not repeated. A
// suppressed repeat returns the first call's output and is audited as a replay:
// the customer's log shows that a second request arrived and that nothing
// happened because of it, which is the fact an operator reconciling their
// instance list needs.
func (r *Registry) callPost(ctx context.Context, tool Tool, args map[string]string) ([]byte, error) {
	path, body, err := tool.resolveWrite(args, r.contextValues())
	if err != nil {
		r.audit.RecordToolCall(ToolCall{
			Tool: tool.Name, Args: args, Allowed: false,
			Reason: err.Error(), At: time.Now().UTC(),
		})
		return nil, fmt.Errorf("%w: %v", ErrBadArgument, err)
	}

	key := idempotencyKey(tool.Name, path, body)
	if out, replay := r.writes.lookup(key); replay {
		r.audit.RecordToolCall(ToolCall{
			Tool: tool.Name, Args: args, Path: path, Allowed: true,
			Reason: "replay: an identical write completed within the last " + writeReplayWindow.String() + "; nothing was created",
			At:     time.Now().UTC(), Bytes: len(out),
		})
		return out, nil
	}

	payload, err := encodeBody(tool.Backend, body)
	if err != nil {
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
	out, runErr := r.writerFor(tool.Backend).Post(ctx, path, payload, key, max)
	runErr = asTimeout(ctx, tool.Name, timeout, runErr)

	rec := ToolCall{
		Tool: tool.Name, Args: args, Path: path, Allowed: true,
		At: started.UTC(), Duration: time.Since(started), Bytes: len(out),
	}
	if runErr != nil {
		rec.Reason = runErr.Error()
	}
	r.audit.RecordToolCall(rec)
	if runErr != nil {
		// Not recorded: a write that failed did not happen, and remembering it
		// would turn a transient failure into a permanent refusal to retry.
		//
		// A write that timed out is the uncomfortable case — it may have landed
		// — and it is deliberately left retryable, because the server saw the
		// same idempotency key and a create-once server will collapse it. A
		// server that ignores the key can duplicate here; that residue is
		// stated in the ADR rather than hidden behind a ledger entry that would
		// also block the legitimate retry of a write that truly failed.
		return out, runErr
	}
	r.writes.record(key, out)
	return out, nil
}
