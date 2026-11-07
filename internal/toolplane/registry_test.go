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

// newTestRegistry returns a registry over the shipped tools whose executor is
// captured rather than run, so the suite never shells out.
func newTestRegistry(t *testing.T) (*Registry, *recorder, *[]string) {
	t.Helper()
	rec := &recorder{}
	r, err := New(Tools, rec)
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

func TestTheShippedToolsAreTheSandboxOnly(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	if got := strings.Join(r.Names(), ","); got != "shell_read" {
		t.Errorf("Names = %q, want only shell_read", got)
	}
}

func TestANonSandboxToolCannotRegister(t *testing.T) {
	if _, err := New([]Tool{{Name: "cluster_check"}}, &recorder{}); err == nil {
		t.Error("a tool that is not the sandbox registered")
	}
}

func TestUnknownToolIsRefusedAndAudited(t *testing.T) {
	r, rec, _ := newTestRegistry(t)
	_, err := r.Call(context.Background(), "cluster_check", nil)
	if !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("err = %v, want ErrUnknownTool", err)
	}
	if len(rec.calls) != 1 || rec.calls[0].Allowed {
		t.Fatalf("refusal not audited: %+v", rec.calls)
	}
}

// Every call lands in the log, allowed or not.
func TestEveryCallIsAudited(t *testing.T) {
	r, rec, _ := newTestRegistry(t)
	ctx := context.Background()
	_, _ = r.Call(ctx, "shell_read", map[string]string{"command": "true"}) // allowed
	_, _ = r.Call(ctx, "shell_read", map[string]string{"cmd": "true"})     // refused: bad argument
	_, _ = r.Call(ctx, "nonexistent", nil)                                 // refused: unknown

	if len(rec.calls) != 3 {
		t.Fatalf("audited %d calls, want 3", len(rec.calls))
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
	if allowed != 1 {
		t.Errorf("allowed = %d, want 1", allowed)
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
	if _, err := New(Tools, nil); err == nil {
		t.Error("a registry without an auditor was allowed; every call must be inspectable")
	}
}

type closableBuffer struct{ b strings.Builder }

func (c *closableBuffer) Write(p []byte) (int, error) { return c.b.Write(p) }
func (c *closableBuffer) Close() error                { return nil }
func (c *closableBuffer) String() string              { return c.b.String() }

func TestTheToolTimeoutBoundsTheCall(t *testing.T) {
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
	if _, err := r.Call(context.Background(), "shell_read", map[string]string{"command": "true"}); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got < 50*time.Second || got > 60*time.Second {
		t.Errorf("shell_read deadline ≈%s, want its declared 60s", got.Round(time.Second))
	}
}

// A killed process reports the timeout, not the raw kill signal (#20).
func TestATimedOutCallNamesItsLimit(t *testing.T) {
	rec := &recorder{}
	r, err := New([]Tool{{Name: "slow", Sandbox: true, Timeout: 20 * time.Millisecond}}, rec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.run = func(ctx context.Context, argv []string, maxBytes int) ([]byte, error) {
		<-ctx.Done()
		return nil, fmt.Errorf("signal: killed")
	}
	out, err := r.Call(context.Background(), "slow", map[string]string{"command": "sleep 1"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.Contains(string(out), "20ms") {
		t.Errorf("result should name the limit that fired: %q", out)
	}
	if got := rec.calls[0].Reason; strings.Contains(got, "signal: killed") {
		t.Errorf("audit reason still shows the raw kill signal: %q", got)
	}
}

func TestANegativeTimeoutCannotRegister(t *testing.T) {
	if _, err := New([]Tool{{Name: "broken", Sandbox: true, Timeout: -time.Second}}, &recorder{}); err == nil {
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
	for _, tool := range Tools {
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
