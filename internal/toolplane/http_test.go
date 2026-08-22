package toolplane

import (
	"context"
	"strings"
	"testing"
)

// A Get tool that takes no model input: the datacenter in the path is the
// agent's own cluster identity, filled by the executor, never chosen by the
// SaaS.
func healthsTool() Tool {
	return Tool{
		Name:        "cube_cos_healths",
		Description: "Cluster health summary from cube-cos-api.",
		Get:         "/api/v1/datacenters/{dc}/healths",
		ReadOnly:    true,
	}
}

// A Get tool with a model parameter, to exercise the enum machinery. Not
// shipped — its enum values are illustrative — so the suite proves the path
// without the allowlist guessing an endpoint's real value set.
func serviceHealthTool() Tool {
	return Tool{
		Name:        "cube_cos_service_health",
		Description: "Health of one service from cube-cos-api.",
		Get:         "/api/v1/datacenters/{dc}/healths/services/{svc}",
		Params:      map[string][]string{"{svc}": {"Storage", "Compute"}},
		ReadOnly:    true,
	}
}

// fakeCubeCOS records the path it was asked for and returns a canned body.
type fakeCubeCOS struct {
	lastPath string
	body     string
	err      error
}

func (f *fakeCubeCOS) Get(_ context.Context, path string, _ int) ([]byte, error) {
	f.lastPath = path
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.body), nil
}

func newGetRegistry(t *testing.T, tools []Tool, dc string) (*Registry, *recorder, *fakeCubeCOS) {
	t.Helper()
	rec := &recorder{}
	r, err := New(tools, rec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fake := &fakeCubeCOS{body: `{"ok":true}`}
	r.SetCubeCOSForTest(dc, fake)
	return r, rec, fake
}

func TestAGetToolFillsTheDatacenterFromTheAgentNotTheCaller(t *testing.T) {
	r, _, fake := newGetRegistry(t, []Tool{healthsTool()}, "sky-dc")
	out, err := r.Call(context.Background(), "cube_cos_healths", nil)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if fake.lastPath != "/api/v1/datacenters/sky-dc/healths" {
		t.Errorf("path = %q, want the agent's own datacenter filled in", fake.lastPath)
	}
	if string(out) != `{"ok":true}` {
		t.Errorf("out = %q", out)
	}
}

func TestTheCallerCannotSupplyTheDatacenter(t *testing.T) {
	// {dc} is the agent's identity, not a model parameter. Passing it is an
	// unexpected argument, refused like any other.
	r, _, _ := newGetRegistry(t, []Tool{healthsTool()}, "sky-dc")
	_, err := r.Call(context.Background(), "cube_cos_healths", map[string]string{"dc": "other-dc"})
	if err == nil {
		t.Fatal("the caller supplied a datacenter and it was accepted")
	}
}

func TestAModelParameterIsEnumCheckedInThePath(t *testing.T) {
	r, _, fake := newGetRegistry(t, []Tool{serviceHealthTool()}, "sky-dc")
	if _, err := r.Call(context.Background(), "cube_cos_service_health", map[string]string{"{svc}": "Storage"}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if fake.lastPath != "/api/v1/datacenters/sky-dc/healths/services/Storage" {
		t.Errorf("path = %q", fake.lastPath)
	}
	if _, err := r.Call(context.Background(), "cube_cos_service_health", map[string]string{"{svc}": "Secrets"}); err == nil {
		t.Error("a value outside the enum reached the path")
	}
}

func TestAPathValueCannotTraverse(t *testing.T) {
	// Defence in depth: even if an allowlist enum were careless, a value with a
	// separator or dot-dot must never compose a path segment that escapes the
	// intended resource.
	tool := Tool{
		Name: "probe", Get: "/api/v1/datacenters/{dc}/nodes/{node}",
		Params: map[string][]string{"{node}": {"../../secrets", "ok"}}, ReadOnly: true,
	}
	r, _, _ := newGetRegistry(t, []Tool{tool}, "sky-dc")
	if _, err := r.Call(context.Background(), "probe", map[string]string{"{node}": "../../secrets"}); err == nil {
		t.Error("a traversing path value was accepted")
	}
}

func TestAGetToolIsAuditedByPathNeverByToken(t *testing.T) {
	r, rec, _ := newGetRegistry(t, []Tool{healthsTool()}, "sky-dc")
	if _, err := r.Call(context.Background(), "cube_cos_healths", nil); err != nil {
		t.Fatal(err)
	}
	last := rec.calls[len(rec.calls)-1]
	if !last.Allowed || last.Tool != "cube_cos_healths" {
		t.Fatalf("audit = %+v", last)
	}
	if last.Path != "/api/v1/datacenters/sky-dc/healths" {
		t.Errorf("audit path = %q, want the resolved path recorded", last.Path)
	}
	// The token lives in the getter and must never appear in the audit record.
	blob := last.Path + strings.Join(last.Argv, " ") + last.Reason
	if strings.Contains(strings.ToLower(blob), "bearer") || strings.Contains(blob, "Authorization") {
		t.Error("the audit record carries auth material")
	}
}

func TestAnUnconfiguredGetToolIsAModelReadableRefusal(t *testing.T) {
	// A shipped Get tool on an agent whose cube-cos-api client was never wired
	// must refuse cleanly, not panic or shell out.
	rec := &recorder{}
	r, err := New([]Tool{healthsTool()}, rec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := r.Call(context.Background(), "cube_cos_healths", nil); err == nil {
		t.Error("an unconfigured Get tool answered instead of refusing")
	}
}

func TestAToolCannotBeBothCommandAndGet(t *testing.T) {
	_, err := New([]Tool{{
		Name: "both", Argv: []string{"echo"}, Get: "/x", ReadOnly: true,
	}}, &recorder{})
	if err == nil {
		t.Error("a tool declaring both an argv and a GET path registered")
	}
}

func TestAGetToolStillMustBeReadOnly(t *testing.T) {
	_, err := New([]Tool{{Name: "w", Get: "/x", ReadOnly: false}}, &recorder{})
	if err == nil {
		t.Error("a non-read-only Get tool registered")
	}
}

func TestAGetTemplateMustDeclareItsModelPlaceholders(t *testing.T) {
	_, err := New([]Tool{{
		Name: "u", Get: "/api/v1/datacenters/{dc}/nodes/{node}", ReadOnly: true,
	}}, &recorder{})
	if err == nil {
		t.Error("a GET path with an undeclared placeholder registered")
	}
}

func TestTheShippedGetToolsRegister(t *testing.T) {
	// The three overview reads ship in the allowlist and must be well-formed.
	got := map[string]bool{}
	for _, tool := range Allowlist {
		if tool.Get != "" {
			got[tool.Name] = true
		}
	}
	for _, want := range []string{"cube_cos_healths", "cube_cos_nodes", "cube_cos_events"} {
		if !got[want] {
			t.Errorf("%s is not in the shipped allowlist", want)
		}
	}
}

func TestTheDatacenterPlaceholderIsNotAnArgumentEvenByItsRealKey(t *testing.T) {
	// {dc} is not in Params, so passing it under any key — "dc" or "{dc}" — is
	// an unexpected argument. This closes the door the previous test only
	// half-shut: not just that "dc" is unknown, but that the executor slot
	// itself can never be driven from the caller.
	r, _, fake := newGetRegistry(t, []Tool{healthsTool()}, "sky-dc")
	if _, err := r.Call(context.Background(), "cube_cos_healths", map[string]string{"{dc}": "evil"}); err == nil {
		t.Fatal("the datacenter was supplied under its placeholder key")
	}
	if fake.lastPath == "/api/v1/datacenters/evil/healths" {
		t.Fatal("a caller-supplied datacenter reached the path")
	}
}

func TestADatacenterWithoutAGetterStillRefuses(t *testing.T) {
	// Configured with a datacenter but no client (getter nil): the default
	// getter must refuse, not answer with an empty body. Covers the case the
	// empty-datacenter check does not reach.
	rec := &recorder{}
	r, err := New([]Tool{healthsTool()}, rec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.ConfigureCubeCOS("sky-dc", nil) // datacenter set, client absent
	if _, err := r.Call(context.Background(), "cube_cos_healths", nil); err == nil {
		t.Error("a configured datacenter with no client answered instead of refusing")
	}
}
