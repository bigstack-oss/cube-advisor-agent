package toolplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// catalogTool is a small stand-in for the shipped read: two keys, so a miss
// and a hit are both expressible without depending on which overviews the
// product happens to serve this week.
func catalogTool() Tool {
	return Tool{
		Name:        "cube_cos_read",
		Description: "Read one overview from cube-cos-api.",
		Catalog: map[string]string{
			"healths": "/api/v1/datacenters/{dc}/healths",
			"nodes":   "/api/v1/datacenters/{dc}/nodes",
		},
		Impact: ImpactRead,
	}
}

func TestACatalogueKeySelectsItsPathAndTheAgentFillsTheDatacenter(t *testing.T) {
	r, _, fake := newGetRegistry(t, []Tool{catalogTool()}, "sky-dc")

	out, err := r.Call(context.Background(), "cube_cos_read", map[string]string{"resource": "nodes"}, true)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if fake.lastPath != "/api/v1/datacenters/sky-dc/nodes" {
		t.Errorf("path = %q, want the key's template with the agent's own datacenter", fake.lastPath)
	}
	if string(out) != `{"ok":true}` {
		t.Errorf("out = %q", out)
	}
}

// The set is closed. A key the catalogue does not hold is refused before
// anything is fetched, and no part of the caller's string reaches a path.
func TestAKeyOutsideTheCatalogueIsRefused(t *testing.T) {
	r, rec, fake := newGetRegistry(t, []Tool{catalogTool()}, "sky-dc")

	_, err := r.Call(context.Background(), "cube_cos_read", map[string]string{"resource": "settings"}, true)
	if !errors.Is(err, ErrBadArgument) {
		t.Fatalf("err = %v, want a bad-argument refusal", err)
	}
	if fake.lastPath != "" {
		t.Errorf("a refused key still reached the API at %q", fake.lastPath)
	}
	if len(rec.calls) != 1 || rec.calls[0].Allowed {
		t.Fatal("the refusal was not audited as a refusal")
	}
}

// A path the API serves but the catalogue does not admit is unreachable for
// the same reason any other unlisted string is: it is not a key. Held-back
// reads are the case that matters — settings and licenses are in the API and
// must not be fetchable through this tool.
func TestAHeldBackReadIsNotReachableThroughTheCatalogue(t *testing.T) {
	for _, attempt := range []string{
		"settings",
		"licenses",
		"me",
		"supportFiles",
		"/api/v1/datacenters/{dc}/settings",
		"../settings",
	} {
		if _, ok := CubeCOSReads[attempt]; ok {
			t.Errorf("%q is a catalogue key; a held-back read is reachable", attempt)
		}
	}
}

// Nothing on this path can express a write. The catalogue holds paths, the
// method is not a field, and the fetch goes through the read client — so a
// caller has no way to name one.
func TestACatalogueReadCannotExpressAWrite(t *testing.T) {
	for key, path := range CubeCOSReads {
		if strings.Contains(strings.ToUpper(key), "POST") || strings.Contains(strings.ToUpper(key), "DELETE") {
			t.Errorf("catalogue key %q reads like a method, not a resource", key)
		}
		if !strings.HasPrefix(path, "/api/v1/") {
			t.Errorf("catalogue key %q maps to %q, which is not a cube-cos-api path", key, path)
		}
	}
	// The shipped entry declares no write field, and validate would refuse it
	// alongside a catalogue anyway — a tool is exactly one kind.
	_, err := New([]Tool{{
		Name:    "both",
		Catalog: map[string]string{"x": "/api/v1/x"},
		Post:    "/api/v1/x",
		Body:    map[string]string{"a": "b"},
		Impact:  ImpactRead,
	}}, &recorder{})
	if err == nil {
		t.Error("a tool that is both a catalogue read and a write registered")
	}
}

// A second argument is not a place to smuggle anything: the key is the only
// thing a caller supplies.
func TestACatalogueReadTakesNoOtherArgument(t *testing.T) {
	r, _, fake := newGetRegistry(t, []Tool{catalogTool()}, "sky-dc")

	_, err := r.Call(context.Background(), "cube_cos_read", map[string]string{
		"resource": "nodes",
		"watch":    "true",
	}, true)
	if !errors.Is(err, ErrBadArgument) {
		t.Fatalf("err = %v, want a bad-argument refusal", err)
	}
	if fake.lastPath != "" {
		t.Errorf("the call reached the API at %q despite an unexpected argument", fake.lastPath)
	}
}

func TestACatalogueReadWithoutItsKeyIsRefused(t *testing.T) {
	r, _, _ := newGetRegistry(t, []Tool{catalogTool()}, "sky-dc")

	if _, err := r.Call(context.Background(), "cube_cos_read", nil, true); !errors.Is(err, ErrBadArgument) {
		t.Fatalf("err = %v, want a bad-argument refusal", err)
	}
}

// The result cap and its marker apply here exactly as they do to a hand-written
// read — both forms share one fetch, and tool-0010 measures whether the model
// reports a cut it was told about.
func TestACatalogueReadIsCappedAndSaysSo(t *testing.T) {
	rec := &recorder{}
	tool := catalogTool()
	tool.MaxOutputBytes = 64
	r, err := New([]Tool{tool}, rec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.SetCubeCOSForTest("sky-dc", &fakeCubeCOS{
		body: strings.Repeat("x", 64),
		err:  fmt.Errorf("%w at 64 bytes", ErrOutputTruncated),
	})

	out, err := r.Call(context.Background(), "cube_cos_read", map[string]string{"resource": "healths"}, true)
	if err != nil {
		t.Fatalf("a truncated read must succeed, got %v", err)
	}
	if !strings.Contains(string(out), "truncated after") {
		t.Errorf("the truncation marker did not reach the caller: %q", out)
	}
	if len(rec.calls) != 1 || !rec.calls[0].Truncated {
		t.Error("the audit record does not say the result was truncated")
	}
}

// An agent with no cube-cos-api client refuses rather than fetching from a
// path built around an empty datacenter.
func TestACatalogueReadWithoutADatacenterIsRefused(t *testing.T) {
	r, err := New([]Tool{catalogTool()}, &recorder{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := r.Call(context.Background(), "cube_cos_read", map[string]string{"resource": "healths"}, true); err == nil {
		t.Fatal("a catalogue read succeeded with no datacenter configured")
	}
}

// Registration rules specific to the catalogue form.
func TestACatalogueEntryMustBeAWellFormedRead(t *testing.T) {
	cases := []struct {
		name string
		tool Tool
	}{
		{"configuring class", Tool{
			Name: "c", Catalog: map[string]string{"x": "/api/v1/x"}, Impact: ImpactOperate,
		}},
		{"declares parameters", Tool{
			Name: "c", Catalog: map[string]string{"x": "/api/v1/x"},
			Params: map[string][]string{"{y}": {"1"}}, Impact: ImpactRead,
		}},
		{"relative path", Tool{
			Name: "c", Catalog: map[string]string{"x": "api/v1/x"}, Impact: ImpactRead,
		}},
		{"unfilled placeholder", Tool{
			Name: "c", Catalog: map[string]string{"x": "/api/v1/datacenters/{dc}/nodes/{node}"}, Impact: ImpactRead,
		}},
		{"empty key", Tool{
			Name: "c", Catalog: map[string]string{"": "/api/v1/x"}, Impact: ImpactRead,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New([]Tool{tc.tool}, &recorder{}); err == nil {
				t.Errorf("a catalogue tool with %s registered", tc.name)
			}
		})
	}
}

// The shipped catalogue is served at every level, observe included: reading is
// what observe is for, and widening the read surface widens it for the
// clusters that allow nothing else. Stated as a test so the property is a
// decision on the record rather than a consequence nobody wrote down.
func TestTheCatalogueIsServedAtObserve(t *testing.T) {
	r, err := New(Allowlist, &recorder{}, WithLevel(LevelObserve))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var found bool
	for _, n := range r.Names() {
		if n == "cube_cos_read" {
			found = true
		}
	}
	if !found {
		t.Error("cube_cos_read is not offered at observe; the read surface must not need a raised level")
	}
}
