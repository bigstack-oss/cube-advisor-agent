package toolplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// poster records what a write actually sent, so a test can assert the request
// rather than the arguments it was asked with.
type poster struct {
	mu    sync.Mutex
	calls []postCall
	err   error
}

type postCall struct {
	path string
	// raw, not a decoded map: the body is the backend's wire shape now, and
	// nova's is nested. Keeping the bytes lets a test assert the shape that
	// actually leaves rather than one the double chose to impose.
	raw []byte
	key string
}

func (p *poster) Post(_ context.Context, path string, body []byte, key string, _ int) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, postCall{path: path, raw: append([]byte(nil), body...), key: key})
	if p.err != nil {
		return nil, p.err
	}
	return []byte(`{"id":"i-1"}`), nil
}

func (p *poster) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func (p *poster) last() postCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[len(p.calls)-1]
}

// writeRegistry builds a registry at the operate level with a wired writer and
// a configured instance profile — an agent whose operator has enabled writes.
func writeRegistry(t *testing.T, now func() time.Time) (*Registry, *poster, *recorder) {
	t.Helper()
	rec := &recorder{}
	r, err := New(Allowlist, rec, WithLevel(LevelOperate))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.ConfigureCubeCOS("dc1", nil)
	r.ConfigureInstanceProfile(InstanceProfile{
		Flavor: "m1.large", Image: "ubuntu-24.04", Network: "tenant-net", Project: "acme-prod",
	})
	p := &poster{}
	r.SetWriterForTest(BackendOpenStackCompute, p, now)
	return r, p, rec
}

func TestAWriteSendsOnlyWhatTheAllowlistDeclares(t *testing.T) {
	r, p, _ := writeRegistry(t, nil)

	out, err := r.Call(context.Background(), "create_instance", map[string]string{"{name}": "web-03"}, true)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if string(out) != `{"id":"i-1"}` {
		t.Errorf("output = %s", out)
	}
	got := p.last()
	// nova's path, relative to the compute endpoint the transport owns. No
	// host, no version prefix, no project id — none of those are the
	// allowlist's to know.
	if got.path != "/servers" {
		t.Errorf("path = %q, want nova's /servers", got.path)
	}

	// The caller chose the name. Everything else came from the profile, which
	// is the property that makes a free-text parameter tolerable. Asserted on
	// nova's wire shape, because that is what a nova would receive.
	var sent struct {
		Server struct {
			Name      string `json:"name"`
			FlavorRef string `json:"flavorRef"`
			ImageRef  string `json:"imageRef"`
			Networks  []struct {
				UUID string `json:"uuid"`
			} `json:"networks"`
			Project string `json:"project"`
		} `json:"server"`
	}
	if err := json.Unmarshal(got.raw, &sent); err != nil {
		t.Fatalf("body is not nova's shape: %v (%s)", err, got.raw)
	}
	if sent.Server.Name != "web-03" {
		t.Errorf("name = %q", sent.Server.Name)
	}
	if sent.Server.FlavorRef != "m1.large" {
		t.Errorf("flavorRef = %q", sent.Server.FlavorRef)
	}
	if sent.Server.ImageRef != "ubuntu-24.04" {
		t.Errorf("imageRef = %q", sent.Server.ImageRef)
	}
	if len(sent.Server.Networks) != 1 || sent.Server.Networks[0].UUID != "tenant-net" {
		t.Errorf("networks = %+v, want one uuid", sent.Server.Networks)
	}
	// The profile's project scopes the credential; it is not a field, and a
	// server created with one would be a server whose project was named by
	// the request rather than by the token.
	if sent.Server.Project != "" {
		t.Errorf("body names a project (%q); in nova it is the credential's scope", sent.Server.Project)
	}
	if got.key == "" {
		t.Error("no idempotency key was sent")
	}
}

// The caller may not choose what the profile decides, and supplying one is
// refused rather than ignored: a request that looks like it chose an image
// should not quietly get the configured one.
func TestACallerCannotChooseWhatTheProfileDecides(t *testing.T) {
	r, p, _ := writeRegistry(t, nil)

	for _, arg := range []string{"{image}", "{flavor}", "{network}", "{project}"} {
		_, err := r.Call(context.Background(), "create_instance", map[string]string{
			"{name}": "web-03", arg: "attacker-chosen",
		}, true)
		if !errors.Is(err, ErrBadArgument) {
			t.Fatalf("%s: err = %v, want ErrBadArgument", arg, err)
		}
		// The reason matters, not just the refusal. Both this guard and the
		// unknown-argument fallback return ErrBadArgument, so asserting only
		// the sentinel passes with the guard deleted — which is exactly what
		// happened when it was deliberately broken. Pinning the message pins
		// the property: an executor-filled value is refused *as* executor
		// context, rather than happening to be unknown.
		if !strings.Contains(err.Error(), "executor context") {
			t.Errorf("%s was refused as %v; it should be refused as executor context", arg, err)
		}
		if p.count() != 0 {
			t.Errorf("%s: a refused call still sent a request", arg)
		}
	}
}

func TestAnUnconfiguredProfileCreatesNothing(t *testing.T) {
	rec := &recorder{}
	r, err := New(Allowlist, rec, WithLevel(LevelOperate))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.ConfigureCubeCOS("dc1", nil)
	p := &poster{}
	r.SetWriterForTest(BackendOpenStackCompute, p, nil)

	if _, err := r.Call(context.Background(), "create_instance", map[string]string{"{name}": "web-03"}, true); !errors.Is(err, ErrBadArgument) {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if p.count() != 0 {
		t.Error("an agent with no instance profile still created something")
	}
}

// The shape is the whole guard on the one value the caller chooses, so the
// cases that matter are the ones a value set made impossible for free.
func TestTheNameShapeRefusesWhatAValueSetWouldHave(t *testing.T) {
	r, p, _ := writeRegistry(t, nil)

	refused := []struct{ name, why string }{
		{"--force", "a leading hyphen could be read as a flag"},
		{"web/03", "a path separator could compose a segment"},
		{"..", "dot-dot could escape a segment"},
		{"web 03", "a space splits a word downstream"},
		{"web;rm", "a shell metacharacter, inert here and not downstream"},
		{"web.03", "a dot is not a single label"},
		{"WEB03", "upper case is not a DNS label"},
		{"", "an empty name is not a name"},
		{strings.Repeat("a", maxDNSLabel+1), "past the length bound"},
		{"-web", "leading hyphen"},
		{"web-", "trailing hyphen"},
	}
	for _, c := range refused {
		if _, err := r.Call(context.Background(), "create_instance", map[string]string{"{name}": c.name}, true); !errors.Is(err, ErrBadArgument) {
			t.Errorf("%q was admitted (%s): err = %v", c.name, c.why, err)
		}
	}
	if p.count() != 0 {
		t.Errorf("%d refused names still reached the API", p.count())
	}

	for _, ok := range []string{"web-03", "a", "web03", strings.Repeat("a", maxDNSLabel)} {
		if _, err := r.Call(context.Background(), "create_instance", map[string]string{"{name}": ok}, true); err != nil {
			t.Errorf("%q was refused: %v", ok, err)
		}
	}
}

// The duplicate-on-retry case, which is why a create is not a read: the same
// request twice inside the window is one create and one replay.
func TestARetriedWriteDoesNotCreateASecondInstance(t *testing.T) {
	r, p, rec := writeRegistry(t, nil)
	args := map[string]string{"{name}": "web-03"}

	first, err := r.Call(context.Background(), "create_instance", args, true)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := r.Call(context.Background(), "create_instance", args, true)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if p.count() != 1 {
		t.Fatalf("the API was called %d times; a retry created a second instance", p.count())
	}
	if string(first) != string(second) {
		t.Errorf("the replay returned different output: %s vs %s", first, second)
	}
	// The customer's log has to show that a second request arrived and that
	// nothing happened because of it — that is the fact an operator
	// reconciling their instance list needs.
	var replays int
	for _, c := range rec.snapshot() {
		if strings.Contains(c.Reason, "replay") {
			replays++
		}
	}
	if replays != 1 {
		t.Errorf("%d replays audited, want 1", replays)
	}
}

// A different name is a different request and must proceed — the ledger
// suppresses repeats, not creation.
func TestADifferentNameIsADifferentWrite(t *testing.T) {
	r, p, _ := writeRegistry(t, nil)
	for _, n := range []string{"web-03", "web-04"} {
		if _, err := r.Call(context.Background(), "create_instance", map[string]string{"{name}": n}, true); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
	}
	if p.count() != 2 {
		t.Errorf("the API was called %d times, want 2", p.count())
	}
}

// Past the window the same request is a new intent, not a retry: an operator
// who deliberately re-creates something must not be told "already done" for the
// rest of the process's life.
func TestTheSameWriteProceedsOnceTheWindowHasPassed(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	r, p, _ := writeRegistry(t, clock)
	args := map[string]string{"{name}": "web-03"}

	if _, err := r.Call(context.Background(), "create_instance", args, true); err != nil {
		t.Fatalf("first: %v", err)
	}
	now = now.Add(writeReplayWindow + time.Minute)
	if _, err := r.Call(context.Background(), "create_instance", args, true); err != nil {
		t.Fatalf("after the window: %v", err)
	}
	if p.count() != 2 {
		t.Errorf("the API was called %d times, want 2", p.count())
	}
}

// A write that failed did not happen, so it stays retryable. Remembering it
// would turn one transient error into a permanent refusal to try again.
func TestAFailedWriteIsNotRemembered(t *testing.T) {
	r, p, _ := writeRegistry(t, nil)
	p.err = errors.New("api unavailable")
	args := map[string]string{"{name}": "web-03"}

	if _, err := r.Call(context.Background(), "create_instance", args, true); err == nil {
		t.Fatal("a failing write reported success")
	}
	p.err = nil
	if _, err := r.Call(context.Background(), "create_instance", args, true); err != nil {
		t.Fatalf("the retry of a failed write was refused: %v", err)
	}
	if p.count() != 2 {
		t.Errorf("the API was called %d times, want 2", p.count())
	}
}

// The refusal a cluster's level produces is the one refusal permitted to say
// why, and its text is the shared constant both repositories import.
func TestALevelRefusalIsLegibleAndShared(t *testing.T) {
	rec := &recorder{}
	r, err := New(Allowlist, rec) // no WithLevel: the default, observe
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.Call(context.Background(), "create_instance", map[string]string{"{name}": "web-03"}, true)
	if !errors.Is(err, ErrRefusedAtLevel) {
		t.Fatalf("err = %v, want ErrRefusedAtLevel", err)
	}
	if !strings.Contains(err.Error(), tunnelproto.RefusedAtLevelReason) {
		t.Errorf("refusal does not carry the shared reason: %v", err)
	}
	// Specific about policy, silent about the allowlist: the exception to the
	// uniform-refusal rule is narrow, and this is what keeps it narrow.
	if strings.Contains(err.Error(), "create_instance") || strings.Contains(err.Error(), "web-03") {
		t.Errorf("the level refusal names a tool or a value: %v", err)
	}
	// Refused before resolution, so the audit shows the decision and not an
	// argument the call was never going to use.
	var refusals int
	for _, c := range rec.snapshot() {
		if !c.Allowed && strings.Contains(c.Reason, "action level") {
			refusals++
		}
	}
	if refusals != 1 {
		t.Errorf("%d level refusals audited, want 1", refusals)
	}
}

// The level governs the configuring classes and nothing else. Probes are gated
// by whether a runner is wired, and reads by nothing — the ordering of the
// impact constants is not a permission scale.
func TestTheLevelDoesNotGateReadsOrProbes(t *testing.T) {
	for _, l := range []Level{LevelObserve, LevelOperate, LevelInternal} {
		r, err := New(Allowlist, &recorder{}, WithLevel(l))
		if err != nil {
			t.Fatalf("New at %s: %v", l, err)
		}
		if r.refusedByLevel(ImpactRead) {
			t.Errorf("level %s refused a read", l)
		}
		if r.refusedByLevel(ImpactScratch) {
			t.Errorf("level %s refused a probe; scratch is gated by the runner, not the level", l)
		}
	}
}

func TestOnlyTheInternalLevelServesTheInternalClass(t *testing.T) {
	cases := []struct {
		level  Level
		impact Impact
		served bool
	}{
		{LevelObserve, ImpactOperate, false},
		{LevelObserve, ImpactInternal, false},
		{LevelOperate, ImpactOperate, true},
		{LevelOperate, ImpactInternal, false},
		{LevelInternal, ImpactOperate, true},
		{LevelInternal, ImpactInternal, true},
	}
	for _, c := range cases {
		r, err := New(nil, &recorder{}, WithLevel(c.level))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if served := !r.refusedByLevel(c.impact); served != c.served {
			t.Errorf("level %s, impact %s: served = %v, want %v", c.level, c.impact, served, c.served)
		}
	}
}

// A read path cannot declare a configuring class: a GET changes nothing, so the
// two fields contradict each other and a cluster at the internal level would
// otherwise serve it as though it did.
func TestAReadPathCannotClaimToConfigure(t *testing.T) {
	_, err := New([]Tool{{
		Name: "sneaky", Get: "/api/v1/datacenters/{dc}/things", Impact: ImpactOperate,
	}}, &recorder{}, WithLevel(LevelInternal))
	if err == nil {
		t.Fatal("a GET declaring a configuring class registered")
	}
	if !strings.Contains(err.Error(), "changes nothing") {
		t.Errorf("error should say why: %v", err)
	}
}

// A free parameter is the one place the allowlist stops enumerating, so the
// rules around it are the ones worth pinning.
func TestFreeParametersAreBoundedByTheirDeclaration(t *testing.T) {
	base := func(mut func(*Tool)) []Tool {
		tool := Tool{
			Name: "w", Post: "/api/v1/x", Body: map[string]string{"n": "{n}"},
			Free: map[string]Shape{"{n}": ShapeDNSLabel}, Impact: ImpactOperate,
		}
		mut(&tool)
		return []Tool{tool}
	}
	cases := []struct {
		name string
		mut  func(*Tool)
		want string
	}{
		{"unshaped", func(t *Tool) { t.Free["{n}"] = 0 }, "wildcard"},
		{"unknown shape", func(t *Tool) { t.Free["{n}"] = Shape(99) }, "does not know"},
		{"both enumerated and shaped", func(t *Tool) { t.Params = map[string][]string{"{n}": {"a"}} }, "one rule"},
		{"declared but unused", func(t *Tool) { t.Free["{spare}"] = ShapeDNSLabel }, "never uses"},
		{"a write with no body", func(t *Tool) { t.Body = nil }, "no body"},
		{"executor context as a caller argument", func(t *Tool) {
			t.Body["f"] = "{flavor}"
			t.Free["{flavor}"] = ShapeDNSLabel
		}, "executor context"},
	}
	for _, c := range cases {
		_, err := New(base(c.mut), &recorder{}, WithLevel(LevelOperate))
		if err == nil {
			t.Errorf("%s: registered", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error should contain %q: %v", c.name, c.want, err)
		}
	}
	// A free parameter on a read is refused: the widening belongs to the write
	// path that asked for it, not to every tool by inheritance.
	if _, err := New([]Tool{{
		Name: "r", Get: "/api/v1/{n}", Free: map[string]Shape{"{n}": ShapeDNSLabel}, Impact: ImpactRead,
	}}, &recorder{}); err == nil {
		t.Error("a read with a free parameter registered")
	}
}
