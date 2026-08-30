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

// fakeCluster stands in for rbd and fio: it records every argv, tracks which
// scratch images "exist", and lets a test decide how the measurement behaves.
// Nothing here shells out, so the suite exercises the lifecycle rather than
// the storage stack.
type fakeCluster struct {
	mu     sync.Mutex
	argvs  [][]string
	images map[string]bool

	// measure is what the fio step does. Default: succeed with plausible JSON.
	measure func(ctx context.Context) ([]byte, error)
}

func newFakeCluster() *fakeCluster {
	return &fakeCluster{images: map[string]bool{}}
}

func (f *fakeCluster) run(ctx context.Context, argv []string, _ int) ([]byte, error) {
	// A cancelled context runs nothing, exactly as exec.CommandContext refuses
	// to start a process on one. Without this the double would happily "clean
	// up" on a dead context and the cleanup tests would pass against code that
	// leaks in production — which is precisely what they exist to catch.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f.mu.Lock()
	f.argvs = append(f.argvs, argv)
	f.mu.Unlock()

	switch {
	case argv[0] == "rbd" && argv[1] == "create":
		f.mu.Lock()
		f.images[argv[len(argv)-1]] = true
		f.mu.Unlock()
		return nil, nil
	case argv[0] == "rbd" && argv[1] == "rm":
		name := argv[2]
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		f.mu.Lock()
		delete(f.images, name)
		f.mu.Unlock()
		return nil, nil
	case argv[0] == "rbd" && argv[1] == "ls":
		f.mu.Lock()
		defer f.mu.Unlock()
		var names []string
		for n := range f.images {
			names = append(names, n)
		}
		return []byte(strings.Join(names, "\n")), nil
	case argv[0] == "fio":
		if f.measure != nil {
			return f.measure(ctx)
		}
		return []byte(`{"jobs":[{"write":{"iops":1234.5,"bw":4938,"lat_ns":{"mean":9000}},"read":{"iops":0,"bw":0}}]}`), nil
	}
	return nil, fmt.Errorf("fakeCluster: unexpected argv %v", argv)
}

func (f *fakeCluster) live() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for n := range f.images {
		out = append(out, n)
	}
	return out
}

func (f *fakeCluster) ran(prefix ...string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
outer:
	for _, argv := range f.argvs {
		if len(argv) < len(prefix) {
			continue
		}
		for i, p := range prefix {
			if argv[i] != p {
				continue outer
			}
		}
		return true
	}
	return false
}

func newTestProbeRunner(t *testing.T, f *fakeCluster) (*ProbeRunner, *recorder) {
	t.Helper()
	rec := &recorder{}
	pr, err := NewProbeRunner(Probes, rec)
	if err != nil {
		t.Fatalf("NewProbeRunner: %v", err)
	}
	pr.SetRunnerForTest(f.run)
	return pr, rec
}

// waitFor polls until cond holds or the test would otherwise hang on a
// goroutine that never finished.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestShippedProbesRegister(t *testing.T) {
	if _, err := NewProbeRunner(Probes, &recorder{}); err != nil {
		t.Fatalf("the shipped probes do not register: %v", err)
	}
}

// Start hands back a run id without waiting for the measurement: that is the
// property that keeps a 30-second fio out of the timeout ladder.
func TestStartReturnsBeforeTheMeasurementFinishes(t *testing.T) {
	f := newFakeCluster()
	release := make(chan struct{})
	f.measure = func(context.Context) ([]byte, error) {
		<-release
		return []byte(`{"jobs":[{"write":{"iops":1,"bw":1,"lat_ns":{"mean":1}},"read":{}}]}`), nil
	}
	pr, _ := newTestProbeRunner(t, f)

	id, err := pr.Start(context.Background(), "probe_fio_volume")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	res, err := pr.Status(id)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if res.State != ProbeRunning {
		t.Fatalf("state = %s, want running while the measurement is blocked", res.State)
	}
	close(release)
	waitFor(t, "the run to finish", func() bool {
		r, _ := pr.Status(id)
		return r.State == ProbeDone
	})
}

func TestAFinishedRunReportsParsedMetricsNotProse(t *testing.T) {
	f := newFakeCluster()
	pr, _ := newTestProbeRunner(t, f)

	id, err := pr.Start(context.Background(), "probe_fio_volume")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, "the run to finish", func() bool {
		r, _ := pr.Status(id)
		return r.State != ProbeRunning
	})
	res, _ := pr.Status(id)
	if res.State != ProbeDone {
		t.Fatalf("state = %s (%s), want done", res.State, res.Error)
	}
	if got := res.Metrics["write_iops"]; got != 1234.5 {
		t.Errorf("write_iops = %v, want 1234.5 parsed from fio's own JSON", got)
	}
	if res.Ended == nil {
		t.Error("a finished run should carry an end time")
	}
}

// Cleanup after the ordinary path: the scratch image is gone when the run ends.
func TestScratchIsDeletedAfterANormalRun(t *testing.T) {
	f := newFakeCluster()
	pr, _ := newTestProbeRunner(t, f)

	id, _ := pr.Start(context.Background(), "probe_fio_volume")
	waitFor(t, "the run to finish", func() bool {
		r, _ := pr.Status(id)
		return r.State != ProbeRunning
	})
	waitFor(t, "the scratch image to be deleted", func() bool { return len(f.live()) == 0 })
}

// The load-bearing test. A measurement killed by its own deadline must still
// have its scratch deleted — cleanup that inherited the cancelled context
// would silently skip, which is exactly how orphans are made.
func TestScratchIsDeletedEvenWhenTheProbesOwnContextTimesOut(t *testing.T) {
	f := newFakeCluster()
	f.measure = func(ctx context.Context) ([]byte, error) {
		<-ctx.Done() // outlive the budget
		return nil, ctx.Err()
	}
	pr, _ := newTestProbeRunner(t, f)

	// A budget short enough that the measurement is killed by it.
	short := Probes[0]
	short.Budget = 30 * time.Millisecond
	pr.probes[short.Name] = short

	id, err := pr.Start(context.Background(), "probe_fio_volume")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, "the run to fail on its budget", func() bool {
		r, _ := pr.Status(id)
		return r.State == ProbeFailed
	})
	res, _ := pr.Status(id)
	if !strings.Contains(res.Error, "budget") {
		t.Errorf("error = %q, want it to name the budget", res.Error)
	}
	waitFor(t, "cleanup to run despite the timeout", func() bool { return len(f.live()) == 0 })
	if !f.ran("rbd", "rm") {
		t.Error("teardown never ran after a timed-out measurement")
	}
}

// The sweeper is what covers a killed process: scratch that belongs to no live
// run is litter, and a fresh runner is exactly the case where none of it does.
func TestSweeperRemovesScratchLeftByAPreviousProcess(t *testing.T) {
	f := newFakeCluster()
	f.images[ScratchPrefix+"deadbeefdeadbeef"] = true // left by a process that died
	f.images["someone-elses-image"] = true            // not ours, not a candidate

	pr, _ := newTestProbeRunner(t, f)
	if n := pr.Sweep(context.Background()); n != 1 {
		t.Fatalf("swept %d, want exactly the one prefixed orphan", n)
	}
	live := f.live()
	if len(live) != 1 || live[0] != "someone-elses-image" {
		t.Errorf("remaining images = %v, want only the image we do not own", live)
	}
}

// A live run's scratch is not litter, however keen the sweeper is.
func TestSweeperLeavesALiveRunAlone(t *testing.T) {
	f := newFakeCluster()
	release := make(chan struct{})
	f.measure = func(context.Context) ([]byte, error) {
		<-release
		return []byte(`{"jobs":[{"write":{"iops":1,"bw":1,"lat_ns":{"mean":1}},"read":{}}]}`), nil
	}
	pr, _ := newTestProbeRunner(t, f)

	id, _ := pr.Start(context.Background(), "probe_fio_volume")
	waitFor(t, "the scratch image to exist", func() bool { return len(f.live()) == 1 })

	if n := pr.Sweep(context.Background()); n != 0 {
		t.Fatalf("swept %d, want 0 while the run is live", n)
	}
	if len(f.live()) != 1 {
		t.Error("the sweeper deleted a live run's scratch")
	}
	close(release)
	waitFor(t, "the run to finish", func() bool {
		r, _ := pr.Status(id)
		return r.State != ProbeRunning
	})
}

// Declining is better than accumulating: a probe that starts on top of litter
// doubles the load and makes the litter harder to attribute.
func TestStartDeclinesWhenOrphansArePresent(t *testing.T) {
	f := newFakeCluster()
	f.images[ScratchPrefix+"0123456789abcdef"] = true
	pr, rec := newTestProbeRunner(t, f)

	_, err := pr.Start(context.Background(), "probe_fio_volume")
	if !errors.Is(err, ErrProbeBusy) {
		t.Fatalf("err = %v, want ErrProbeBusy", err)
	}
	if f.ran("fio") {
		t.Error("a measurement ran despite the pre-flight refusal")
	}
	var refused bool
	for _, c := range rec.snapshot() {
		if c.Tool == "probe_start" && !c.Allowed {
			refused = true
		}
	}
	if !refused {
		t.Error("the refusal was not audited")
	}
}

func TestAnUnknownProbeIsRefusedAndAudited(t *testing.T) {
	f := newFakeCluster()
	pr, rec := newTestProbeRunner(t, f)

	if _, err := pr.Start(context.Background(), "probe_delete_everything"); !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("err = %v, want ErrUnknownTool", err)
	}
	calls := rec.snapshot()
	if len(calls) != 1 || calls[0].Allowed {
		t.Errorf("an unknown probe should be audited as refused: %+v", calls)
	}
}

func TestAnUnknownRunIdIsAnError(t *testing.T) {
	pr, _ := newTestProbeRunner(t, newFakeCluster())
	if _, err := pr.Status("not-a-run"); !errors.Is(err, ErrNoSuchRun) {
		t.Fatalf("err = %v, want ErrNoSuchRun", err)
	}
}

// Every bound is in the argv, so a caller cannot make a probe run longer or
// heavier than the allowlist says.
func TestTheMeasurementCarriesItsBoundsLiterally(t *testing.T) {
	f := newFakeCluster()
	pr, _ := newTestProbeRunner(t, f)

	id, _ := pr.Start(context.Background(), "probe_fio_volume")
	waitFor(t, "the run to finish", func() bool {
		r, _ := pr.Status(id)
		return r.State != ProbeRunning
	})

	f.mu.Lock()
	defer f.mu.Unlock()
	var fioArgv []string
	for _, a := range f.argvs {
		if a[0] == "fio" {
			fioArgv = a
		}
	}
	if fioArgv == nil {
		t.Fatal("fio never ran")
	}
	joined := strings.Join(fioArgv, " ")
	for _, want := range []string{"--runtime 30", "--time_based", "--iodepth 16", "--numjobs 1", "--size 512M"} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv is missing the literal bound %q: %s", want, joined)
		}
	}
	// The only substituted element is the scratch name, and it is ours.
	if !strings.Contains(joined, ScratchPrefix) {
		t.Error("the scratch name was never substituted")
	}
}

// A malformed probe is caught when the agent starts, not when the SaaS calls
// it — the same rule the allowlist follows.
func TestMalformedProbesAreRefusedAtRegistration(t *testing.T) {
	base := func() Probe {
		p := Probes[0]
		return p
	}
	cases := []struct {
		name  string
		probe func(Probe) Probe
	}{
		{"no teardown", func(p Probe) Probe { p.Teardown = nil; return p }},
		{"no list", func(p Probe) Probe { p.List = nil; return p }},
		{"no parser", func(p Probe) Probe { p.Parse = nil; return p }},
		{"no budget", func(p Probe) Probe { p.Budget = 0; return p }},
		{"wrong impact", func(p Probe) Probe { p.Impact = ImpactRead; return p }},
		{"undeclared placeholder", func(p Probe) Probe {
			p.Measure = append([]string{}, "fio", "--rw", "{pattern}")
			return p
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewProbeRunner([]Probe{tc.probe(base())}, &recorder{}); err == nil {
				t.Fatalf("a probe with %s registered", tc.name)
			}
		})
	}
}

// The control tools are the SaaS's whole view of the plane, and they are short
// calls: start launches and returns, status reads a map.
func TestControlToolsStartAndPollThroughTheRegistry(t *testing.T) {
	f := newFakeCluster()
	pr, _ := newTestProbeRunner(t, f)
	rec := &recorder{}
	r, err := New(Allowlist, rec, WithProbes(pr))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := r.Call(context.Background(), "probe_start", map[string]string{"probe": "probe_fio_volume"})
	if err != nil {
		t.Fatalf("probe_start: %v", err)
	}
	var started struct{ Run, State string }
	if err := json.Unmarshal(out, &started); err != nil {
		t.Fatalf("probe_start result is not JSON: %v", err)
	}
	if started.Run == "" {
		t.Fatal("probe_start returned no run id")
	}

	waitFor(t, "the run to finish", func() bool {
		res, _ := pr.Status(started.Run)
		return res.State != ProbeRunning
	})

	out, err = r.Call(context.Background(), "probe_status", map[string]string{"run": started.Run})
	if err != nil {
		t.Fatalf("probe_status: %v", err)
	}
	var res ProbeResult
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("probe_status result is not JSON: %v", err)
	}
	if res.State != ProbeDone || res.Metrics["write_iops"] == 0 {
		t.Errorf("status = %+v, want a finished run carrying metrics", res)
	}
}

// Without a probe runner the control tools are not advertised at all: an agent
// that cannot probe must not claim it can.
func TestAnAgentWithoutAProbePlaneAdvertisesNoProbeTools(t *testing.T) {
	r, err := New(Allowlist, &recorder{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, n := range r.Names() {
		if strings.HasPrefix(n, "probe_") {
			t.Errorf("an agent with no probe plane advertises %s", n)
		}
	}
	if _, err := r.Call(context.Background(), "probe_start", map[string]string{"probe": "probe_fio_volume"}); !errors.Is(err, ErrUnknownTool) {
		t.Errorf("err = %v, want ErrUnknownTool", err)
	}
}

func TestControlToolsRefuseAnUndeclaredArgument(t *testing.T) {
	f := newFakeCluster()
	pr, _ := newTestProbeRunner(t, f)
	r, err := New(Allowlist, &recorder{}, WithProbes(pr))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.Call(context.Background(), "probe_start", map[string]string{
		"probe": "probe_fio_volume", "runtime": "600",
	})
	if !errors.Is(err, ErrBadArgument) {
		t.Fatalf("err = %v, want ErrBadArgument for an argument the plane does not take", err)
	}
	if f.ran("fio") {
		t.Error("a probe ran despite an undeclared argument")
	}
}

// A control tool that declared substitutable parameters would imply this file
// checks them; it does not, and a guard that looks stronger than it is is
// worse than none.
func TestAControlToolCannotDeclareParameters(t *testing.T) {
	f := newFakeCluster()
	pr, _ := newTestProbeRunner(t, f)
	_, err := New([]Tool{{
		Name: "probe_start_but_wrong", Control: ControlProbeStart, Impact: ImpactScratch,
		Params: map[string][]string{"{probe}": {"probe_fio_volume"}},
	}}, &recorder{}, WithProbes(pr))
	if err == nil {
		t.Fatal("a control tool declaring parameters registered")
	}
}

// Cleanup is audited, so a customer reading the local log can see that the
// scratch a probe created was also removed.
func TestCleanupIsAudited(t *testing.T) {
	f := newFakeCluster()
	pr, rec := newTestProbeRunner(t, f)

	id, _ := pr.Start(context.Background(), "probe_fio_volume")
	waitFor(t, "the run to finish", func() bool {
		r, _ := pr.Status(id)
		return r.State != ProbeRunning
	})
	waitFor(t, "cleanup to be audited", func() bool {
		for _, c := range rec.snapshot() {
			if c.Tool == "probe_cleanup" {
				return true
			}
		}
		return false
	})
}
