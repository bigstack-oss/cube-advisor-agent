package toolplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// A probe is the one tool class that does something to the cluster rather than
// only reading it: it creates scratch storage, generates load against it, and
// deletes it again. Nothing it touches is configuration, and nothing it leaves
// behind is intentional — which makes cleanup, not measurement, the hard part
// of this file.
//
// Three properties bound it:
//
//  1. Every bound is literal. Runtime, size and queue depth live in the argv
//     below; no caller argument reaches them, so the SaaS chooses whether a
//     probe runs and never how hard it runs.
//  2. Every scratch resource is named advisor-probe-<runID> from an id this
//     process generated, so recognising our own litter is a prefix match and
//     nothing outside the prefix is ever a deletion candidate.
//  3. Cleanup runs on a context that the probe's own deadline cannot cancel,
//     and a sweeper covers the cases a deferred cleanup cannot: the process
//     being killed, the node rebooting mid-run.

// ScratchPrefix marks every resource a probe creates. A name without it is
// never a deletion candidate, however old and however orphaned it looks: the
// prefix is the whole ownership claim.
const ScratchPrefix = "advisor-probe-"

// ScratchPool is the product-owned pool probes create scratch images in.
// Dedicated so that a stray prefix match cannot reach a tenant's pool.
const ScratchPool = "advisor-scratch"

// probeCleanupBudget bounds teardown. Deliberately its own budget on its own
// context: teardown must survive the deadline that killed the measurement,
// because the timeout that ends a probe is exactly when its scratch volume
// most needs deleting.
const probeCleanupBudget = 30 * time.Second

// sweepInterval is how often the sweeper looks for litter left by a previous
// process. It also runs once at startup, which is the case that matters —
// a killed agent's scratch outlives it and nothing else will notice.
const sweepInterval = 10 * time.Minute

// ProbeState is where a run is. It is deliberately coarse: a caller decides
// whether to keep polling, and nothing else.
type ProbeState string

const (
	ProbeRunning ProbeState = "running"
	ProbeDone    ProbeState = "done"
	ProbeFailed  ProbeState = "failed"
)

// ProbeResult is what a poll returns. Metrics are parsed structurally from the
// measurement's own machine-readable output, never scraped from prose, so the
// numbers that reach a model are the numbers the tool produced.
type ProbeResult struct {
	Run     string             `json:"run"`
	Probe   string             `json:"probe"`
	State   ProbeState         `json:"state"`
	Metrics map[string]float64 `json:"metrics,omitempty"`
	Error   string             `json:"error,omitempty"`
	Started time.Time          `json:"started"`
	Ended   *time.Time         `json:"ended,omitempty"`
}

// scratchPlaceholder is the one slot a probe's argv carries. Like {dc} in a
// Get tool, the executor fills it — here from an id it generated itself — so
// no caller-supplied byte ever reaches a command line.
const scratchPlaceholder = "{scratch}"

// Probe is one bounded measurement and the full lifecycle of the scratch it
// needs. Setup, Measure and Teardown are separate because cleanup has to be
// runnable without the measurement, from the sweeper, long after the run that
// created the resource is gone.
type Probe struct {
	Name        string
	Description string

	// Impact is ImpactScratch for every probe. Declared per-probe anyway so a
	// future light-class probe states its own class rather than inheriting one.
	Impact Impact

	// Setup creates the scratch resources. Each element is a literal argv
	// except for {scratch}.
	Setup [][]string

	// Measure is the measurement. Its stdout goes to Parse.
	Measure []string

	// Teardown destroys the scratch resources. Runs on a detached context,
	// and is also what the sweeper runs against an orphan.
	Teardown [][]string

	// List enumerates existing scratch names, one per line, so the sweeper and
	// the pre-flight check can find litter without guessing.
	List []string

	// Budget hard-kills the whole run. Not a rung of the tool timeout ladder:
	// a probe is started and polled, so nothing holds a channel open while it
	// runs, and this bound exists to stop a wedged fio living forever.
	Budget time.Duration

	// Parse turns the measurement's output into metrics.
	Parse func([]byte) (map[string]float64, error)
}

// Probes is the complete set this executor will run.
//
// Adding one is the security-relevant act, exactly as with the Allowlist: keep
// every bound literal, and keep every scratch resource inside ScratchPool
// under ScratchPrefix.
var Probes = []Probe{
	{
		Name: "probe_fio_volume",
		Description: "Measure block storage from this node: create a 1 GiB scratch volume, " +
			"run a fixed 30-second random-write profile against it, delete it.",
		Impact: ImpactScratch,
		Setup: [][]string{
			{"rbd", "create", "--size", "1024", "--pool", ScratchPool, scratchPlaceholder},
		},
		// Every bound is here and literal: 30s time-based, 512 MiB working set,
		// one job at queue depth 16. The profile is fixed rather than tunable
		// because comparability across runs — and against a commissioning
		// baseline — matters more than covering every access pattern.
		Measure: []string{
			"fio",
			"--name", "advisor-probe",
			"--ioengine", "rbd",
			"--pool", ScratchPool,
			"--rbdname", scratchPlaceholder,
			"--rw", "randwrite",
			"--bs", "4k",
			"--iodepth", "16",
			"--numjobs", "1",
			"--size", "512M",
			"--runtime", "30",
			"--time_based",
			"--output-format", "json",
		},
		Teardown: [][]string{
			{"rbd", "rm", ScratchPool + "/" + scratchPlaceholder},
		},
		List: []string{"rbd", "ls", ScratchPool},
		// 30s of fio plus image create and delete lands near a minute; the
		// budget is generous enough that a slow-but-working cluster finishes
		// and tight enough that a wedged one does not linger.
		Budget: 5 * time.Minute,
		Parse:  parseFioJSON,
	},
}

// probeRun is one in-flight or finished run.
type probeRun struct {
	result  ProbeResult
	scratch string
}

// ProbeRunner starts, tracks and cleans up probe runs.
//
// Runs live in memory only. A run whose process died is not resumable — the
// measurement is gone with it — and pretending otherwise would mean reporting
// a result nobody observed. What must survive a restart is the *cleanup*, and
// that is the sweeper's job, which needs no memory of the run at all.
type ProbeRunner struct {
	mu     sync.Mutex
	runs   map[string]*probeRun
	probes map[string]Probe

	audit Auditor

	// run executes a command; swapped in tests so the suite never shells out.
	run func(ctx context.Context, argv []string, maxBytes int) ([]byte, error)

	now   func() time.Time
	newID func() (string, error)
}

// NewProbeRunner builds a runner over probes, refusing anything malformed at
// construction rather than at call time.
func NewProbeRunner(probes []Probe, audit Auditor) (*ProbeRunner, error) {
	if audit == nil {
		return nil, fmt.Errorf("toolplane: an auditor is required; every probe must be inspectable by the customer")
	}
	pr := &ProbeRunner{
		runs:   map[string]*probeRun{},
		probes: make(map[string]Probe, len(probes)),
		audit:  audit,
		run:    runCommand,
		now:    func() time.Time { return time.Now().UTC() },
		newID:  newRunID,
	}
	for _, p := range probes {
		if err := p.validate(); err != nil {
			return nil, fmt.Errorf("toolplane: %w", err)
		}
		if _, dup := pr.probes[p.Name]; dup {
			return nil, fmt.Errorf("toolplane: probe %q registered twice", p.Name)
		}
		pr.probes[p.Name] = p
	}
	return pr, nil
}

// SetRunnerForTest replaces the executor, for the same reason the registry has
// one: a suite must exercise the lifecycle without shelling out to rbd.
func (pr *ProbeRunner) SetRunnerForTest(fn func(ctx context.Context, argv []string, maxBytes int) ([]byte, error)) {
	pr.run = fn
}

// Names returns the probes this runner serves, sorted.
func (pr *ProbeRunner) Names() []string {
	out := make([]string, 0, len(pr.probes))
	for n := range pr.probes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (p Probe) validate() error {
	if p.Name == "" {
		return fmt.Errorf("probe has no name")
	}
	if p.Impact != ImpactScratch {
		return fmt.Errorf("probe %q declares impact %s; a probe is the scratch class", p.Name, p.Impact)
	}
	if len(p.Measure) == 0 {
		return fmt.Errorf("probe %q has no measurement", p.Name)
	}
	if len(p.Teardown) == 0 {
		return fmt.Errorf("probe %q has no teardown; a probe that cannot clean up is not servable", p.Name)
	}
	if len(p.List) == 0 {
		return fmt.Errorf("probe %q cannot enumerate its scratch; orphans would be undetectable", p.Name)
	}
	if p.Budget <= 0 {
		return fmt.Errorf("probe %q has no budget", p.Name)
	}
	if p.Parse == nil {
		return fmt.Errorf("probe %q has no parser; results must be structured, not scraped", p.Name)
	}
	// Bounds must be literal. A placeholder other than {scratch} anywhere in
	// the probe would be a caller-supplied element on a command line, which is
	// the one thing this class must not have.
	for _, argv := range append(append([][]string{p.Measure, p.List}, p.Setup...), p.Teardown...) {
		if len(argv) == 0 {
			return fmt.Errorf("probe %q has an empty step", p.Name)
		}
		if isPlaceholder(argv[0]) {
			return fmt.Errorf("probe %q parameterises an executable", p.Name)
		}
		for _, a := range argv {
			for _, tok := range strings.Fields(strings.ReplaceAll(a, "/", " ")) {
				if isPlaceholder(tok) && tok != scratchPlaceholder {
					return fmt.Errorf("probe %q uses %s; only %s is fillable", p.Name, tok, scratchPlaceholder)
				}
			}
		}
	}
	return nil
}

// newRunID returns an id built from the executor's own randomness. Callers
// never supply it, so the scratch name it lands in contains only [0-9a-f] and
// no argument the SaaS chose can shape a resource name.
func newRunID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ErrProbeBusy is the pre-flight refusal: litter exists that the sweeper has
// not cleared, so a new probe would pile scratch onto scratch.
var ErrProbeBusy = fmt.Errorf("toolplane: scratch from an earlier probe is still present")

// ErrNoSuchRun is returned for a run id this process does not know. It covers
// both a made-up id and a genuine one from a previous process — neither has a
// result here, and reporting them the same way is honest.
var ErrNoSuchRun = fmt.Errorf("toolplane: no such probe run")

// Start validates, refuses if orphans exist, allocates a run id and launches
// the probe. It returns as soon as the goroutine is running: the caller polls.
func (pr *ProbeRunner) Start(ctx context.Context, name string) (string, error) {
	p, ok := pr.probes[name]
	if !ok {
		pr.audit.RecordToolCall(ToolCall{
			Tool: "probe_start", Args: map[string]string{"probe": name},
			Allowed: false, Reason: "no such probe", At: pr.now(),
		})
		return "", fmt.Errorf("%w: %q", ErrUnknownTool, name)
	}

	// Pre-flight: decline rather than accumulate. A probe that starts while
	// litter is present makes the litter harder to attribute and doubles the
	// load on a cluster somebody is already worried about.
	if orphans, err := pr.orphans(ctx, p); err == nil && len(orphans) > 0 {
		pr.audit.RecordToolCall(ToolCall{
			Tool: "probe_start", Args: map[string]string{"probe": name},
			Allowed: false, Reason: fmt.Sprintf("%d orphaned scratch resource(s) present", len(orphans)),
			At: pr.now(),
		})
		return "", fmt.Errorf("%w: %d left over, sweeper has not cleared them yet", ErrProbeBusy, len(orphans))
	}

	id, err := pr.newID()
	if err != nil {
		return "", fmt.Errorf("toolplane: allocating a run id: %w", err)
	}
	scratch := ScratchPrefix + id
	started := pr.now()

	pr.mu.Lock()
	pr.runs[id] = &probeRun{
		scratch: scratch,
		result: ProbeResult{
			Run: id, Probe: name, State: ProbeRunning, Started: started,
		},
	}
	pr.mu.Unlock()

	pr.audit.RecordToolCall(ToolCall{
		Tool: "probe_start", Args: map[string]string{"probe": name, "run": id},
		Argv: []string{"probe", name, scratch}, Allowed: true, At: started,
	})

	// The run owns its own budget from here. It deliberately does not inherit
	// the caller's context: probe_start returns immediately, and a probe that
	// died because the channel that started it closed would be a probe that
	// leaves scratch behind every time the tunnel flaps.
	go pr.execute(context.WithoutCancel(ctx), p, id, scratch)
	return id, nil
}

// execute runs setup, measurement and teardown for one run.
func (pr *ProbeRunner) execute(base context.Context, p Probe, id, scratch string) {
	ctx, cancel := context.WithTimeout(base, p.Budget)
	defer cancel()

	// Teardown on a context the measurement's deadline cannot reach. This is
	// the whole reason the two are separate: cleanup inheriting the context
	// that just killed the probe is a cleanup that never runs, which is
	// precisely how orphans are made.
	defer func() {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(base), probeCleanupBudget)
		defer cancelCleanup()
		pr.teardown(cleanupCtx, p, scratch, "run")
	}()

	for _, step := range p.Setup {
		if out, err := pr.run(ctx, fillScratch(step, scratch), defaultMaxOutputBytes); err != nil {
			pr.finish(id, ProbeFailed, nil, fmt.Errorf("setup: %v: %s", err, strings.TrimSpace(string(out))))
			return
		}
	}

	out, err := pr.run(ctx, fillScratch(p.Measure, scratch), defaultMaxOutputBytes)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("probe exceeded its %s budget", p.Budget)
		}
		pr.finish(id, ProbeFailed, nil, err)
		return
	}
	metrics, err := p.Parse(out)
	if err != nil {
		pr.finish(id, ProbeFailed, nil, fmt.Errorf("parsing the measurement: %w", err))
		return
	}
	pr.finish(id, ProbeDone, metrics, nil)
}

// teardown runs a probe's cleanup steps against one scratch name, auditing the
// outcome. Failures are logged and audited rather than returned: nobody is
// waiting on them, and a silent cleanup failure is how litter becomes routine.
func (pr *ProbeRunner) teardown(ctx context.Context, p Probe, scratch, why string) {
	for _, step := range p.Teardown {
		argv := fillScratch(step, scratch)
		out, err := pr.run(ctx, argv, defaultMaxOutputBytes)
		rec := ToolCall{
			Tool: "probe_cleanup", Args: map[string]string{"scratch": scratch, "cause": why},
			Argv: argv, Allowed: true, At: pr.now(),
		}
		if err != nil {
			rec.Reason = fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out)))
			log.Printf("toolplane: cleaning up %s: %v", scratch, err)
		}
		pr.audit.RecordToolCall(rec)
	}
}

func (pr *ProbeRunner) finish(id string, state ProbeState, metrics map[string]float64, err error) {
	ended := pr.now()
	pr.mu.Lock()
	defer pr.mu.Unlock()
	r, ok := pr.runs[id]
	if !ok {
		return
	}
	r.result.State = state
	r.result.Metrics = metrics
	r.result.Ended = &ended
	if err != nil {
		r.result.Error = err.Error()
	}
}

// Status returns a run's current state. An unknown id is an error rather than
// an empty result: a caller polling a run that does not exist has a bug, and
// answering "running" forever would hide it.
func (pr *ProbeRunner) Status(id string) (ProbeResult, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	r, ok := pr.runs[id]
	if !ok {
		return ProbeResult{}, fmt.Errorf("%w: %q", ErrNoSuchRun, id)
	}
	return r.result, nil
}

// orphans lists scratch resources that carry our prefix but belong to no live
// run in this process. At startup that is all of them, which is correct: a run
// this process never started is a run whose result nobody will ever collect.
func (pr *ProbeRunner) orphans(ctx context.Context, p Probe) ([]string, error) {
	out, err := pr.run(ctx, p.List, defaultMaxOutputBytes)
	if err != nil {
		return nil, err
	}
	live := map[string]bool{}
	pr.mu.Lock()
	for _, r := range pr.runs {
		if r.result.State == ProbeRunning {
			live[r.scratch] = true
		}
	}
	pr.mu.Unlock()

	var found []string
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		// The prefix is the entire ownership claim: anything else in the pool
		// belongs to somebody else and is not ours to delete.
		if name == "" || !strings.HasPrefix(name, ScratchPrefix) || live[name] {
			continue
		}
		found = append(found, name)
	}
	sort.Strings(found)
	return found, nil
}

// Sweep deletes scratch left behind by runs this process does not have. It is
// what covers the failures a deferred cleanup cannot: the agent being killed,
// the node rebooting mid-probe. Safe to call at any time — a live run's
// scratch is excluded by name.
func (pr *ProbeRunner) Sweep(ctx context.Context) int {
	swept := 0
	for _, p := range pr.probes {
		orphans, err := pr.orphans(ctx, p)
		if err != nil {
			log.Printf("toolplane: listing scratch for %s: %v", p.Name, err)
			continue
		}
		for _, name := range orphans {
			pr.teardown(ctx, p, name, "sweep")
			swept++
		}
	}
	return swept
}

// RunSweeper sweeps once at startup and then on a tick until ctx ends.
//
// The startup sweep is the one that matters: it is the only thing that ever
// notices scratch left by a process that is no longer running.
func (pr *ProbeRunner) RunSweeper(ctx context.Context) {
	if n := pr.Sweep(ctx); n > 0 {
		log.Printf("toolplane: swept %d orphaned scratch resource(s) at startup", n)
	}
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pr.Sweep(ctx)
		}
	}
}

// fillScratch substitutes the executor-generated scratch name into a step.
// The placeholder may be a whole element or the tail of a pool-qualified one
// (pool/{scratch}), and nothing else is substituted.
func fillScratch(argv []string, scratch string) []string {
	out := make([]string, 0, len(argv))
	for _, a := range argv {
		out = append(out, strings.ReplaceAll(a, scratchPlaceholder, scratch))
	}
	return out
}

// fioJSON is the slice of fio's --output-format=json we read. Parsing its own
// machine-readable output rather than its human summary is what lets a result
// travel to a model as numbers instead of a paragraph it might retype wrongly.
type fioJSON struct {
	Jobs []struct {
		Write fioDirection `json:"write"`
		Read  fioDirection `json:"read"`
	} `json:"jobs"`
}

type fioDirection struct {
	IOPS  float64 `json:"iops"`
	BWKiB float64 `json:"bw"`
	Lat   struct {
		Mean float64 `json:"mean"`
	} `json:"lat_ns"`
}

func parseFioJSON(out []byte) (map[string]float64, error) {
	// fio prints its JSON after any warnings, so start at the first brace
	// rather than assuming the output begins with the document.
	if i := strings.IndexByte(string(out), '{'); i > 0 {
		out = out[i:]
	}
	var doc fioJSON
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("fio output was not the JSON we asked for: %w", err)
	}
	if len(doc.Jobs) == 0 {
		return nil, fmt.Errorf("fio reported no jobs")
	}
	j := doc.Jobs[0]
	return map[string]float64{
		"write_iops":        j.Write.IOPS,
		"write_bw_kib_s":    j.Write.BWKiB,
		"write_lat_mean_ns": j.Write.Lat.Mean,
		"read_iops":         j.Read.IOPS,
		"read_bw_kib_s":     j.Read.BWKiB,
	}, nil
}
