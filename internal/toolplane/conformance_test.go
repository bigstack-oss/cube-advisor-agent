package toolplane

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// The allowlist names cube-cos-api paths as string literals, and nothing used
// to check them against the API that has to serve them. create_instance
// shipped pointing at /api/v1/datacenters/{dc}/instances, which cube-cos-api
// does not have and has never had: not in its OpenAPI document, not in its
// embedded copy, and not as a handler in its source. It was found by reading
// the spec, which is a thing a person does once. This does it every run.
//
// testdata/cube-cos-api-paths.txt is vendored rather than read from a checkout
// of cube-cos-api, because CI has no such checkout and a test that skips when
// its input is missing reports green for the case it was written to catch.
// The file's header names the revision it came from and the command that
// regenerates it.

// dcPlaceholder is the one rewrite between the two vocabularies: the allowlist
// writes {dc} because the executor fills it from its own configuration, and
// the OpenAPI document writes {dataCenter} because that is the parameter's
// name. Pinned here so a change to either is a failure rather than a silent
// mismatch in a substitution nobody reads.
const (
	allowlistDC = "{dc}"
	specDC      = "{dataCenter}"
)

// notInTheSpec lists allowlist paths knowingly absent from the API that would
// have to serve them, each with the reason. An entry here is a debt, not a
// dispensation: it says the tool cannot work today, and removing it is what
// shipping the tool means.
//
// It is empty, and that is the point — create_instance was its only entry, and
// giving the tool nova as a destination paid the debt rather than excusing it.
// The two guards below iterate this map, so an empty map exercises nothing;
// they earn their keep the moment anyone adds an entry, which is when a wrong
// one would otherwise go unnoticed.
var notInTheSpec = map[string]string{}

// specFile is the vendored path list each backend is checked against, and the
// floor below which the file is assumed truncated.
//
// Per backend rather than one list, because "the API that must serve this" is
// a different API per tool now. A backend with no entry here is a backend
// nothing can be checked against, and addPath below treats that as a failure
// rather than a pass: an unchecked destination is how the first one went
// wrong.
var specFile = map[Backend]struct {
	path string
	// min guards against a truncated or empty file, which would make every
	// path "absent" and every exclusion look justified — the failure this
	// test exists to prevent in the code it checks.
	min int
	// methods reports whether the file records "METHOD PATH" rather than
	// paths alone. Only a file that does can answer "does this API serve
	// this path by GET", which is what the read catalogue's claim rests on.
	methods bool
}{
	BackendCubeCOS:          {path: "testdata/cube-cos-api-paths.txt", min: 50, methods: true},
	BackendOpenStackCompute: {path: "testdata/nova-compute-paths.txt", min: 100},
}

// specOps reads a backend's vendored list as method -> set of paths.
//
// Two file shapes are in use. cube-cos-api's records "METHOD PATH", because a
// catalogue claiming to reach only reads has to be checked against reads
// specifically, and a path-only list cannot tell a GET from a POST sharing a
// URL. nova's records paths alone. Asking for methods from a file that has
// none is a Fatal rather than an empty answer, for the same reason a backend
// with no vendored list is: an unchecked destination is how the first one went
// wrong.
func specOps(t *testing.T, b Backend) map[string]map[string]bool {
	t.Helper()

	src, known := specFile[b]
	if !known {
		t.Fatalf("no vendored path list for backend %s; add one before a tool goes there", b)
	}
	if !src.methods {
		t.Fatalf("the vendored list for %s records paths without methods; it cannot answer a question about GETs", b)
	}

	f, err := os.Open(src.path)
	if err != nil {
		t.Fatalf("open the vendored operation list for %s: %v", b, err)
	}
	defer f.Close()

	ops := map[string]map[string]bool{}
	total := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		method, path, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("vendored operation list for %s has a line that is not %q: %q", b, "METHOD PATH", line)
		}
		if ops[method] == nil {
			ops[method] = map[string]bool{}
		}
		ops[method][path] = true
		total++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read the vendored operation list for %s: %v", b, err)
	}
	if total < src.min {
		t.Fatalf("vendored operation list for %s holds %d operations, far fewer than it serves; it is truncated", b, total)
	}
	return ops
}

func specPaths(t *testing.T, b Backend) map[string]bool {
	t.Helper()

	src, known := specFile[b]
	if !known {
		t.Fatalf("no vendored path list for backend %s; add one before a tool goes there", b)
	}

	f, err := os.Open(src.path)
	if err != nil {
		t.Fatalf("open the vendored path list for %s: %v", b, err)
	}
	defer f.Close()

	paths := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A "METHOD PATH" line contributes its path; a path-only line is the
		// whole line. One reader for both shapes, so a caller asking only
		// "does this API serve this path" need not know which it is reading.
		if _, path, ok := strings.Cut(line, " "); ok {
			paths[path] = true
			continue
		}
		paths[line] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read the vendored path list for %s: %v", b, err)
	}
	if len(paths) < src.min {
		t.Fatalf("vendored path list for %s holds %d paths, far fewer than it serves; it is truncated", b, len(paths))
	}
	return paths
}

// specName rewrites an allowlist path into the vocabulary its spec uses.
//
// Only cube-cos-api needs it. nova's paths carry no executor-filled
// placeholder — {dc} is meaningless to it, since which cluster is decided by
// which endpoint the catalog gave us — so its paths are compared verbatim.
func specName(b Backend, path string) string {
	if b == BackendCubeCOS {
		return strings.ReplaceAll(path, allowlistDC, specDC)
	}
	return path
}

// TestEveryAllowlistPathIsOneTheAPIServes is the check that would have caught
// create_instance before it shipped.
func TestEveryAllowlistPathIsOneTheAPIServes(t *testing.T) {
	specs := map[Backend]map[string]bool{}

	for _, tool := range append(append([]Tool{}, Allowlist...), ProbeControls...) {
		for _, path := range []string{tool.Get, tool.Post} {
			if path == "" {
				continue
			}
			if reason, known := notInTheSpec[path]; known {
				t.Logf("%s: %s is knowingly absent from the API: %s", tool.Name, path, reason)
				continue
			}
			spec, loaded := specs[tool.Backend]
			if !loaded {
				spec = specPaths(t, tool.Backend)
				specs[tool.Backend] = spec
			}
			if !spec[specName(tool.Backend, path)] {
				t.Errorf("%s names %s, which %s does not serve; "+
					"fix the path, or list it in notInTheSpec with the reason it cannot work yet",
					tool.Name, path, tool.Backend)
			}
		}
	}
}

// TestTheCreateGoesToNovaAndNotTheManagementAPI pins the destination itself,
// not just that the path resolves somewhere.
//
// Without it, a create could be pointed back at cube-cos-api with a path that
// happens to exist there and every other test would still pass. The tool's
// whole correction was which API it addresses, so that is worth asserting
// directly rather than as a side effect.
func TestTheCreateGoesToNovaAndNotTheManagementAPI(t *testing.T) {
	var found bool
	for _, tool := range Allowlist {
		if tool.Name != "create_instance" {
			continue
		}
		found = true
		if tool.Backend != BackendOpenStackCompute {
			t.Errorf("create_instance goes to %s; instances are nova's", tool.Backend)
		}
		if tool.Post != "/servers" {
			t.Errorf("create_instance posts to %q, want nova's /servers", tool.Post)
		}
		if _, names := tool.Body["project"]; names {
			t.Error("create_instance names a project in its body; " +
				"in nova the project is the credential's scope, and a project " +
				"that cannot be named cannot be named wrongly")
		}
	}
	if !found {
		t.Fatal("create_instance is not in the allowlist; if it was removed, remove this test")
	}
}

// TestEveryCatalogueReadIsAGetTheAPIServes checks the widened read surface the
// same way the hand-written entries are checked, and one way further: a
// catalogue entry must be a path the API serves *by GET*. A path-only list
// could not tell a read from a write sharing a URL, and the catalogue's whole
// claim is that it cannot reach anything but reads.
func TestEveryCatalogueReadIsAGetTheAPIServes(t *testing.T) {
	gets := specOps(t, BackendCubeCOS)["GET"]
	if len(gets) == 0 {
		t.Fatal("the vendored operation list records no GETs; it is malformed")
	}

	for _, tool := range Allowlist {
		for key, path := range tool.Catalog {
			spec := specName(BackendCubeCOS, path)
			if !gets[spec] {
				t.Errorf("%s catalogue key %q names %s, which cube-cos-api does not serve by GET",
					tool.Name, key, path)
			}
		}
	}
}

// TestEverySimpleGetIsAdmittedOrHeldBack is what makes admission opt-in and
// still visible.
//
// Opt-in alone would leave a read the API gains tomorrow silently unreachable:
// safe, but nobody would know it existed, and the catalogue would quietly fall
// behind the product. Requiring the two sets to cover the API between them
// turns that into a failing test naming the new path, so somebody classifies
// it. Admitting it stays a deliberate act; ignoring it stops being one.
//
// Scoped to GETs whose only placeholder is the datacenter, because those are
// the reads the catalogue can express — a per-resource read needs a value set
// or a shape for the identifier, which is a wider decision than this slice.
func TestEverySimpleGetIsAdmittedOrHeldBack(t *testing.T) {
	admitted := map[string]bool{}
	for _, tool := range Allowlist {
		for _, path := range tool.Catalog {
			admitted[specName(BackendCubeCOS, path)] = true
		}
		if tool.Get != "" {
			admitted[specName(BackendCubeCOS, tool.Get)] = true
		}
	}

	for path := range specOps(t, BackendCubeCOS)["GET"] {
		if strings.Contains(strings.ReplaceAll(path, specDC, ""), "{") {
			continue // per-resource read; out of the catalogue's scope for now
		}
		if admitted[path] {
			continue
		}
		if _, held := cubeCOSReadsHeldBack[path]; held {
			continue
		}
		t.Errorf("cube-cos-api serves GET %s and this agent neither reads it nor says why not; "+
			"add it to CubeCOSReads or to cubeCOSReadsHeldBack with the reason", path)
	}
}

// TestNothingIsBothAdmittedAndHeldBack stops the two sets from disagreeing.
// A path in both reads as refused to anyone scanning the reasons and is in
// fact reachable, which is the worst of the two states to be in.
func TestNothingIsBothAdmittedAndHeldBack(t *testing.T) {
	for _, tool := range Allowlist {
		for key, path := range tool.Catalog {
			spec := specName(BackendCubeCOS, path)
			if reason, held := cubeCOSReadsHeldBack[spec]; held {
				t.Errorf("%s reads %q (%s) but it is also held back as %q; one of the two is wrong",
					tool.Name, key, path, reason)
			}
		}
	}
}

// TestEveryHeldBackReadIsOneTheAPIStillServes keeps the held-back list from
// outliving the API, the same honesty the exclusion list gets: a reason
// written about a path that no longer exists is a wrong statement, and it
// makes the coverage test above pass for the wrong reason.
func TestEveryHeldBackReadIsOneTheAPIStillServes(t *testing.T) {
	gets := specOps(t, BackendCubeCOS)["GET"]
	for path, reason := range cubeCOSReadsHeldBack {
		if !gets[path] {
			t.Errorf("cubeCOSReadsHeldBack lists %s (%q), which cube-cos-api no longer serves by GET; delete the entry",
				path, reason)
		}
	}
}

// TestAnExcludedPathIsOneTheAPIReallyLacks keeps the exclusion list honest in
// the other direction: an entry that the API has since gained is a debt
// someone already paid, and leaving it listed hides a working tool behind a
// note saying it cannot work.
func TestAnExcludedPathIsOneTheAPIReallyLacks(t *testing.T) {
	declaredBy := map[string]Backend{}
	for _, tool := range append(append([]Tool{}, Allowlist...), ProbeControls...) {
		for _, path := range []string{tool.Get, tool.Post} {
			if path != "" {
				declaredBy[path] = tool.Backend
			}
		}
	}

	for path, reason := range notInTheSpec {
		b, declared := declaredBy[path]
		if !declared {
			// The other guard reports this; checking it against an
			// arbitrary spec here would be a second, worse message.
			continue
		}
		if specPaths(t, b)[specName(b, path)] {
			t.Errorf("%s is listed as absent from %s (%q) but the spec now has it; remove the exclusion",
				path, b, reason)
		}
	}
}

// TestEveryExcludedPathIsStillInTheAllowlist stops the list outliving what it
// describes. A stale exclusion reads as a known gap in a tool that no longer
// exists, which is a wrong statement about the state of the world.
func TestEveryExcludedPathIsStillInTheAllowlist(t *testing.T) {
	declared := map[string]bool{}
	for _, tool := range append(append([]Tool{}, Allowlist...), ProbeControls...) {
		if tool.Get != "" {
			declared[tool.Get] = true
		}
		if tool.Post != "" {
			declared[tool.Post] = true
		}
	}

	for path := range notInTheSpec {
		if !declared[path] {
			t.Errorf("notInTheSpec lists %s, which no tool declares; delete the entry", path)
		}
	}
}
