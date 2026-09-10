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

// notInTheSpec lists allowlist paths knowingly absent from cube-cos-api,
// each with the reason. An entry here is a debt, not a dispensation: it says
// the tool cannot work today, and removing it is what shipping the tool means.
var notInTheSpec = map[string]string{
	"/api/v1/datacenters/{dc}/instances": "cube-cos-api does not create instances — " +
		"no such path in its OpenAPI document or source, and VM lifecycle is not " +
		"this API's concern. create_instance cannot write until either that endpoint " +
		"exists or the tool is given a transport that reaches whatever does.",
}

func specPaths(t *testing.T) map[string]bool {
	t.Helper()

	f, err := os.Open("testdata/cube-cos-api-paths.txt")
	if err != nil {
		t.Fatalf("open the vendored path list: %v", err)
	}
	defer f.Close()

	paths := map[string]bool{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		paths[line] = true
	}
	if err := s.Err(); err != nil {
		t.Fatalf("read the vendored path list: %v", err)
	}
	// A truncated or empty file would make every path "absent" and every
	// exclusion look justified, which is the failure this test exists to
	// prevent in the code it checks.
	if len(paths) < 50 {
		t.Fatalf("vendored path list holds %d paths, far fewer than cube-cos-api serves; it is truncated", len(paths))
	}
	return paths
}

// TestEveryAllowlistPathIsOneTheAPIServes is the check that would have caught
// create_instance before it shipped.
func TestEveryAllowlistPathIsOneTheAPIServes(t *testing.T) {
	spec := specPaths(t)

	for _, tool := range append(append([]Tool{}, Allowlist...), ProbeControls...) {
		for _, path := range []string{tool.Get, tool.Post} {
			if path == "" {
				continue
			}
			if reason, known := notInTheSpec[path]; known {
				t.Logf("%s: %s is knowingly absent from the API: %s", tool.Name, path, reason)
				continue
			}
			if !spec[strings.ReplaceAll(path, allowlistDC, specDC)] {
				t.Errorf("%s names %s, which cube-cos-api does not serve; "+
					"fix the path, or list it in notInTheSpec with the reason it cannot work yet",
					tool.Name, path)
			}
		}
	}
}

// TestAnExcludedPathIsOneTheAPIReallyLacks keeps the exclusion list honest in
// the other direction: an entry that the API has since gained is a debt
// someone already paid, and leaving it listed hides a working tool behind a
// note saying it cannot work.
func TestAnExcludedPathIsOneTheAPIReallyLacks(t *testing.T) {
	spec := specPaths(t)

	for path, reason := range notInTheSpec {
		if spec[strings.ReplaceAll(path, allowlistDC, specDC)] {
			t.Errorf("%s is listed as absent from cube-cos-api (%q) but the spec now has it; remove the exclusion",
				path, reason)
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
