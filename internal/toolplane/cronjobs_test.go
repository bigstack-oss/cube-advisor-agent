package toolplane

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func everyMinuteJobs(t *testing.T) Tool {
	t.Helper()
	for _, tl := range Allowlist {
		if tl.Name == "every_minute_jobs" {
			return tl
		}
	}
	t.Fatal("every_minute_jobs is not in the allowlist")
	return Tool{}
}

func TestEveryMinuteJobsIsAFixedRead(t *testing.T) {
	tl := everyMinuteJobs(t)
	if tl.Impact != ImpactRead || len(tl.Params) > 0 || len(tl.Free) > 0 {
		t.Fatalf("want a parameterless read, got impact %v params %v free %v", tl.Impact, tl.Params, tl.Free)
	}
	if _, err := tl.resolve(map[string]string{"{lines}": "1"}); err == nil {
		t.Error("an argument was accepted")
	}
}

// The same argv, rooted in a temp dir: the file's text when present, an
// empty success when it is not.
func TestEveryMinuteJobsReadsTheFileOrNothing(t *testing.T) {
	tl := everyMinuteJobs(t)
	root := t.TempDir()
	rewrite := func(argv []string) []string {
		out := make([]string, len(argv))
		for i, a := range argv {
			out[i] = strings.Replace(a, "/etc/cube/cos", root, 1)
		}
		return out
	}
	argv := rewrite(tl.Argv)
	run := func() (string, error) {
		b, err := exec.Command(argv[0], argv[1:]...).Output()
		return string(b), err
	}
	if out, err := run(); err != nil || out != "" {
		t.Fatalf("missing file: %q, %v", out, err)
	}
	job := `/usr/sbin/hex_sdk ceph_osd_safe_remove "4" "1.81898" "2" "14 pgs" "0"` + "\n"
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "cron"), 0o755))
	must(os.WriteFile(filepath.Join(root, "cron", "every_minute_jobs.sh"), []byte(job), 0o644))
	must(os.WriteFile(filepath.Join(root, "cron", "every_minute_jobs.sh.running"), []byte("x"), 0o644))
	if out, err := run(); err != nil || out != job {
		t.Fatalf("present file: %q, %v", out, err)
	}
}
