package main

import (
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// The line the Advisor sends parses here and starts a job.
func TestJobStartLineDispatches(t *testing.T) {
	dir := t.TempDir()
	line := tunnelproto.JobStartCommand("job_cli", time.Now().Add(time.Hour), "echo hi")
	args := strings.Fields(line)[1:]
	args = append(args[:2], append([]string{"-dir", dir}, args[2:]...)...)
	if code := dispatch(args); code != exitOK {
		t.Fatalf("job start exited %d", code)
	}
	if code := dispatch([]string{"job", "stop", "-dir", dir, "job_cli"}); code != exitOK {
		t.Fatalf("job stop exited %d", code)
	}
	if code := dispatch([]string{"job", "start", "-dir", dir, "-id", "x", "-deadline", "soon"}); code != exitUsage {
		t.Fatalf("bad deadline exited %d", code)
	}
}
