package toolplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// These run real processes with setsid; systemd is not needed.

func testJobs(t *testing.T) *Jobs {
	t.Helper()
	return &Jobs{Dir: t.TempDir(), StopGrace: time.Second,
		Spawn: func(_ string, argv []string) (string, error) { return "", SetsidSpawn(argv) }}
}

func waitState(t *testing.T, j *Jobs, id, want string) tunnelproto.JobStatus {
	t.Helper()
	var st tunnelproto.JobStatus
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		var err error
		if st, err = j.Status(id, DefaultJobLines); err != nil {
			t.Fatal(err)
		}
		if st.State == want {
			return st
		}
	}
	t.Fatalf("job %s state = %s, want %s", id, st.State, want)
	return st
}

func pgidOf(t *testing.T, j *Jobs, id string) int {
	t.Helper()
	b, err := os.ReadFile(j.path(id, "pgid"))
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func TestJobRunsDetachedAndReportsExit(t *testing.T) {
	j := testJobs(t)
	st, err := j.Start("j1", "echo one; echo two >&2; exit 3", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if st.ID != "j1" {
		t.Fatalf("status = %+v", st)
	}
	st = waitState(t, j, "j1", tunnelproto.JobExited)
	if st.ExitCode == nil || *st.ExitCode != 3 {
		t.Fatalf("exit code = %v, want 3", st.ExitCode)
	}
	if st.Tail != "one\ntwo" || st.OutputBytes != 8 {
		t.Fatalf("tail = %q, bytes = %d", st.Tail, st.OutputBytes)
	}
}

func TestJobSurvivesANewAgent(t *testing.T) {
	j := testJobs(t)
	if _, err := j.Start("j2", "sleep 30", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = j.Stop("j2") })
	// A restarted agent knows the job only from disk.
	again := &Jobs{Dir: j.Dir, StopGrace: time.Second}
	if st := waitState(t, again, "j2", tunnelproto.JobRunning); st.Terminal() {
		t.Fatalf("state = %s", st.State)
	}
}

func TestJobStopKillsTheProcessGroup(t *testing.T) {
	j := testJobs(t)
	// A child in the background and one that ignores SIGTERM.
	cmd := "sleep 300 & trap '' TERM; sleep 300; wait"
	if _, err := j.Start("j3", cmd, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	waitState(t, j, "j3", tunnelproto.JobRunning)
	pgid := pgidOf(t, j, "j3")
	time.Sleep(200 * time.Millisecond)
	st, err := j.Stop("j3")
	if err != nil {
		t.Fatal(err)
	}
	if st.State != tunnelproto.JobStopped || st.EndedAt == nil {
		t.Fatalf("after stop: %+v", st)
	}
	if err := syscall.Kill(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("process group %d still has members: %v", pgid, err)
	}
	// Stopping again changes nothing.
	if st2, err := j.Stop("j3"); err != nil || st2.State != tunnelproto.JobStopped {
		t.Fatalf("second stop: %+v %v", st2, err)
	}
}

func TestJobPastItsDeadlineIsTimedOut(t *testing.T) {
	j := testJobs(t)
	if _, err := j.Start("j4", "sleep 300", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	waitState(t, j, "j4", tunnelproto.JobRunning)
	pgid := pgidOf(t, j, "j4")
	j.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	st, err := j.Status("j4", 10)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != tunnelproto.JobTimedOut {
		t.Fatalf("state = %s, want timed_out", st.State)
	}
	if err := syscall.Kill(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("process group %d survived its deadline", pgid)
	}
}

func TestJobKilledFromOutsideIsLost(t *testing.T) {
	j := testJobs(t)
	if _, err := j.Start("j5", "sleep 300", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	waitState(t, j, "j5", tunnelproto.JobRunning)
	_ = syscall.Kill(-pgidOf(t, j, "j5"), syscall.SIGKILL)
	waitState(t, j, "j5", tunnelproto.JobLost)
}

func TestJobStartRefusesBadInput(t *testing.T) {
	j := testJobs(t)
	now := time.Now()
	for name, c := range map[string]struct {
		id, cmd string
		dl      time.Time
	}{
		"bad id":       {"../x", "true", now.Add(time.Hour)},
		"empty":        {"a", " ", now.Add(time.Hour)},
		"past":         {"b", "true", now.Add(-time.Second)},
		"too far":      {"c", "true", now.Add(MaxJobDuration + time.Hour)},
		"too long cmd": {"d", strings.Repeat("x", MaxJobCommand+1), now.Add(time.Hour)},
	} {
		if _, err := j.Start(c.id, c.cmd, c.dl); err == nil {
			t.Errorf("%s: started", name)
		}
	}
	if _, err := j.Start("e", "true", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Start("e", "true", now.Add(time.Hour)); !errors.Is(err, ErrJobExists) {
		t.Fatalf("reused id: %v", err)
	}
}

func TestJobTailIsCapped(t *testing.T) {
	j := testJobs(t)
	if _, err := j.Start("j6", "seq 1 100000", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	waitState(t, j, "j6", tunnelproto.JobExited)
	st, _ := j.Status("j6", 3)
	if st.Tail != "99998\n99999\n100000" || !st.TailTruncated || st.OutputBytes < MaxJobTailBytes {
		t.Fatalf("tail = %q truncated=%v bytes=%d", st.Tail, st.TailTruncated, st.OutputBytes)
	}
}

func TestJobToolsAreServedAndAudited(t *testing.T) {
	j := testJobs(t)
	rec := &recorder{}
	reg, err := New(append(append([]Tool{}, Tools...), JobTools(j)...), rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Start("j7", "sleep 300", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	out, err := reg.Call(context.Background(), tunnelproto.JobStatusTool, map[string]string{"id": "j7", "lines": "5"})
	if err != nil {
		t.Fatal(err)
	}
	var st tunnelproto.JobStatus
	if err := json.Unmarshal(out, &st); err != nil || st.State != tunnelproto.JobRunning {
		t.Fatalf("status: %s %v", out, err)
	}
	out, err = reg.Call(context.Background(), tunnelproto.JobStopTool, map[string]string{"id": "j7"})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &st); err != nil || st.State != tunnelproto.JobStopped {
		t.Fatalf("stop: %s %v", out, err)
	}
	// No command text is accepted, and unknown jobs are refused.
	if _, err := reg.Call(context.Background(), tunnelproto.JobStopTool, map[string]string{"id": "j7", "command": "id"}); err == nil {
		t.Fatal("stop accepted a command argument")
	}
	if _, err := reg.Call(context.Background(), tunnelproto.JobStatusTool, map[string]string{"id": "nope"}); err == nil {
		t.Fatal("status of an unknown job")
	}
	calls := rec.snapshot()
	if len(calls) != 4 || !calls[1].Allowed || calls[1].Tool != tunnelproto.JobStopTool || calls[3].Allowed {
		t.Fatalf("audit = %+v", calls)
	}
}

func TestJobStartCommandRoundTrips(t *testing.T) {
	line := tunnelproto.JobStartCommand("job_1", time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), "fio --name='x' \"$HOME\"")
	if !strings.HasPrefix(line, tunnelproto.AgentBinary+" job start --id job_1 --deadline 2030-01-02T03:04:05Z --command-b64 ") ||
		strings.ContainsAny(line, "'\"$") {
		t.Fatalf("line = %s", line)
	}
}

// systemd-run expands $$ to $ (and $VAR, %x specifiers) in a unit's argv;
// the spawn argv must carry none of them.
func TestJobArgvSurvivesSystemdExpansion(t *testing.T) {
	var got []string
	j := &Jobs{Dir: t.TempDir(), StopGrace: time.Second,
		Spawn: func(_ string, argv []string) (string, error) {
			got = argv
			for i, a := range argv {
				if strings.ContainsAny(a, "$%") {
					t.Errorf("spawn argv[%d] has $ or %%: %q", i, a)
				}
				argv[i] = strings.ReplaceAll(a, "$$", "$")
			}
			return "", SetsidSpawn(argv)
		}}
	if _, err := j.Start("j-sysd", "sleep 0.3", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("spawn not called")
	}
	if pg := pgidOf(t, j, "j-sysd"); pg <= 0 {
		t.Fatalf("pgid = %d, want the leader's pid", pg)
	}
	waitState(t, j, "j-sysd", tunnelproto.JobExited)
}
