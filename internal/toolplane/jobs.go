package toolplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// DefaultJobsDir holds one directory per background job.
const DefaultJobsDir = "/var/lib/cube-advisor-agent/jobs"

// Job limits.
const (
	MaxJobCommand   = 16 << 10
	MaxJobDuration  = 30 * 24 * time.Hour
	MaxJobTailBytes = 16 << 10
	DefaultJobLines = 50
	MaxJobLines     = 500
	// jobStartGrace is how long a job may run before its pgid file appears.
	jobStartGrace = 30 * time.Second
	// jobKeep is how long a finished job's directory stays on the node.
	jobKeep = 14 * 24 * time.Hour
)

var jobID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ErrJobExists refuses a start that reuses an id.
var ErrJobExists = errors.New("toolplane: job already exists")

// jobScript runs the command as the job's process-group leader, writes its
// pgid first and its exit code last. $1 is the job directory.
const jobScript = `d="$1"
echo $$ > "$d/pgid.tmp" && mv "$d/pgid.tmp" "$d/pgid"
cd "$d/work" || exit 1
/bin/bash -l "$d/command" > "$d/out" 2>&1 < /dev/null
rc=$?
echo $rc > "$d/exit.tmp" && mv "$d/exit.tmp" "$d/exit"
`

// Jobs starts, follows and stops background jobs. State lives on disk under
// Dir, so a job outlives the agent and the process that started it.
type Jobs struct {
	Dir string
	// Spawn starts argv detached; nil picks systemd-run on systemd hosts,
	// else setsid. unit names the systemd unit, empty for setsid.
	Spawn func(id string, argv []string) (unit string, err error)
	// StopGrace is how long stop waits after SIGTERM; zero means 5s.
	StopGrace time.Duration
	Now       func() time.Time
}

type jobMeta struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"startedAt"`
	DeadlineAt time.Time `json:"deadlineAt"`
	BootID     string    `json:"bootId"`
	Unit       string    `json:"unit,omitempty"`
}

type jobEnd struct {
	State string    `json:"state"` // stopped or timed_out
	At    time.Time `json:"at"`
}

func (j *Jobs) dir() string {
	if j.Dir == "" {
		return DefaultJobsDir
	}
	return j.Dir
}

func (j *Jobs) now() time.Time {
	if j.Now != nil {
		return j.Now().UTC()
	}
	return time.Now().UTC()
}

func (j *Jobs) path(id string, name ...string) string {
	return filepath.Join(append([]string{j.dir(), id}, name...)...)
}

// Start runs command detached and returns at once.
func (j *Jobs) Start(id, command string, deadline time.Time) (tunnelproto.JobStatus, error) {
	now := j.now()
	switch {
	case !jobID.MatchString(id):
		return tunnelproto.JobStatus{}, fmt.Errorf("job id must match %s", jobID)
	case strings.TrimSpace(command) == "":
		return tunnelproto.JobStatus{}, errors.New("job command is empty")
	case len(command) > MaxJobCommand:
		return tunnelproto.JobStatus{}, fmt.Errorf("job command is %d bytes; at most %d", len(command), MaxJobCommand)
	case !deadline.After(now):
		return tunnelproto.JobStatus{}, errors.New("job deadline is in the past")
	case deadline.Sub(now) > MaxJobDuration:
		return tunnelproto.JobStatus{}, fmt.Errorf("job deadline is more than %s away", MaxJobDuration)
	}
	if err := os.MkdirAll(j.dir(), 0o700); err != nil {
		return tunnelproto.JobStatus{}, err
	}
	if err := os.Mkdir(j.path(id), 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return tunnelproto.JobStatus{}, fmt.Errorf("%w: %s", ErrJobExists, id)
		}
		return tunnelproto.JobStatus{}, err
	}
	if err := os.Mkdir(j.path(id, "work"), 0o700); err != nil {
		return tunnelproto.JobStatus{}, err
	}
	if err := os.WriteFile(j.path(id, "command"), []byte(command), 0o600); err != nil {
		return tunnelproto.JobStatus{}, err
	}
	meta := jobMeta{ID: id, StartedAt: now, DeadlineAt: deadline.UTC(), BootID: bootID()}
	if err := j.writeMeta(meta); err != nil {
		return tunnelproto.JobStatus{}, err
	}
	spawn := j.Spawn
	if spawn == nil {
		spawn = DefaultSpawn(deadline)
	}
	unit, err := spawn(id, []string{"/bin/bash", "-c", jobScript, "advisor-job", j.path(id)})
	if err != nil {
		_ = j.writeEnd(id, jobEnd{State: tunnelproto.JobLost, At: now})
		return tunnelproto.JobStatus{}, fmt.Errorf("start job: %w", err)
	}
	if unit != "" {
		meta.Unit = unit
		if err := j.writeMeta(meta); err != nil {
			return tunnelproto.JobStatus{}, err
		}
	}
	// Wait briefly for the leader's pgid so stop works straight away.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(j.path(id, "pgid")); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return j.Status(id, DefaultJobLines)
}

// DefaultSpawn starts a job in its own transient systemd unit where systemd
// runs, so restarting the agent or closing the SSH session leaves it alone;
// elsewhere, or when not root, it starts it in a new session with setsid.
func DefaultSpawn(deadline time.Time) func(id string, argv []string) (string, error) {
	return func(id string, argv []string) (string, error) {
		if _, err := os.Stat("/run/systemd/system"); err == nil && os.Geteuid() == 0 {
			if path, err := exec.LookPath("systemd-run"); err == nil {
				unit := "cube-advisor-job-" + id
				max := int(time.Until(deadline).Seconds()) + 600
				args := []string{"--unit=" + unit, "--description=Advisor background job " + id, "--collect", "--quiet",
					"-p", "TimeoutStopSec=15", "-p", fmt.Sprintf("RuntimeMaxSec=%d", max), "--"}
				out, err := exec.Command(path, append(args, argv...)...).CombinedOutput()
				if err != nil {
					return "", fmt.Errorf("systemd-run: %v: %s", err, bytes.TrimSpace(out))
				}
				return unit, nil
			}
		}
		return "", SetsidSpawn(argv)
	}
}

// SetsidSpawn starts argv as the leader of a new session and process group,
// with no inherited descriptors.
func SetsidSpawn(argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// Status reads a job's state, ending it first if its deadline has passed.
func (j *Jobs) Status(id string, lines int) (tunnelproto.JobStatus, error) {
	st, meta, pgid, err := j.read(id, lines)
	if err != nil {
		return st, err
	}
	if st.State == tunnelproto.JobRunning && !j.now().Before(meta.DeadlineAt) && pgid > 0 {
		return j.stop(id, tunnelproto.JobTimedOut, lines)
	}
	return st, nil
}

// Stop ends a running job's process group: SIGTERM, then SIGKILL.
func (j *Jobs) Stop(id string) (tunnelproto.JobStatus, error) {
	return j.stop(id, tunnelproto.JobStopped, DefaultJobLines)
}

func (j *Jobs) stop(id, reason string, lines int) (tunnelproto.JobStatus, error) {
	st, meta, pgid, err := j.read(id, lines)
	if err != nil || st.Terminal() {
		return st, err
	}
	if err := j.writeEnd(id, jobEnd{State: reason, At: j.now()}); err != nil {
		return st, err
	}
	if pgid > 0 {
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
		grace := j.StopGrace
		if grace <= 0 {
			grace = 5 * time.Second
		}
		for end := time.Now().Add(grace); groupAlive(pgid) && time.Now().Before(end); {
			time.Sleep(100 * time.Millisecond)
		}
		if groupAlive(pgid) {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
	}
	if meta.Unit != "" {
		// Anything left in the unit's cgroup, e.g. a child that called setsid.
		_ = exec.Command("systemctl", "kill", "--signal=SIGKILL", meta.Unit).Run()
	}
	for end := time.Now().Add(2 * time.Second); pgid > 0 && groupAlive(pgid) && time.Now().Before(end); {
		time.Sleep(50 * time.Millisecond)
	}
	st, _, _, err = j.read(id, lines)
	return st, err
}

// read derives a job's state from its files.
func (j *Jobs) read(id string, lines int) (tunnelproto.JobStatus, jobMeta, int, error) {
	if !jobID.MatchString(id) {
		return tunnelproto.JobStatus{}, jobMeta{}, 0, fmt.Errorf("job id must match %s", jobID)
	}
	var meta jobMeta
	b, err := os.ReadFile(j.path(id, "meta.json"))
	if err != nil {
		return tunnelproto.JobStatus{}, meta, 0, fmt.Errorf("no job %s", id)
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return tunnelproto.JobStatus{}, meta, 0, fmt.Errorf("job %s: %w", id, err)
	}
	st := tunnelproto.JobStatus{ID: id, StartedAt: meta.StartedAt, DeadlineAt: meta.DeadlineAt}
	st.OutputBytes, st.Tail, st.TailTruncated = tail(j.path(id, "out"), lines)

	pgid := 0
	if b, err := os.ReadFile(j.path(id, "pgid")); err == nil {
		pgid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	sameBoot := meta.BootID == "" || meta.BootID == bootID()
	alive := pgid > 0 && sameBoot && groupAlive(pgid)

	var end jobEnd
	ended := false
	if b, err := os.ReadFile(j.path(id, "end.json")); err == nil && json.Unmarshal(b, &end) == nil {
		ended = true
	}
	code, exited, exitAt := readExit(j.path(id, "exit"))
	switch {
	case ended && !alive:
		st.State, st.EndedAt = end.State, &end.At
		if exited {
			st.ExitCode = &code
		}
	case exited:
		st.State, st.ExitCode, st.EndedAt = tunnelproto.JobExited, &code, &exitAt
	case alive:
		st.State = tunnelproto.JobRunning
	case pgid == 0 && sameBoot && j.now().Sub(meta.StartedAt) < jobStartGrace:
		st.State = tunnelproto.JobRunning
	default:
		// Gone without an exit code: killed from outside, OOM or a reboot.
		st.State = tunnelproto.JobLost
	}
	return st, meta, pgid, nil
}

// List reports every job on the node, newest first.
func (j *Jobs) List() []tunnelproto.JobStatus {
	entries, _ := os.ReadDir(j.dir())
	var out []tunnelproto.JobStatus
	for _, e := range entries {
		if st, err := j.Status(e.Name(), 0); err == nil {
			out = append(out, st)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].StartedAt.After(out[b].StartedAt) })
	return out
}

// Sweep enforces deadlines and removes old finished jobs, every minute.
func (j *Jobs) Sweep(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		for _, st := range j.List() {
			if st.EndedAt != nil && j.now().Sub(*st.EndedAt) > jobKeep {
				_ = os.RemoveAll(j.path(st.ID))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (j *Jobs) writeMeta(m jobMeta) error {
	b, _ := json.Marshal(m)
	return writeAtomic(j.path(m.ID, "meta.json"), b)
}

func (j *Jobs) writeEnd(id string, e jobEnd) error {
	b, _ := json.Marshal(e)
	return writeAtomic(j.path(id, "end.json"), b)
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readExit(path string) (int, bool, time.Time) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false, time.Time{}
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, false, time.Time{}
	}
	at := time.Time{}
	if fi, err := os.Stat(path); err == nil {
		at = fi.ModTime().UTC()
	}
	return code, true, at
}

// tail returns the output's size and its last lines, at most MaxJobTailBytes.
func tail(path string, lines int) (int64, string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, "", false
	}
	size := fi.Size()
	if lines <= 0 {
		return size, "", false
	}
	off := size - MaxJobTailBytes
	cut := off > 0
	if off < 0 {
		off = 0
	}
	buf := make([]byte, size-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return size, "", false
	}
	if cut {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	all := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if len(all) > lines {
		all, cut = all[len(all)-lines:], true
	}
	return size, strings.ToValidUTF8(strings.Join(all, "\n"), "�"), cut
}

// groupAlive reports whether any process is left in the process group.
func groupAlive(pgid int) bool {
	err := syscall.Kill(-pgid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}

// JobTools are the tool calls that follow and stop jobs. Neither runs
// caller text: an id is a directory this agent created.
func JobTools(j *Jobs) []Tool {
	return []Tool{
		{
			Name:        tunnelproto.JobStatusTool,
			Description: "A background job's state, exit code, output size and last lines.",
			Timeout:     30 * time.Second,
			Local: func(_ context.Context, args map[string]string) ([]byte, error) {
				id, lines, err := jobArgs(args, true)
				if err != nil {
					return nil, err
				}
				st, err := j.Status(id, lines)
				if err != nil {
					return nil, err
				}
				return json.Marshal(st)
			},
		},
		{
			Name:        tunnelproto.JobStopTool,
			Description: "Stop a background job: SIGTERM to its process group, then SIGKILL.",
			Timeout:     30 * time.Second,
			Local: func(_ context.Context, args map[string]string) ([]byte, error) {
				id, _, err := jobArgs(args, false)
				if err != nil {
					return nil, err
				}
				st, err := j.Stop(id)
				if err != nil {
					return nil, err
				}
				return json.Marshal(st)
			},
		},
	}
}

func jobArgs(args map[string]string, withLines bool) (string, int, error) {
	lines := DefaultJobLines
	for k, v := range args {
		switch {
		case k == "id":
		case k == "lines" && withLines:
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > MaxJobLines {
				return "", 0, fmt.Errorf("lines must be 0 to %d", MaxJobLines)
			}
			lines = n
		default:
			return "", 0, fmt.Errorf("unexpected argument %q", k)
		}
	}
	if !jobID.MatchString(args["id"]) {
		return "", 0, fmt.Errorf("id must match %s", jobID)
	}
	return args["id"], lines, nil
}
