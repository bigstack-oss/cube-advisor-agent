package tunnelproto

import (
	"encoding/base64"
	"fmt"
	"time"
)

// Background jobs: an approved command started detached on a node, followed
// and stopped by id. Start runs through the recorded shell as the agent's
// `job start` command; status and stop are tool calls.

// JobsCapability in Hello.Capabilities says the agent serves background jobs.
const JobsCapability = "jobs"

// Tool names for following and stopping a job.
const (
	JobStatusTool = "job_status"
	JobStopTool   = "job_stop"
)

// Job states as the node reports them.
const (
	JobRunning  = "running"
	JobExited   = "exited"
	JobStopped  = "stopped"
	JobTimedOut = "timed_out"
	JobLost     = "lost"
)

// AgentBinary is where CubeCOS installs the agent.
const AgentBinary = "/usr/local/bin/cube-advisor-agent"

// JobStatus is what job start, job_status and job_stop return.
type JobStatus struct {
	ID          string     `json:"id"`
	State       string     `json:"state"`
	ExitCode    *int       `json:"exitCode,omitempty"`
	StartedAt   time.Time  `json:"startedAt"`
	DeadlineAt  time.Time  `json:"deadlineAt"`
	EndedAt     *time.Time `json:"endedAt,omitempty"`
	OutputBytes int64      `json:"outputBytes"`
	// Tail is the output's last lines, capped.
	Tail          string `json:"tail,omitempty"`
	TailTruncated bool   `json:"tailTruncated,omitempty"`
}

// Terminal reports whether the job can no longer change.
func (s JobStatus) Terminal() bool { return s.State != JobRunning }

// JobStartCommand is the line that starts a job on the node. The command
// travels base64-encoded so no quoting reaches it.
func JobStartCommand(id string, deadline time.Time, command string) string {
	return fmt.Sprintf("%s job start --id %s --deadline %s --command-b64 %s",
		AgentBinary, id, deadline.UTC().Format(time.RFC3339),
		base64.StdEncoding.EncodeToString([]byte(command)))
}
