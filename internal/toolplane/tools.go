// Package toolplane serves the AI plane's tools: shell_read, a command run in
// ADR 0018's read-only sandbox reaching data only through the read brokers
// (ADR 0019), and the status and stop calls of background jobs. Writes,
// starting a job included, go through the recorded console instead.
//
// Every call, served or refused, is written to a local append-only log the
// customer can read. The node's action level and consent files are still read
// and reported in the Hello; the Advisor applies them.
package toolplane

import (
	"context"
	"fmt"
	"time"
)

// Tool is one operation the AI plane may invoke.
type Tool struct {
	// Name is what the Advisor asks for, matched exactly.
	Name string

	// Description is for the operator reading this file.
	Description string

	// Sandbox runs the caller's command text in SandboxArgvFor's sandbox.
	Sandbox bool

	// Local serves the call in the agent itself, running no caller text:
	// the background-job status and stop calls.
	Local func(ctx context.Context, args map[string]string) ([]byte, error)

	// MaxOutputBytes caps one call's output. Zero means the registry default.
	MaxOutputBytes int

	// Timeout bounds one call. Zero means the registry default. It must stay
	// under the server's per-call cap so this timeout fires first.
	Timeout time.Duration
}

// Tools is every tool the agent serves.
var Tools = []Tool{
	{
		Name:           "shell_read",
		Description:    "Run a command in the read-only sandbox; anything that changes the system fails.",
		Sandbox:        true,
		MaxOutputBytes: 64 << 10,
		Timeout:        60 * time.Second,
	},
}

// validate checks a tool is well-formed for registration.
func (t Tool) validate() error {
	if t.Name == "" {
		return fmt.Errorf("tool has no name")
	}
	if t.Sandbox == (t.Local != nil) {
		return fmt.Errorf("tool %q must be exactly one of a sandbox tool or a local one", t.Name)
	}
	if t.Timeout < 0 {
		return fmt.Errorf("tool %q has a negative timeout", t.Name)
	}
	if t.MaxOutputBytes < 0 {
		return fmt.Errorf("tool %q has a negative output cap", t.Name)
	}
	return nil
}
