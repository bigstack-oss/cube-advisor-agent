package toolplane

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ToolCall is one record in the local log.
//
// Both halves matter. The allowed calls are what the vendor actually did; the
// refused ones are what the vendor asked for and did not get, which is the part
// a customer reviewing access most wants to see.
type ToolCall struct {
	At       time.Time         `json:"at"`
	Tool     string            `json:"tool"`
	Args     map[string]string `json:"args,omitempty"`
	Argv     []string          `json:"argv,omitempty"` // exactly what ran, empty when refused
	Allowed  bool              `json:"allowed"`
	Reason   string            `json:"reason,omitempty"`
	Duration time.Duration     `json:"durationMs,omitempty"`
	Bytes    int               `json:"bytes,omitempty"`
}

// Auditor records tool calls.
type Auditor interface {
	RecordToolCall(ToolCall)
}

// FileAuditor appends JSON lines to a file on the cluster.
//
// Local and append-only on purpose: the record of what the vendor did lives on
// the customer's own machine, readable with `cat`, and does not depend on the
// SaaS to be honest about it.
type FileAuditor struct {
	mu sync.Mutex
	w  io.WriteCloser
}

// DefaultAuditPath is where the log lands on a CubeCOS node.
const DefaultAuditPath = "/var/log/cube-advisor-agent/tool-calls.jsonl"

// NewFileAuditor opens (creating if needed) an append-only log.
func NewFileAuditor(path string) (*FileAuditor, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("toolplane: audit dir: %w", err)
	}
	// 0644: the customer must be able to read this without root. It contains
	// what was asked and what ran, never tool output.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("toolplane: open audit log: %w", err)
	}
	return &FileAuditor{w: f}, nil
}

// NewWriterAuditor writes records to w. Used by tests and by callers that
// already own a log sink.
func NewWriterAuditor(w io.WriteCloser) *FileAuditor { return &FileAuditor{w: w} }

func (a *FileAuditor) RecordToolCall(c ToolCall) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Milliseconds read better than nanoseconds for a human scanning the log.
	type wire struct {
		ToolCall
		Duration int64 `json:"durationMs,omitempty"`
	}
	rec := wire{ToolCall: c, Duration: c.Duration.Milliseconds()}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	// A failed audit write must not be silent, but must also not take the agent
	// down: the tool call already happened, and losing the agent loses the
	// customer's support path.
	if _, err := a.w.Write(append(b, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "toolplane: audit write failed: %v\n", err)
	}
}

func (a *FileAuditor) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.w.Close()
}
