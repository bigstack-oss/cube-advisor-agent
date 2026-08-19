package tunnelproto

import (
	"bytes"
	"strings"
	"testing"
)

// The point of moving this contract into pkg/ is that both sides share one
// implementation. This is the test that says so: what the SaaS writes is what
// the agent reads, and vice versa.
func TestToolCallRoundTrips(t *testing.T) {
	var wire bytes.Buffer
	sent := map[string]string{"group": "Storage"}
	if err := WriteToolArgs(&wire, sent); err != nil {
		t.Fatalf("WriteToolArgs: %v", err)
	}
	got, err := ReadToolArgs(&wire)
	if err != nil {
		t.Fatalf("ReadToolArgs: %v", err)
	}
	if got["group"] != "Storage" {
		t.Errorf("args = %v, want group=Storage", got)
	}

	var back bytes.Buffer
	if err := WriteToolResult(&back, ToolResult{OK: true, Output: "all ok"}); err != nil {
		t.Fatalf("WriteToolResult: %v", err)
	}
	res, err := ReadToolResult(&back)
	if err != nil {
		t.Fatalf("ReadToolResult: %v", err)
	}
	if !res.OK || res.Output != "all ok" {
		t.Errorf("result = %+v", res)
	}
}

// The frame is newline-terminated because a yamux stream has no half-close:
// a caller cannot signal "arguments finished" without closing the stream it is
// about to read the result from. Losing the newline deadlocks every call.
func TestArgsFrameIsNewlineTerminated(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteToolArgs(&wire, map[string]string{"a": "b"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(wire.String(), "\n") {
		t.Errorf("argument frame %q does not end in a newline", wire.String())
	}
	if strings.Count(wire.String(), "\n") != 1 {
		t.Errorf("argument frame contains %d newlines, want 1", strings.Count(wire.String(), "\n"))
	}
}

// A tool taking no arguments still sends a frame, or the reader blocks.
func TestNilArgsWriteAnEmptyObject(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteToolArgs(&wire, nil); err != nil {
		t.Fatal(err)
	}
	if wire.String() != "{}\n" {
		t.Errorf("nil args wrote %q, want %q", wire.String(), "{}\n")
	}
}

func TestOversizedArgsAreRefusedBeforeSending(t *testing.T) {
	var wire bytes.Buffer
	err := WriteToolArgs(&wire, map[string]string{"x": strings.Repeat("a", MaxToolArgsBytes)})
	if err == nil {
		t.Fatal("an oversized argument frame was written")
	}
	if wire.Len() != 0 {
		t.Errorf("%d bytes were written before the refusal", wire.Len())
	}
}

func TestOversizedArgsAreRefusedOnReceipt(t *testing.T) {
	line := `{"x":"` + strings.Repeat("a", MaxToolArgsBytes) + `"}` + "\n"
	if _, err := ReadToolArgs(strings.NewReader(line)); err == nil {
		t.Fatal("an oversized argument frame was accepted")
	}
}

// The SaaS reads from a cluster it does not control. An unbounded read is an
// unbounded allocation.
func TestResultReadIsBounded(t *testing.T) {
	huge := `{"ok":true,"output":"` + strings.Repeat("a", MaxToolOutputBytes) + `"}`
	if _, err := ReadToolResult(strings.NewReader(huge)); err == nil {
		t.Fatal("an oversized result frame was accepted whole")
	}
}

// Every refusal must look identical from the SaaS's side; a precise refusal is
// a probe oracle for the allowlist.
func TestRefusedCarriesNoDetail(t *testing.T) {
	r := Refused()
	if r.OK {
		t.Error("a refusal reported OK")
	}
	if r.Error != RefusedReason {
		t.Errorf("Error = %q, want the single flat reason %q", r.Error, RefusedReason)
	}
	if r.Output != "" {
		t.Errorf("a refusal carried output: %q", r.Output)
	}
}

// Wire compatibility: the JSON field names are the contract, and renaming a Go
// field must not silently change them.
func TestResultWireFieldNames(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteToolResult(&buf, ToolResult{OK: true, Output: "x", Error: "y"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"ok":`, `"output":`, `"error":`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("result frame %s is missing %s", buf.String(), want)
		}
	}
}
