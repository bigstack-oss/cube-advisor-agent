package toolplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// These exercise runCommand for real, because the registry tests stub it out
// and the properties below are the ones that hold at the exec boundary.

// No shell is involved, so metacharacters are ordinary argument bytes. If a
// shell were in the path this would run `id`; instead the characters come back
// verbatim. This is the difference between "inert" and "filtered".
func TestExecUsesNoShellSoMetacharactersAreInert(t *testing.T) {
	out, err := runCommand(context.Background(),
		[]string{"echo", "hello; id && whoami | cat > /tmp/x"}, 4096)
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != "hello; id && whoami | cat > /tmp/x" {
		t.Fatalf("output = %q; a shell interpreted the argument", got)
	}
}

// One tool call must not be able to exhaust the node's memory.
func TestExecBoundsOutput(t *testing.T) {
	const max = 1000
	out, err := runCommand(context.Background(),
		[]string{"head", "-c", "50000", "/dev/zero"}, max)
	if len(out) != max {
		t.Errorf("output = %d bytes, want it capped at %d", len(out), max)
	}
	if !errors.Is(err, ErrOutputTruncated) {
		t.Errorf("truncation should be reported as ErrOutputTruncated, got err = %v", err)
	}
}

// A tool call is a diagnostic read, not a job: it has a deadline.
func TestExecHonoursTheDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := runCommand(ctx, []string{"sleep", "10"}, 4096); err == nil {
		t.Fatal("a command past its deadline returned no error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("deadline took %s to bite; the process was not killed", elapsed)
	}
}

// A command that fails still returns whatever it managed to emit, so the agent
// can report the stderr an operator needs rather than an opaque exit code.
func TestExecReturnsOutputAlongsideAFailure(t *testing.T) {
	out, err := runCommand(context.Background(),
		[]string{"ls", "/definitely/not/here"}, 4096)
	if err == nil {
		t.Fatal("expected a non-zero exit")
	}
	if len(out) == 0 {
		t.Error("no output captured; stderr is what makes a failure diagnosable")
	}
}

func TestExecReportsAMissingProgram(t *testing.T) {
	if _, err := runCommand(context.Background(),
		[]string{"definitely-not-a-real-program-xyz"}, 4096); err == nil {
		t.Error("a missing executable returned no error")
	}
}
