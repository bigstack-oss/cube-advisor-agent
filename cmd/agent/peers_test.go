package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
)

func stubPeers(t *testing.T, run func(ctx context.Context, out io.Writer) error) (*int, *bytes.Buffer) {
	t.Helper()
	sdk := filepath.Join(t.TempDir(), "hex_sdk")
	if err := os.WriteFile(sdk, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	oldSDK, oldCmd := hexSDK, enrollPeersCmd
	calls := 0
	hexSDK = sdk
	enrollPeersCmd = func(ctx context.Context, out io.Writer) error { calls++; return run(ctx, out) }
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { hexSDK, enrollPeersCmd = oldSDK, oldCmd; log.SetOutput(os.Stderr) })
	return &calls, &logs
}

// The first admitted connect after enrolling fans out once, and the peers'
// output lands in this agent's journal.
func TestPeersAreEnrolledOnceAfterEnrolment(t *testing.T) {
	calls, logs := stubPeers(t, func(_ context.Context, out io.Writer) error {
		fmt.Fprintln(out, "== sky142")
		fmt.Fprintln(out, "   console access: enabled for this cluster")
		return nil
	})
	dir := t.TempDir()
	if err := identity.MarkPeersPending(dir); err != nil {
		t.Fatal(err)
	}
	enrollPeersOnce(context.Background(), dir)
	enrollPeersOnce(context.Background(), dir)
	if *calls != 1 {
		t.Errorf("fan-out ran %d times, want 1", *calls)
	}
	if !strings.Contains(logs.String(), "agent: peers:    console access: enabled for this cluster") {
		t.Errorf("peer output not in the journal:\n%s", logs)
	}
}

// A node that was already enrolled (no mark) never fans out on reconnect.
func TestNoFanOutWithoutAFreshEnrolment(t *testing.T) {
	calls, _ := stubPeers(t, func(context.Context, io.Writer) error { return nil })
	enrollPeersOnce(context.Background(), t.TempDir())
	if *calls != 0 {
		t.Errorf("fan-out ran %d times without a mark", *calls)
	}
}

// One attempt: a failure is logged with the manual retry, not repeated on
// every reconnect.
func TestAFailedFanOutIsNotRetriedOnReconnect(t *testing.T) {
	calls, logs := stubPeers(t, func(context.Context, io.Writer) error { return fmt.Errorf("exit status 1") })
	dir := t.TempDir()
	_ = identity.MarkPeersPending(dir)
	enrollPeersOnce(context.Background(), dir)
	enrollPeersOnce(context.Background(), dir)
	if *calls != 1 {
		t.Errorf("fan-out ran %d times, want 1", *calls)
	}
	if !strings.Contains(logs.String(), "run `advisor enroll` with no token to retry") {
		t.Errorf("no retry hint:\n%s", logs)
	}
}

// Rotation reaches sshd's copy only where console access was granted.
func TestConnectRotatesTheConsoleCAOnlyWhereGranted(t *testing.T) {
	const caA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEe4bv2j4FtzsksuvuL9LuAyISEvJt0YcT0Zr2iizt9Q c"
	const caB = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCk5w584S2EMXJmYEv0w0GrnbAsRU+hYd/ZnFt8gfIcKwK96FZOk66GQcLHLP8NPI78XxBVOrsWGf9OLdS27pJE= c"
	granted, denied := t.TempDir(), t.TempDir()
	trusted := filepath.Join(granted, "cube-advisor.pub")
	_ = os.WriteFile(trusted, []byte(caA+"\n"), 0o644)
	recordConsoleCA(granted, trusted, caB)
	recordConsoleCA(denied, filepath.Join(denied, "cube-advisor.pub"), caB)

	if b, _ := os.ReadFile(trusted); string(b) != caB+"\n" {
		t.Errorf("granted node trusts %q, want the rotated CA", b)
	}
	if _, err := os.Stat(filepath.Join(denied, "cube-advisor.pub")); !os.IsNotExist(err) {
		t.Error("a node without console access was given a trusted CA")
	}
	for _, d := range []string{granted, denied} {
		if b, _ := os.ReadFile(filepath.Join(d, identity.ConsoleCAFileName)); string(b) != caB+"\n" {
			t.Errorf("%s: console-ca.pub = %q", d, b)
		}
	}
}
