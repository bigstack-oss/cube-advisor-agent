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

// fakeSDK mimics today's advisor_enroll_peers: one single-use token per run,
// so only the first peer that reaches redemption enrols. compute* peers are
// refused before redemption; broken* peers fail without spending the token
// (the Advisor marks it used only once a certificate is issued).
const fakeSDK = `#!/bin/bash
[ "$1" = advisor_enroll_peers ] || exit 2
d=$(dirname "$0")
echo run >> "$d/calls"
todo=()
while read -r n ; do [ -n "$n" ] && todo+=("$n") ; done < "$d/pending"
if [ ${#todo[@]} -eq 0 ] ; then echo "Every node of this cluster is already enrolled." ; exit 0 ; fi
echo "Enrolling ${#todo[@]} node(s): ${todo[*]}"
used=false ; : > "$d/next"
for n in "${todo[@]}" ; do
    echo "== $n"
    case $n in compute*) echo "   Error: enrol from a control node" >&2 ; echo "$n" >> "$d/next" ; continue ;; esac
    if $used ; then echo "   The pairing token was refused" >&2 ; echo "$n" >> "$d/next" ; continue ; fi
    case $n in broken*) echo "   Error: enrolment failed" >&2 ; echo "$n" >> "$d/next" ; continue ;; esac
    used=true
    echo "   enrolled"
done
mv "$d/next" "$d/pending"
`

func runFakeSDK(t *testing.T, peers ...string) (passes int, pending string, logs string) {
	t.Helper()
	d := t.TempDir()
	sdk := filepath.Join(d, "hex_sdk")
	if err := os.WriteFile(sdk, []byte(fakeSDK), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "pending"), []byte(strings.Join(peers, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldSDK := hexSDK
	hexSDK = sdk
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { hexSDK = oldSDK; log.SetOutput(os.Stderr) })

	dir := t.TempDir()
	if err := identity.MarkPeersPending(dir); err != nil {
		t.Fatal(err)
	}
	enrollPeersOnce(context.Background(), dir)
	calls, _ := os.ReadFile(filepath.Join(d, "calls"))
	left, _ := os.ReadFile(filepath.Join(d, "pending"))
	return strings.Count(string(calls), "run"), strings.TrimSpace(string(left)), buf.String()
}

// A reused token enrols one peer per run; re-running enrols them all.
func TestPeersReRunUntilAllEnrolled(t *testing.T) {
	passes, left, logs := runFakeSDK(t, "n2", "n3", "n4")
	if left != "" {
		t.Errorf("still pending: %q\n%s", left, logs)
	}
	if passes != 4 {
		t.Errorf("%d passes, want 4 (three enrolments and a check)", passes)
	}
	if !strings.Contains(logs, "agent: peers: pass 4") || !strings.Contains(logs, "agent: peers: done") {
		t.Errorf("passes not logged:\n%s", logs)
	}
}

// Peers that never enrol do not block the rest, and stop the loop once the
// count stops falling.
func TestPeersStopWhenNoProgress(t *testing.T) {
	passes, left, logs := runFakeSDK(t, "compute2", "n3", "broken4", "n5")
	if left != "compute2\nbroken4" {
		t.Errorf("pending = %q, want compute2 and broken4\n%s", left, logs)
	}
	if passes > 5 {
		t.Errorf("%d passes for 4 peers", passes)
	}
	if !strings.Contains(logs, "2 node(s) still not enrolled") {
		t.Errorf("no-progress stop not logged:\n%s", logs)
	}
}
