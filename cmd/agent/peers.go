package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
)

// hexSDK is the CubeCOS helper whose advisor_enroll_peers enrols every node
// of the cluster that has no identity yet.
var hexSDK = "/usr/sbin/hex_sdk"

// peersTimeout bounds one fan-out: each peer downloads and installs the agent.
const peersTimeout = 30 * time.Minute

// enrollPeersCmd runs the fan-out and streams its output; a var for tests.
var enrollPeersCmd = func(ctx context.Context, out io.Writer) error {
	cmd := exec.CommandContext(ctx, hexSDK, "advisor_enroll_peers")
	cmd.Stdout, cmd.Stderr = out, out
	return cmd.Run()
}

// cosVersionFile names the running CubeCOS release; a var for tests.
var cosVersionFile = "/etc/version"

// enrollPeersOnce enrols the cluster's other nodes the first time this node is
// admitted after enrolling, and again on the first admitted connect after the
// CubeCOS version changes (an upgrade may let more nodes enrol). With no
// recorded version, an enrolled node records the current one without running.
// advisor_enroll_peers may enrol only one peer per run, so it is re-run while
// the count of unenrolled peers it reports falls; that count bounds the passes. Each peer lands on the Advisor's enrolment
// page to verify, and `advisor enroll` with no token retries.
func enrollPeersOnce(ctx context.Context, dir string) {
	fresh := identity.TakePeersPending(dir)
	cur := cosVersion()
	last, seen := identity.PeersVersion(dir)
	upgraded := seen && cur != "" && cur != last
	// Recorded before running: a reconnect mid-run must not start another.
	if cur != "" && cur != last {
		if err := identity.RecordPeersVersion(dir, cur); err != nil {
			log.Printf("agent: peers: %v", err)
		}
	}
	if !fresh && !upgraded {
		return
	}
	if _, err := os.Stat(hexSDK); err != nil {
		log.Printf("agent: peers: %s not found; enrol the other nodes with `advisor enroll`", hexSDK)
		return
	}
	if fresh {
		log.Printf("agent: peers: admitted; enrolling this cluster's other nodes")
	} else {
		log.Printf("agent: peers: CubeCOS changed from %s to %s; enrolling any node it now allows", last, cur)
	}
	prev := -1
	for pass := 1; ; pass++ {
		log.Printf("agent: peers: pass %d", pass)
		pending, err := enrollPeersPass(ctx)
		switch {
		case pending == 0:
			log.Printf("agent: peers: done; verify each new node on the Advisor's enrolment page")
			return
		case pending < 0 && err != nil:
			log.Printf("agent: peers: fan-out did not complete: %v; run `advisor enroll` with no token to retry", err)
			return
		case pending < 0:
			log.Printf("agent: peers: done; verify each new node on the Advisor's enrolment page")
			return
		case prev >= 0 && pending >= prev:
			log.Printf("agent: peers: %d node(s) still not enrolled; run `advisor enroll` with no token to retry", pending)
			return
		}
		prev = pending
	}
}

// enrollPeersPass runs advisor_enroll_peers once, logging its output. It
// returns how many peers were unenrolled when it started: 0 when all were,
// -1 when the output did not say.
func enrollPeersPass(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, peersTimeout)
	defer cancel()
	pr, pw := io.Pipe()
	pending := -1
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := sc.Text()
			log.Printf("agent: peers: %s", line)
			if m := enrollingRE.FindStringSubmatch(line); m != nil {
				pending, _ = strconv.Atoi(m[1])
			} else if strings.HasPrefix(line, allEnrolled) {
				pending = 0
			}
		}
		_, _ = io.Copy(io.Discard, pr)
	}()
	err := enrollPeersCmd(ctx, pw)
	pw.Close()
	<-done
	return pending, err
}

// What advisor_enroll_peers prints before and instead of a fan-out.
var enrollingRE = regexp.MustCompile(`^Enrolling (\d+) node\(s\):`)

const allEnrolled = "Every node of this cluster is already enrolled."

// cosVersion returns the trimmed /etc/version, or "" when unreadable.
func cosVersion() string {
	b, err := os.ReadFile(cosVersionFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
