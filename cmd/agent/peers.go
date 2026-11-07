package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"os/exec"
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

// enrollPeersOnce enrols the cluster's other nodes the first time this node is
// admitted after enrolling. One attempt: each peer lands on the Advisor's
// enrolment page to verify, and `advisor enroll` with no token retries.
func enrollPeersOnce(ctx context.Context, dir string) {
	if !identity.TakePeersPending(dir) {
		return
	}
	if _, err := os.Stat(hexSDK); err != nil {
		log.Printf("agent: peers: %s not found; enrol the other nodes with `advisor enroll`", hexSDK)
		return
	}
	log.Printf("agent: peers: admitted; enrolling this cluster's other nodes")
	ctx, cancel := context.WithTimeout(ctx, peersTimeout)
	defer cancel()
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			log.Printf("agent: peers: %s", sc.Text())
		}
	}()
	err := enrollPeersCmd(ctx, pw)
	pw.Close()
	<-done
	if err != nil {
		log.Printf("agent: peers: fan-out did not complete: %v; run `advisor enroll` with no token to retry", err)
		return
	}
	log.Printf("agent: peers: done; verify each new node on the Advisor's enrolment page")
}
