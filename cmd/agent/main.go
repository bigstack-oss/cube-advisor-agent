// cube-advisor-agent is the on-cluster agent: it dials the SaaS outbound, serves
// read-only tools from an allowlist it enforces itself, and (later) carries
// recorded human consoles.
//
// It is released as a signed per-arch artifact and verified by CubeCOS before
// it runs (ADR 0003); this repository never holds the signing key.
package main

import (
	"flag"
	"fmt"
	"log"
)

// Set at build time by mkrelease.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("cube-advisor-agent %s (%s)\n", version, commit)
		return
	}
	// TODO: load the enrolled identity, dial the tunnel with mTLS, serve the
	// tool plane. The pieces exist in internal/identity, pkg/tunnel and
	// internal/agent; wiring them into a daemon is the next task.
	log.Printf("cube-advisor-agent %s (%s): no runtime yet", version, commit)
}
