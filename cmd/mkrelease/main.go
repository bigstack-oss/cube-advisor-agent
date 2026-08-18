// mkrelease builds the agent for each supported architecture and writes the
// release manifest beside the binaries.
//
// It deliberately does not sign. The release signing key lives in the SaaS
// repository's CI, not in this public one (ADR 0003), so signing is a separate
// step run somewhere this code never reaches. Keeping the two apart is the
// point: a build pipeline that could also sign is a build pipeline that can
// mint releases.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bigstack-oss/cube-advisor-agent/internal/release"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// targets are the architectures a release ships. Listed rather than derived, so
// adding one is a visible change in a diff.
var targets = []struct{ os, arch string }{
	{"linux", "amd64"},
	{"linux", "arm64"},
}

func main() {
	out := flag.String("out", "dist", "directory to write artifacts and the manifest into")
	version := flag.String("version", "", "release version, e.g. 0.2.0 (required)")
	commit := flag.String("commit", "", "git commit being released (defaults to git HEAD)")
	flag.Parse()

	if *version == "" {
		log.Fatal("mkrelease: -version is required; a release without a version cannot be pinned")
	}
	if *commit == "" {
		*commit = gitHead()
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatalf("mkrelease: %v", err)
	}
	for _, t := range targets {
		name := fmt.Sprintf("cube-advisor-agent_%s_%s", t.os, t.arch)
		path := filepath.Join(*out, name)
		log.Printf("mkrelease: building %s", name)
		cmd := exec.Command("go", "build",
			"-trimpath", // so the manifest does not depend on where it was built
			"-ldflags", fmt.Sprintf("-s -w -X main.version=%s -X main.commit=%s", *version, *commit),
			"-o", path, "./cmd/agent")
		cmd.Env = append(os.Environ(),
			"GOOS="+t.os, "GOARCH="+t.arch, "CGO_ENABLED=0")
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("mkrelease: building %s: %v", name, err)
		}
	}

	m, err := release.Build(*out, *version, *commit, tunnelproto.Version)
	if err != nil {
		log.Fatalf("mkrelease: %v", err)
	}
	if err := release.WriteManifest(*out, m); err != nil {
		log.Fatalf("mkrelease: %v", err)
	}

	log.Printf("mkrelease: %s (%s), protocol v%d, %d artifacts",
		m.Version, m.Commit, m.ProtocolVersion, len(m.Artifacts))
	log.Printf("mkrelease: sign %s out of band; this pipeline holds no signing key",
		filepath.Join(*out, release.ManifestName))
}

func gitHead() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		log.Fatal("mkrelease: cannot determine the commit; pass -commit")
	}
	return strings.TrimSpace(string(out))
}
