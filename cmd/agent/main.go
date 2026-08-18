// cube-advisor-agent is the on-cluster agent: it dials the SaaS outbound, serves
// read-only tools from an allowlist it enforces itself, and (later) carries
// recorded human consoles.
//
// It is released as a signed per-arch artifact and verified by CubeCOS before
// it runs (ADR 0003); this repository never holds the signing key.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
)

// Set at build time by mkrelease.
var (
	version = "dev"
	commit  = "none"
)

// Exit codes an installer can branch on. A script that can only see "non-zero"
// has to parse messages, and then the messages become an interface nobody meant
// to define.
const (
	exitOK           = 0
	exitUsage        = 2
	exitAlready      = 3 // already enrolled; not an error if the caller is idempotent
	exitTokenRefused = 4 // get a fresh pairing token
	exitUnreachable  = 5 // network or service problem, worth retrying
	exitFailed       = 1
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}
	switch os.Args[1] {
	case "enroll":
		os.Exit(enrollCmd(os.Args[2:]))
	case "status":
		os.Exit(statusCmd(os.Args[2:]))
	case "version", "-version", "--version":
		fmt.Printf("cube-advisor-agent %s (%s)\n", version, commit)
		os.Exit(exitOK)
	default:
		usage()
		os.Exit(exitUsage)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `cube-advisor-agent %s

  enroll  -server <url> [-token <t> | -token-file <path> | -token-stdin]
  status
  version
`, version)
}

func enrollCmd(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	server := fs.String("server", "", "SaaS base URL, e.g. https://advisor.bigstack.co")
	cluster := fs.String("cluster", "", "cluster id (defaults to the hostname)")
	dir := fs.String("dir", identity.DefaultDir, "where the identity is stored")
	token := fs.String("token", "", "pairing token (visible in ps; prefer -token-file)")
	tokenFile := fs.String("token-file", "", "read the pairing token from a file")
	tokenStdin := fs.Bool("token-stdin", false, "read the pairing token from stdin")
	force := fs.Bool("force", false, "replace an existing identity")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *server == "" {
		fmt.Fprintln(os.Stderr, "enroll: -server is required")
		return exitUsage
	}
	if *cluster == "" {
		h, err := os.Hostname()
		if err != nil {
			fmt.Fprintln(os.Stderr, "enroll: cannot determine the hostname; pass -cluster")
			return exitUsage
		}
		*cluster = h
	}

	tok, err := readToken(*token, *tokenFile, *tokenStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enroll: %v\n", err)
		return exitUsage
	}

	// Re-enrolling invalidates the certificate the SaaS currently accepts, so
	// it is never a side effect of running the command twice.
	if identity.Exists(*dir) && !*force {
		fmt.Fprintf(os.Stderr,
			"enroll: %s is already enrolled (identity in %s); pass -force to replace it\n",
			*cluster, *dir)
		return exitAlready
	}
	if *force {
		if err := identity.Remove(*dir); err != nil {
			fmt.Fprintf(os.Stderr, "enroll: cannot replace the existing identity: %v\n", err)
			return exitFailed
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	e := &identity.Enroller{BaseURL: strings.TrimRight(*server, "/"), AgentVersion: version}
	id, err := e.EnrollAndSave(ctx, *dir, *cluster, tok)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enroll: %v\n", err)
		switch {
		case errors.Is(err, identity.ErrTokenRejected):
			return exitTokenRefused
		case strings.Contains(err.Error(), "unreachable"):
			return exitUnreachable
		}
		return exitFailed
	}

	fp, err := id.Fingerprint()
	if err != nil {
		fmt.Fprintf(os.Stderr, "enroll: enrolled but cannot read the fingerprint: %v\n", err)
		return exitFailed
	}
	// The fingerprint is printed because an operator compares it against the one
	// the SaaS shows. Enrollment is not finished until a human has done that.
	fmt.Printf("Enrolled %s\n", *cluster)
	fmt.Printf("Fingerprint: %s\n", fp)
	fmt.Printf("Compare this with the fingerprint shown by the Advisor before approving.\n")
	return exitOK
}

func statusCmd(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	dir := fs.String("dir", identity.DefaultDir, "where the identity is stored")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if !identity.Exists(*dir) {
		fmt.Printf("Not enrolled (no identity in %s)\n", *dir)
		return exitAlready
	}
	id, err := identity.Load(*dir)
	if err != nil {
		// A present but unloadable identity is worth distinguishing from an
		// absent one: it usually means the key's permissions were changed.
		fmt.Fprintf(os.Stderr, "status: identity present but unusable: %v\n", err)
		return exitFailed
	}
	fp, _ := id.Fingerprint()
	fmt.Printf("Enrolled as %s\n", id.ClusterID)
	fmt.Printf("Fingerprint: %s\n", fp)
	return exitOK
}

// readToken takes the token from exactly one source.
//
// The flag is kept for interactive use but is the worst option: a token on a
// command line is visible in ps to every user on the box for as long as the
// process runs. Installers should use a file or stdin.
func readToken(flagVal, file string, stdin bool) (string, error) {
	given := 0
	for _, on := range []bool{flagVal != "", file != "", stdin} {
		if on {
			given++
		}
	}
	switch {
	case given == 0:
		return "", errors.New("a pairing token is required (-token, -token-file or -token-stdin)")
	case given > 1:
		return "", errors.New("give the pairing token exactly once")
	}

	switch {
	case flagVal != "":
		return strings.TrimSpace(flagVal), nil
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("reading the token file: %w", err)
		}
		return trimmedNonEmpty(string(b))
	default:
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			return "", fmt.Errorf("reading the token from stdin: %w", err)
		}
		return trimmedNonEmpty(string(b))
	}
}

func trimmedNonEmpty(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("the pairing token is empty")
	}
	return s, nil
}
