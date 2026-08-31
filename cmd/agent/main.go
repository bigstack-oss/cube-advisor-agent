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
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
)

// defaultTunnelPort is the SaaS tunnel listener's chart default. It is what
// -tunnel derives from -server's host when the operator does not say
// otherwise; a SaaS whose tunnel listens elsewhere requires -tunnel explicitly.
const defaultTunnelPort = "8443"

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
	case "run":
		os.Exit(runCmd(os.Args[2:]))
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

  enroll  -server <url> [-token <t> | -token-file <path> | -token-stdin] [-tunnel <host:port>]
  run     [-server <host:port>] [-dir <path>] [-audit <path>]
  status
  version
`, version)
}

// deriveTunnelAddr computes the tunnel address run should persist-and-use when
// the operator did not pass -tunnel: serverURL's host, on defaultTunnelPort.
// That default is the SaaS chart's tunnel listener port, not the enrollment
// service's — the two can differ, which is exactly why -tunnel exists for an
// operator whose SaaS tunnel listens elsewhere.
func deriveTunnelAddr(serverURL string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("parsing -server to derive a tunnel address: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("-server %q has no host to derive a tunnel address from; pass -tunnel", serverURL)
	}
	return net.JoinHostPort(host, defaultTunnelPort), nil
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
	tunnel := fs.String("tunnel", "",
		"SaaS tunnel address to persist for `run`, host:port (default: -server's host on port "+defaultTunnelPort+")")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *server == "" {
		fmt.Fprintln(os.Stderr, "enroll: -server is required")
		return exitUsage
	}
	// An explicit -cluster always wins: the caller knows the cluster, and on a
	// CubeCOS node the enrolment wrapper passes it. The rest is for a
	// hand-started enrolment, where the driver's assigned id beats the
	// hostname — the hostname names one node, and a cluster outlives any of
	// them.
	if *cluster == "" {
		*cluster = clusterIDFromDriver()
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

	// Persist the tunnel address so `run` needs no operator argument
	// afterwards (bigstack-oss/cube-advisor-agent#19). This is a convenience
	// on top of an already-successful enrolment, not part of it: a failure
	// here is reported but does not undo the identity just saved, since an
	// operator can still pass -server to `run` explicitly.
	tunnelAddr := *tunnel
	if tunnelAddr == "" {
		tunnelAddr, err = deriveTunnelAddr(*server)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "enroll: enrolled, but could not determine a tunnel address to persist: %v\n", err)
		fmt.Fprintln(os.Stderr, "enroll: pass -server host:port to `run` explicitly, or -force -tunnel host:port to re-enroll")
	} else if err := identity.SaveServer(*dir, tunnelAddr); err != nil {
		fmt.Fprintf(os.Stderr, "enroll: enrolled, but could not persist the tunnel address: %v\n", err)
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
