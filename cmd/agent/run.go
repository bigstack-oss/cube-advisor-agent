package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/agent"
	"github.com/bigstack-oss/cube-advisor-agent/internal/console"
	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
	"github.com/bigstack-oss/cube-advisor-agent/internal/openstack"
	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnel"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// runCmd connects to the SaaS and serves the tool plane, forever.
//
// The connection is outbound-only wss over mTLS: the identity enrollment
// issued is the client certificate, and the SaaS's tunnel endpoint must
// present a certificate chaining to the same enrollment CA — the agent trusts
// nothing else, and there is no flag to loosen that. Websocket framing is what
// lets the single outbound connection traverse egress proxies that only pass
// HTTPS.
func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	addr := fs.String("server", "",
		"SaaS tunnel address, host:port (default: the address enrolment persisted)")
	dir := fs.String("dir", identity.DefaultDir, "where the identity is stored")
	auditPath := fs.String("audit", "/var/log/cube-advisor-agent/toolcalls.log",
		"append-only audit log of every tool call served")
	probes := fs.Bool("probes", false,
		"serve the probe plane: bounded measurements that create and delete their own scratch storage")
	webTargets := fs.String("web-targets", "/etc/cube-advisor-agent/web-targets.json",
		"JSON map of symbolic web target names to host:port this node may proxy; absent means none")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	serverAddr, err := resolveServerAddr(*addr, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return exitUsage
	}

	id, err := identity.Load(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: no usable identity in %s (enroll first): %v\n", *dir, err)
		return exitFailed
	}
	webAllow, err := console.LoadWebAllowlist(*webTargets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return exitFailed
	}
	fp, err := id.Fingerprint()
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return exitFailed
	}
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: -server must be host:port: %v\n", err)
		return exitUsage
	}
	tlsCfg, err := id.TLSConfig(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return exitFailed
	}

	auditor, err := toolplane.NewFileAuditor(*auditPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: audit log: %v\n", err)
		return exitFailed
	}
	var opts []toolplane.Option
	var probeRunner *toolplane.ProbeRunner
	if *probes {
		probeRunner, err = toolplane.NewProbeRunner(toolplane.Probes, auditor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "run: %v\n", err)
			return exitFailed
		}
		opts = append(opts, toolplane.WithProbes(probeRunner))
	}
	// The cluster's own action level (ADR 0011), read once here so a malformed
	// value is one loud line at startup rather than a mystery repeated per
	// call. A missing or empty file is not an error and means observe; a word
	// that is not a level is an error, and the agent still starts — at observe,
	// serving reads — because refusing to run would take diagnosis away from
	// the operator at exactly the moment they need it.
	level, err := toolplane.ReadLevel(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v; serving %s until it is corrected\n", err, level)
	}
	opts = append(opts, toolplane.WithLevel(level))

	reg, err := toolplane.New(toolplane.Allowlist, auditor, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return exitFailed
	}

	// The OpenStack credential, if the operator has written one. Absent is the
	// ordinary state and not an error: an agent with no credential serves
	// every read it always did and refuses a create with a message naming the
	// missing configuration — which is a different refusal from the action
	// level's, and says so.
	//
	// Wired only when present, so opting in is writing a file, and nothing
	// about an existing deployment changes until someone does.
	switch cred, err := openstack.ReadCredential(*dir); {
	case errors.Is(err, openstack.ErrNoCredential):
		// Said once, at startup, because "why did it refuse" is a question
		// better answered before it is asked.
		fmt.Fprintf(os.Stderr, "run: no OpenStack credential; creates will refuse until one is configured\n")
	case err != nil:
		// Loud, and still starts: a malformed credential must not take
		// diagnosis away from the operator at the moment they need it, which
		// is the same argument the action level makes.
		fmt.Fprintf(os.Stderr, "run: %v; creates will refuse until it is corrected\n", err)
	default:
		compute, cerr := openstack.NewCompute(cred)
		if cerr != nil {
			fmt.Fprintf(os.Stderr, "run: %v; creates will refuse until it is corrected\n", cerr)
			break
		}
		reg.ConfigureWriter(toolplane.BackendOpenStackCompute, compute)
		fmt.Fprintf(os.Stderr, "run: OpenStack credential loaded for project %s\n", cred.Project)
	}
	// Stated at startup, because "what may this assistant do here" is the
	// question an operator asks of a log and should not have to infer.
	fmt.Fprintf(os.Stderr, "run: action level %s; serving %d tool(s)\n", level, len(reg.Names()))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if probeRunner != nil {
		// Sweep before serving. Scratch left by a process that was killed
		// mid-probe outlives it, and this is the only thing that ever notices:
		// the deferred cleanup died with the process that owed it.
		go probeRunner.RunSweeper(ctx)
	}

	hello := tunnelproto.Hello{
		ClusterID:       id.ClusterID,
		Fingerprint:     fp,
		AgentVersion:    version,
		ProtocolVersion: tunnelproto.Version,
	}
	url := "wss://" + serverAddr + tunnel.WSPath
	httpClient := tunnel.NewTLSClient(tlsCfg)
	connect := func(ctx context.Context) (*tunnel.Session, error) {
		conn, err := tunnel.DialWS(ctx, url, nil, httpClient)
		if err != nil {
			return nil, err
		}
		sess, err := tunnel.Dial(ctx, conn, hello)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return sess, nil
	}

	// The console handler is constructed from the identity the agent enrolled
	// with, never from anything the SaaS sends: the node this agent is is a
	// fact about this process, and a node id the caller could influence is a
	// node id a compromised SaaS could pick.
	srv := &agent.Server{
		Tools:   reg,
		Console: &console.Handler{NodeID: id.NodeID},
		Web:     &console.WebHandler{Allow: webAllow},
	}
	backoff := tunnel.DefaultBackoff()
	guard := tunnel.DefaultFlapGuard()
	log.Printf("agent %s: serving %d tools, a console and %d web targets for %s/%s via %s",
		version, len(reg.Names()), len(webAllow), id.ClusterID, id.NodeID, serverAddr)

	// Serve until told to stop. Each session ending — network flap, SaaS
	// restart, supersession by a newer agent — is a reason to reconnect, not
	// to exit: an air-gapped operator is not watching this process.
	//
	// The guard is what keeps two agents sharing one identity from fighting at
	// reconnect speed: connect succeeds instantly, the SaaS supersedes the
	// other's session, it reconnects and supersedes ours, forever. Sessions
	// that die young back off hard; sessions that live cost nothing.
	for ctx.Err() == nil {
		sess, err := backoff.Reconnect(ctx, connect, nil)
		if err != nil {
			break // only a cancelled context ends Reconnect
		}
		log.Printf("agent: connected to %s", serverAddr)
		started := time.Now()
		if err := srv.Serve(ctx, sess); err != nil {
			log.Printf("agent: session ended: %v", err)
		}
		_ = sess.Close()
		if d := guard.SessionEnded(time.Since(started)); d > 0 {
			log.Printf("agent: session died young — waiting %s before reconnecting (another agent may hold this identity)",
				d.Round(time.Second))
			if tunnel.Sleep(ctx, d) != nil {
				break
			}
		}
	}
	log.Printf("agent: stopping")
	return exitOK
}

// resolveServerAddr picks the tunnel address to dial: an explicit -server
// always wins (bigstack-oss/cube-advisor-agent#19's whole point is that an
// operator need not pass it, not that they cannot), otherwise the address
// enrolment persisted. Neither present is a distinct, actionable refusal
// rather than a confusing dial failure against an empty address.
func resolveServerAddr(explicit, dir string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	persisted, err := identity.LoadServer(dir)
	if err != nil {
		return "", fmt.Errorf("reading the persisted tunnel address: %w", err)
	}
	if persisted == "" {
		return "", fmt.Errorf("no tunnel address: enrol first, or pass -server host:port")
	}
	return persisted, nil
}
