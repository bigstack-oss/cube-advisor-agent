package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/bigstack-oss/cube-advisor-agent/internal/agent"
	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
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
	addr := fs.String("server", "", "SaaS tunnel address, host:port")
	dir := fs.String("dir", identity.DefaultDir, "where the identity is stored")
	auditPath := fs.String("audit", "/var/log/cube-advisor-agent/toolcalls.log",
		"append-only audit log of every tool call served")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *addr == "" {
		fmt.Fprintln(os.Stderr, "run: -server is required")
		return exitUsage
	}

	id, err := identity.Load(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: no usable identity in %s (enroll first): %v\n", *dir, err)
		return exitFailed
	}
	fp, err := id.Fingerprint()
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return exitFailed
	}
	host, _, err := net.SplitHostPort(*addr)
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
	reg, err := toolplane.New(toolplane.Allowlist, auditor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return exitFailed
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hello := tunnelproto.Hello{
		ClusterID:       id.ClusterID,
		Fingerprint:     fp,
		AgentVersion:    version,
		ProtocolVersion: tunnelproto.Version,
	}
	url := "wss://" + *addr + tunnel.WSPath
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

	srv := &agent.Server{Tools: reg}
	backoff := tunnel.DefaultBackoff()
	log.Printf("agent %s: serving %d tools for %s via %s",
		version, len(reg.Names()), id.ClusterID, *addr)

	// Serve until told to stop. Each session ending — network flap, SaaS
	// restart, supersession by a newer agent — is a reason to reconnect, not
	// to exit: an air-gapped operator is not watching this process.
	for ctx.Err() == nil {
		sess, err := backoff.Reconnect(ctx, connect, nil)
		if err != nil {
			break // only a cancelled context ends Reconnect
		}
		log.Printf("agent: connected to %s", *addr)
		if err := srv.Serve(ctx, sess); err != nil {
			log.Printf("agent: session ended: %v", err)
		}
		_ = sess.Close()
	}
	log.Printf("agent: stopping")
	return exitOK
}
