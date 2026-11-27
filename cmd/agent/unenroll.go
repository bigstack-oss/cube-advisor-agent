package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnel"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// defaultUnenrollReason is what the Advisor records when the caller says
// nothing else.
const defaultUnenrollReason = "the customer cut this cluster off"

// unenrollCmd tells the Advisor the customer cut this cluster off, then exits.
//
// Best effort: it deletes nothing and stops nothing — CubeCOS does both, and
// carries on whatever this returns.
func unenrollCmd(args []string) int {
	fs := flag.NewFlagSet("unenroll", flag.ContinueOnError)
	addr := fs.String("server", "",
		"Advisor tunnel address, host:port (default: the address enrolment persisted)")
	dir := fs.String("dir", identity.DefaultDir, "where the identity is stored")
	timeout := fs.Duration("timeout", 10*time.Second, "give up telling the Advisor after this long")
	reason := fs.String("reason", defaultUnenrollReason, "what the Advisor records as the reason")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "unenroll: -timeout must be positive")
		return exitUsage
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := tellAdvisorCutOff(ctx, *addr, *dir, *reason); err != nil {
		fmt.Fprintf(os.Stderr, "unenroll: the Advisor could not be told this cluster was cut off: %v\n", err)
		return exitNotTold
	}
	fmt.Println("unenroll: told the Advisor this cluster was cut off")
	return exitOK
}

// tellAdvisorCutOff dials the Advisor as run does — same identity, same
// egress proxy — and sends one KillSwitch on the control stream.
func tellAdvisorCutOff(ctx context.Context, addr, dir, reason string) error {
	serverAddr, err := resolveServerAddr(addr, dir)
	if err != nil {
		return err
	}
	id, err := identity.Load(dir)
	if err != nil {
		return fmt.Errorf("no usable identity in %s: %w", dir, err)
	}
	fp, err := id.Fingerprint()
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return fmt.Errorf("the tunnel address must be host:port: %w", err)
	}
	tlsCfg, err := id.TLSConfig(host)
	if err != nil {
		return err
	}
	proxy, _ := egressProxy(dir, &neturl.URL{Scheme: "https", Host: serverAddr}, http.ProxyFromEnvironment)

	conn, err := tunnel.DialWS(ctx, "wss://"+serverAddr+tunnel.WSPath, nil, tunnel.NewTLSClientVia(tlsCfg, proxy))
	if err != nil {
		return err
	}
	sess, err := tunnel.Dial(ctx, conn, helloFor(id.ClusterID, fp))
	if err != nil {
		_ = conn.Close()
		return err
	}
	err = sendKillSwitch(ctx, sess, reason)
	closeWithin(ctx, sess)
	return err
}

// sendKillSwitch sends the message and waits for it to reach the Advisor, or
// for ctx to end.
func sendKillSwitch(ctx context.Context, sess *tunnel.Session, reason string) error {
	sent := make(chan error, 1)
	go func() {
		err := sess.SendKillSwitch(tunnelproto.KillSwitch{Reason: reason})
		if err == nil {
			// One round trip: the Advisor's side has read past the message.
			// It may hang up instead, which is the answer asked for.
			_, _ = sess.Ping()
		}
		sent <- err
	}()
	select {
	case err := <-sent:
		return err
	case <-ctx.Done():
		return fmt.Errorf("gave up waiting: %w", ctx.Err())
	}
}

// closeWithin closes the session without outliving ctx.
func closeWithin(ctx context.Context, sess *tunnel.Session) {
	closed := make(chan struct{})
	go func() {
		_ = sess.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-ctx.Done():
	}
}
