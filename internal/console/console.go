// Package console serves the recorded console plane on the agent side: a
// console channel is piped to the node's own sshd and to nothing else.
//
// A channel may name another node of the cluster, one with no agent of its
// own (ADR 0021). It is still piped to this node's sshd: the Advisor's SSH
// session there runs the hop to the peer, as root over the cluster's
// node-to-node SSH. This side only checks the peer is on the cluster's node
// list and is not this node, and audits the open.
//
// Two kinds of channel arrive here, and both are served the same way: a
// person's interactive console, and an agent-driven one the SaaS opens to run
// one shell-tool command (ADR 0017), marked AgentDriven on the channel open.
// Since ADR 0019 the agent serves the marked channel at every action level:
// the SaaS grades the command, an admin approves it, and the session is
// recorded there, under a certificate whose key ID names the agent and the
// person.
//
// The agent never forks a PTY, never spawns a shell and never authenticates an
// end user (ADR 0002). It moves bytes between the tunnel and a local TCP
// connection, which is what keeps the node's own keys, PAM, sudo and audit
// authoritative — a shell this process spawned would answer to this process's
// privileges, not the operator's.
package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// LocalSSH is the only address a console channel can reach. Loopback, and
// literal: a relayed channel is piped here too, so there is no address to
// widen and no configuration that could widen it.
const LocalSSH = "127.0.0.1:22"

// dialTimeout bounds the connection to local sshd. Loopback either answers
// quickly or is not listening; a long wait here only delays telling the
// operator that SSH is off on this node.
const dialTimeout = 5 * time.Second

// ErrNotThisNode is returned when a channel names a node this agent is not.
//
// The caller must not pass this text to the SaaS: a probing SaaS learns the
// cluster's topology by watching which names come back differently. The
// distinction is for this node's own log.
var ErrNotThisNode = errors.New("console: target names another node")

// ErrRelayRefused is returned when a channel names a node that is not one of
// the cluster's other nodes, or relaying is off.
var ErrRelayRefused = errors.New("console: target is not a peer this node relays to")

// peerName is a node name as the cluster's node list holds it; it can never
// be read as an ssh option.
var peerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// ErrNoSSHD is returned when nothing is listening on the node's sshd port.
var ErrNoSSHD = errors.New("console: sshd is not accepting connections on this node")

// Dialer opens the local connection. Injected so tests can stand in a fake
// sshd without a listener on port 22.
type Dialer func(ctx context.Context, address string) (net.Conn, error)

func defaultDialer(ctx context.Context, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", address)
}

// Handler serves console channels for one node.
type Handler struct {
	// NodeID is this agent's own node. A target naming anything else is
	// refused — the check is here, on the node, and not only in the SaaS,
	// because the SaaS is never trusted to scope its own requests.
	NodeID string

	// Dial opens the local sshd connection; nil uses a real TCP dialler.
	Dial Dialer

	// Peers lists the cluster's nodes. Nil turns relaying off: a channel
	// naming another node is refused.
	Peers func(ctx context.Context) ([]string, error)

	// Audit records each relay open, allowed or refused. Nil records nothing.
	Audit func(node string, allowed bool, reason string)
}

// Relays reports whether this handler serves channels for other nodes.
func (h *Handler) Relays() bool { return h.Peers != nil }

// checkRelay allows target only if it is on the cluster's node list and is
// not this node.
func (h *Handler) checkRelay(ctx context.Context, target string) error {
	if h.Peers == nil {
		return fmt.Errorf("%w: %q", ErrNotThisNode, target)
	}
	if !peerName.MatchString(target) {
		return fmt.Errorf("%w: %q is not a node name", ErrRelayRefused, target)
	}
	self := strings.ToLower(h.NodeID)
	t := strings.ToLower(target)
	if t == self || t == strings.SplitN(self, ".", 2)[0] || strings.SplitN(t, ".", 2)[0] == self {
		return fmt.Errorf("%w: %q is this node", ErrRelayRefused, target)
	}
	nodes, err := h.Peers(ctx)
	if err != nil {
		return fmt.Errorf("%w: node list: %v", ErrRelayRefused, err)
	}
	for _, n := range nodes {
		if n == target {
			return nil
		}
	}
	return fmt.Errorf("%w: %q is not on the cluster's node list", ErrRelayRefused, target)
}

func (h *Handler) audit(node string, err error) {
	if h.Audit == nil {
		return
	}
	if err != nil {
		h.Audit(node, false, err.Error())
		return
	}
	h.Audit(node, true, "relayed through this node's sshd")
}

// Serve pipes rw to the node's local sshd until either side closes.
//
// target is the name the channel asked for: this node, checked by equality
// against the identity this agent enrolled with, or a peer on the cluster's
// node list when relaying is on (checkRelay).
func (h *Handler) Serve(ctx context.Context, target string, rw io.ReadWriter) error {
	if target == "" {
		return fmt.Errorf("%w: %q", ErrNotThisNode, target)
	}
	if target != h.NodeID {
		err := h.checkRelay(ctx, target)
		if h.Peers != nil {
			h.audit(target, err)
		}
		if err != nil {
			return err
		}
	}

	dial := h.Dial
	if dial == nil {
		dial = defaultDialer
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := dial(dialCtx, LocalSSH)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoSSHD, err)
	}
	defer conn.Close()

	return pipe(ctx, rw, conn)
}

// pipe copies both directions and returns when either finishes.
//
// One direction ending is a normal end of session — the user typed exit, or
// the channel closed — so the first completion wins and the other copy is
// unblocked by closing the connection. Copy errors after that point are the
// consequence of the close, not the cause, and are not reported.
func pipe(ctx context.Context, remote io.ReadWriter, local net.Conn) error {
	done := make(chan error, 2)
	var once sync.Once
	stop := func() { once.Do(func() { _ = local.Close() }) }

	go func() {
		_, err := io.Copy(local, remote)
		done <- err
		stop()
	}()
	go func() {
		_, err := io.Copy(remote, local)
		done <- err
		stop()
	}()

	select {
	case err := <-done:
		stop()
		if err != nil && !isClosed(err) {
			return err
		}
		return nil
	case <-ctx.Done():
		stop()
		return ctx.Err()
	}
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF)
}
