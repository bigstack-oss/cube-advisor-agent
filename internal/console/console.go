// Package console serves the human plane on the agent side: a console channel
// is piped to the node's own sshd and to nothing else.
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
	"sync"
	"time"
)

// LocalSSH is the only address a console channel can reach. Loopback, and
// literal: with one agent per node there is no cross-node dialling to permit,
// so there is no allowlist to widen and no configuration that could widen it.
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
}

// Serve pipes rw to the node's local sshd until either side closes.
//
// target is the name the channel asked for. It must be this node: the check is
// an equality against the identity this agent enrolled with, so a compromised
// SaaS cannot reach a neighbour by asking politely.
func (h *Handler) Serve(ctx context.Context, target string, rw io.ReadWriter) error {
	if target == "" || target != h.NodeID {
		return fmt.Errorf("%w: %q", ErrNotThisNode, target)
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
