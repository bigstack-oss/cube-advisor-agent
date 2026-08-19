// Package agent joins the tunnel to the tool plane: it accepts channels the
// SaaS opens and serves the ones it is willing to serve.
//
// This is where the pieces meet, and where the claim they exist to support has
// to hold — that a compromised or prompt-injected SaaS can at worst read health
// and logs. The protocol makes an address unrepresentable, the allowlist makes
// an unanticipated command unreachable, and this package must not quietly
// become the place either stops being true.
package agent

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnel"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// Server serves channels for one session.
type Server struct {
	Tools *toolplane.Registry

	// CallTimeout bounds one tool call end to end. Zero uses the default.
	CallTimeout time.Duration
}

const defaultCallTimeout = 90 * time.Second

// Serve accepts channels until the session ends or ctx is cancelled.
//
// Each channel is handled in its own goroutine: a tool that hangs must not
// stall the accept loop, or one slow call would block every other channel on
// the connection — including the console channels a human is waiting on.
func (s *Server) Serve(ctx context.Context, sess *tunnel.Session) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		ch, err := sess.AcceptChannel(ctx)
		if err != nil {
			if isSessionOver(err) || ctx.Err() != nil {
				return nil
			}
			// A malformed or refused channel-open is not fatal to the session:
			// the peer may simply be a version we partly disagree with. Log it
			// and keep serving.
			log.Printf("agent: rejecting channel: %v", err)
			continue
		}
		wg.Add(1)
		go func(ch *tunnel.Channel) {
			defer wg.Done()
			s.handle(ctx, ch)
		}(ch)
	}
}

// handle serves one channel, whatever happens inside it.
func (s *Server) handle(ctx context.Context, ch *tunnel.Channel) {
	defer ch.Close()

	// A handler panic must not take the agent down. The agent is the
	// customer's only path to support; losing it to one malformed tool call is
	// a worse outcome than failing that call.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("agent: handler panicked on %s: %v", ch.Open.Target, r)
			_ = writeResult(ch, tunnelproto.ToolResult{OK: false, Error: tunnelproto.RefusedReason})
		}
	}()

	switch ch.Open.Kind {
	case tunnelproto.ChannelTool:
		s.serveTool(ctx, ch)
	default:
		// Console channels are not served here. The protocol already prevents a
		// tool channel from naming a console target; this refuses the converse
		// so the tool handler can never grow into a console one by accident.
		log.Printf("agent: tool handler refusing a %s channel", ch.Open.Kind)
		_ = writeResult(ch, tunnelproto.ToolResult{OK: false, Error: tunnelproto.RefusedReason})
	}
}

func (s *Server) serveTool(ctx context.Context, ch *tunnel.Channel) {
	// The tool name comes from the target the protocol already validated —
	// never from a body field the SaaS could disagree with itself about. One
	// source of truth for "which tool", and it is the one that was checked.
	if ch.Open.Target.Kind != tunnelproto.TargetTool {
		_ = writeResult(ch, tunnelproto.ToolResult{OK: false, Error: tunnelproto.RefusedReason})
		return
	}
	name := ch.Open.Target.Name

	args, err := readArgs(ch)
	if err != nil {
		log.Printf("agent: %s: bad arguments: %v", name, err)
		_ = writeResult(ch, tunnelproto.ToolResult{OK: false, Error: tunnelproto.RefusedReason})
		return
	}

	timeout := s.CallTimeout
	if timeout <= 0 {
		timeout = defaultCallTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out, err := s.Tools.Call(ctx, name, args)
	if err != nil {
		// Refusals and failures are reported the same way on the wire. The
		// distinction — and the reason — is in the local audit log, which the
		// customer reads and the SaaS does not.
		log.Printf("agent: %s failed: %v", name, err)
		_ = writeResult(ch, tunnelproto.ToolResult{OK: false, Error: tunnelproto.RefusedReason})
		return
	}
	_ = writeResult(ch, tunnelproto.ToolResult{OK: true, Output: string(out)})
}

// readArgs reads the argument frame. The framing itself is the protocol's
// (pkg/tunnelproto), so both sides of the wire share one implementation.
func readArgs(r io.Reader) (map[string]string, error) {
	return tunnelproto.ReadToolArgs(r)
}

func writeResult(w io.Writer, r tunnelproto.ToolResult) error {
	return tunnelproto.WriteToolResult(w, r)
}

// isSessionOver reports whether an accept error means the tunnel has gone,
// rather than one channel being unacceptable.
func isSessionOver(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	// yamux reports its own shutdown as a plain error value.
	return strings.Contains(err.Error(), "session shutdown") ||
		strings.Contains(err.Error(), "use of closed")
}
