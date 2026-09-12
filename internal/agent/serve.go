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
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/console"
	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnel"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// Server serves channels for one session.
type Server struct {
	Tools *toolplane.Registry

	// Console serves the human plane. Nil refuses every console channel,
	// which is the right default: an agent with no node identity configured
	// must not guess which node it is.
	Console *console.Handler

	// Web serves web channels. Nil refuses them, which is the default: a node
	// exposes no web target until one is configured.
	Web *console.WebHandler

	// CallTimeout bounds one tool call end to end. Zero uses the default.
	CallTimeout time.Duration
}

// defaultCallTimeout is one rung of the timeout ladder: it must sit above the
// largest tool timeout in the registry (so the tool's own timeout fires first
// and the model gets an honest "tool timed out" result, not a dead channel)
// and below the SaaS's channel deadline (120s), for the same reason one level
// up. Today: tools ≤100s < this 110s < SaaS 120s.
const defaultCallTimeout = 110 * time.Second

// maxConsecutiveAcceptErrors ends the session once channel-open keeps failing;
// cmd/agent then reconnects with backoff.
const maxConsecutiveAcceptErrors = 10

// acceptErrorPause keeps a burst of rejects off the CPU.
const acceptErrorPause = 200 * time.Millisecond

// Serve accepts channels until the session ends or ctx is cancelled.
//
// Each channel is handled in its own goroutine: a tool that hangs must not
// stall the accept loop, or one slow call would block every other channel on
// the connection — including the console channels a human is waiting on.
func (s *Server) Serve(ctx context.Context, sess *tunnel.Session) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	var consecutive int
	for {
		ch, err := sess.AcceptChannel(ctx)
		if err != nil {
			if isSessionOver(err) || ctx.Err() != nil {
				return nil
			}
			// One bad open is not fatal — log it and keep serving. Pause, and
			// give up once it stops looking like one bad open.
			consecutive++
			log.Printf("agent: rejecting channel (%d/%d): %v",
				consecutive, maxConsecutiveAcceptErrors, err)
			if consecutive >= maxConsecutiveAcceptErrors {
				return fmt.Errorf("agent: %d consecutive channel-open failures: %w", consecutive, err)
			}
			if tunnel.Sleep(ctx, acceptErrorPause) != nil {
				return nil
			}
			continue
		}
		consecutive = 0
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
	case tunnelproto.ChannelConsole:
		s.serveConsole(ctx, ch)
	default:
		log.Printf("agent: refusing a %s channel", ch.Open.Kind)
		_ = writeResult(ch, tunnelproto.ToolResult{OK: false, Error: tunnelproto.RefusedReason})
	}
}

// serveConsole pipes a console channel to this node's sshd or an allowlisted web endpoint.
//
// Every refusal returns the same generic reason. The distinctions — wrong
// node, no sshd, console not configured — are logged here, on the node, and
// never sent: a SaaS that could tell them apart could map the cluster by
// asking for names and watching which answer differently.
func (s *Server) serveConsole(ctx context.Context, ch *tunnel.Channel) {
	switch ch.Open.Target.Kind {
	case tunnelproto.TargetSSH:
		s.serveSSHConsole(ctx, ch)
	case tunnelproto.TargetWeb:
		s.serveWebConsole(ctx, ch)
	default:
		log.Printf("agent: console channel refused, target kind %q", ch.Open.Target.Kind)
		_ = writeResult(ch, tunnelproto.ToolResult{OK: false, Error: tunnelproto.RefusedReason})
	}
}

func (s *Server) serveSSHConsole(ctx context.Context, ch *tunnel.Channel) {
	if s.Console == nil {
		log.Printf("agent: console channel refused, no console handler configured")
		_ = writeResult(ch, tunnelproto.ToolResult{OK: false, Error: tunnelproto.RefusedReason})
		return
	}
	if err := s.Console.Serve(ctx, ch.Open.Target.Name, ch); err != nil {
		log.Printf("agent: console channel for %q ended: %v", ch.Open.Target.Name, err)
	}
}

func (s *Server) serveWebConsole(ctx context.Context, ch *tunnel.Channel) {
	if s.Web == nil {
		log.Printf("agent: web channel refused, no web targets configured")
		_ = writeResult(ch, tunnelproto.ToolResult{OK: false, Error: tunnelproto.RefusedReason})
		return
	}
	if err := s.Web.Serve(ctx, ch.Open.Target.Name, ch); err != nil {
		log.Printf("agent: web channel for %q ended: %v", ch.Open.Target.Name, err)
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

	// Approved comes from the open frame the protocol already validated, for
	// the reason the tool name does: one source of truth per fact, and it is
	// the one that was checked.
	out, err := s.Tools.Call(ctx, name, args, ch.Open.Approved)
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
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	// A dead transport arrives on the same path as a refused channel-open, but
	// means the session is gone rather than one channel.
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	// yamux reports its own shutdown as a plain error value.
	return strings.Contains(err.Error(), "session shutdown") ||
		strings.Contains(err.Error(), "use of closed")
}
