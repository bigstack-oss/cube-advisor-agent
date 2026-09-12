package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/console"
	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnel"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// These drive a real tunnel.Session rather than calling the registry directly,
// so the protocol, the transport and the allowlist are exercised together —
// which is the only way the end-to-end claim is actually tested.

type recorder struct {
	mu    sync.Mutex
	calls []toolplane.ToolCall
}

func (r *recorder) RecordToolCall(c toolplane.ToolCall) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c)
}

func (r *recorder) snapshot() []toolplane.ToolCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]toolplane.ToolCall(nil), r.calls...)
}

// harness stands up an agent serving one end of a real session, and returns
// the SaaS end plus the audit recorder.
//
// The tool executor is stubbed so the suite is hermetic — nothing shells out —
// but everything between the SaaS's channel-open and the registry's argv
// resolution is the production path.
func harness(t *testing.T) (*tunnel.Session, *recorder) {
	t.Helper()
	return harnessWithConsole(t, nil)
}

// harnessWithConsole is harness plus a console handler, for the human plane.
func harnessWithConsole(t *testing.T, con *console.Handler) (*tunnel.Session, *recorder) {
	t.Helper()
	return harnessFull(t, con, nil)
}

// harnessWith is harness plus a hook that configures the registry — the action
// level, the consent dial, a wired writer — for tests about what a configured
// cluster serves rather than about the transport.
func harnessWith(t *testing.T, configure func(*toolplane.Registry)) (*tunnel.Session, *recorder) {
	t.Helper()
	return harnessFull(t, nil, configure)
}

func harnessFull(t *testing.T, con *console.Handler, configure func(*toolplane.Registry)) (*tunnel.Session, *recorder) {
	t.Helper()
	rec := &recorder{}
	reg, err := toolplane.New(toolplane.Allowlist, rec)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if configure != nil {
		configure(reg)
	}
	reg.SetRunnerForTest(func(ctx context.Context, argv []string, max int) ([]byte, error) {
		return []byte("ran: " + strings.Join(argv, " ")), nil
	})

	a, b := connPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	type res struct {
		s   *tunnel.Session
		err error
	}
	saasCh := make(chan res, 1)
	go func() {
		s, err := tunnel.Accept(ctx, b, tunnelproto.Negotiate)
		saasCh <- res{s, err}
	}()

	agentSess, err := tunnel.Dial(ctx, a, tunnelproto.Hello{
		ClusterID: "acme-prod-01", Fingerprint: "SHA256:abc",
		AgentVersion: "0.1.0", ProtocolVersion: tunnelproto.Version,
	})
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	r := <-saasCh
	if r.err != nil {
		t.Fatalf("saas accept: %v", r.err)
	}

	srv := &Server{Tools: reg, Console: con, CallTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ctx, agentSess) }()

	t.Cleanup(func() { agentSess.Close(); r.s.Close() })
	return r.s, rec
}

func connPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	acc := make(chan res, 1)
	go func() { c, err := ln.Accept(); acc <- res{c, err} }()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-acc
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { client.Close(); r.c.Close() })
	return client, r.c
}

// callTool does what the SaaS does: open a tool channel, send arguments, read
// the result.
func callTool(t *testing.T, saas *tunnel.Session, id uint32, name string, args map[string]string) tunnelproto.ToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := saas.OpenChannel(ctx, id, tunnelproto.ChannelTool,
		tunnelproto.Target{Kind: tunnelproto.TargetTool, Name: name})
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	// Always exactly one argument line — `{}` when the tool takes none. yamux
	// streams have no half-close, so the frame must be self-delimiting.
	if args == nil {
		args = map[string]string{}
	}
	if err := json.NewEncoder(conn).Encode(args); err != nil {
		t.Fatalf("send args: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var res tunnelproto.ToolResult
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		t.Fatalf("read result for %s: %v", name, err)
	}
	return res
}

// The whole chain: the SaaS asks, the protocol carries it, the allowlist
// permits it, the agent runs it, the output comes back, the audit records it.
func TestToolCallEndToEnd(t *testing.T) {
	saas, rec := harness(t)

	res := callTool(t, saas, 1, "cluster_check", nil)
	if !res.OK {
		t.Fatalf("call failed: %+v", res)
	}
	if !strings.Contains(res.Output, "hex_cli -c cluster -c check") {
		t.Errorf("output = %q", res.Output)
	}

	calls := rec.snapshot()
	if len(calls) != 1 || !calls[0].Allowed || calls[0].Tool != "cluster_check" {
		t.Fatalf("audit = %+v", calls)
	}
}

func TestToolCallWithPermittedArgument(t *testing.T) {
	saas, _ := harness(t)
	res := callTool(t, saas, 1, "cluster_health", map[string]string{"{group}": "Storage"})
	if !res.OK {
		t.Fatalf("call failed: %+v", res)
	}
	if !strings.HasSuffix(strings.TrimSpace(res.Output), "health Storage") {
		t.Errorf("output = %q", res.Output)
	}
}

// The refusal path, end to end — and the SaaS learns only that it was refused.
func TestRefusalsAreOpaqueToTheSaaSButDetailedLocally(t *testing.T) {
	saas, rec := harness(t)

	unknown := callTool(t, saas, 1, "run_anything", nil)
	badArg := callTool(t, saas, 2, "cluster_health", map[string]string{"{group}": "Storage; rm -rf /"})

	for _, r := range []tunnelproto.ToolResult{unknown, badArg} {
		if r.OK {
			t.Errorf("a refused call reported success: %+v", r)
		}
		if r.Error != tunnelproto.RefusedReason {
			t.Errorf("refusal leaked detail to the SaaS: %q", r.Error)
		}
	}

	// The reason a customer needs is in their own log, and it is specific.
	calls := rec.snapshot()
	if len(calls) != 2 {
		t.Fatalf("audited %d calls, want 2", len(calls))
	}
	for _, c := range calls {
		if c.Allowed {
			t.Errorf("a refused call was audited as allowed: %+v", c)
		}
		if c.Reason == "" {
			t.Error("the local audit must say why, even though the SaaS is not told")
		}
	}
}

// A tool channel naming a console target must not be servable. The protocol
// already refuses it; this proves the handler does not quietly re-open the door.
func TestToolChannelCannotNameAConsoleTarget(t *testing.T) {
	saas, rec := harness(t)
	ctx := context.Background()

	_, err := saas.OpenChannel(ctx, 1, tunnelproto.ChannelTool,
		tunnelproto.Target{Kind: tunnelproto.TargetSSH, Name: "sky141"})
	if err == nil {
		t.Fatal("a tool channel targeting ssh was opened")
	}
	if len(rec.snapshot()) != 0 {
		t.Error("a refused channel reached the tool registry")
	}
}

// One hung call must not stall the accept loop or other channels — otherwise a
// single slow tool blocks every console session on the same connection.
func TestASlowCallDoesNotStallOtherChannels(t *testing.T) {
	rec := &recorder{}
	reg, err := toolplane.New(toolplane.Allowlist, rec)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	reg.SetRunnerForTest(func(ctx context.Context, argv []string, max int) ([]byte, error) {
		if strings.Contains(strings.Join(argv, " "), "journalctl") {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []byte("done"), nil
	})

	a, b := connPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	saasCh := make(chan *tunnel.Session, 1)
	go func() {
		s, err := tunnel.Accept(ctx, b, tunnelproto.Negotiate)
		if err != nil {
			saasCh <- nil
			return
		}
		saasCh <- s
	}()
	agentSess, err := tunnel.Dial(ctx, a, tunnelproto.Hello{
		ClusterID: "c", Fingerprint: "f", AgentVersion: "0.1.0",
		ProtocolVersion: tunnelproto.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	saas := <-saasCh
	if saas == nil {
		t.Fatal("no saas session")
	}
	defer func() { agentSess.Close(); saas.Close() }()

	srv := &Server{Tools: reg, CallTimeout: 15 * time.Second}
	go func() { _ = srv.Serve(ctx, agentSess) }()

	// Start the slow call and leave it hanging.
	slow, err := saas.OpenChannel(ctx, 1, tunnelproto.ChannelTool,
		tunnelproto.Target{Kind: tunnelproto.TargetTool, Name: "service_log_tail"})
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewEncoder(slow).Encode(map[string]string{"{unit}": "keystone", "{lines}": "50"})

	// A second call must complete while the first is still stuck.
	done := make(chan tunnelproto.ToolResult, 1)
	go func() { done <- callTool(t, saas, 2, "cluster_check", nil) }()

	select {
	case res := <-done:
		if !res.OK {
			t.Errorf("the second call failed while the first hung: %+v", res)
		}
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("a hung tool call stalled the serve loop")
	}
	close(release)
}

// The session ending is not an error the agent should log as one.
func TestServeReturnsCleanlyWhenTheSessionEnds(t *testing.T) {
	rec := &recorder{}
	reg, err := toolplane.New(toolplane.Allowlist, rec)
	if err != nil {
		t.Fatal(err)
	}
	a, b := connPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	saasCh := make(chan *tunnel.Session, 1)
	go func() {
		s, _ := tunnel.Accept(ctx, b, tunnelproto.Negotiate)
		saasCh <- s
	}()
	agentSess, err := tunnel.Dial(ctx, a, tunnelproto.Hello{
		ClusterID: "c", Fingerprint: "f", AgentVersion: "0.1.0",
		ProtocolVersion: tunnelproto.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	saas := <-saasCh

	srv := &Server{Tools: reg}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx, agentSess) }()

	saas.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Serve returned %v on a normal session end", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the session ended")
	}
}

func TestReadArgsRejectsAnOversizedFrame(t *testing.T) {
	big := strings.Repeat("a", tunnelproto.MaxToolArgsBytes+10) + "\n"
	if _, err := readArgs(strings.NewReader(big)); err == nil {
		t.Error("an oversized argument frame was accepted")
	}
	if _, err := readArgs(strings.NewReader("\n")); err != nil {
		t.Errorf("an empty frame should mean no arguments: %v", err)
	}
	got, err := readArgs(strings.NewReader(`{"{group}":"Storage"}` + "\n"))
	if err != nil || got["{group}"] != "Storage" {
		t.Errorf("readArgs = %v, %v", got, err)
	}
}

// The 147 GB incident: a peer reset arrived through AcceptChannel, isSessionOver
// did not recognise it, and the accept loop treated a dead transport as one bad
// channel — logging and retrying with no pause and no bound until the node's
// root filesystem was full.
func TestATransportResetEndsTheSession(t *testing.T) {
	cases := []struct {
		name string
		err  error
		over bool
	}{
		{"peer reset", &net.OpError{Op: "read", Net: "tcp",
			Err: os.NewSyscallError("read", syscall.ECONNRESET)}, true},
		{"broken pipe", &net.OpError{Op: "write", Net: "tcp",
			Err: os.NewSyscallError("write", syscall.EPIPE)}, true},
		{"wrapped reset", fmt.Errorf("failed to get reader: failed to read frame header: %w",
			&net.OpError{Op: "read", Net: "tcp",
				Err: os.NewSyscallError("read", syscall.ECONNRESET)}), true},
		{"unexpected eof", io.ErrUnexpectedEOF, true},
		{"eof", io.EOF, true},
		{"a merely invalid open", errors.New("tunnel: rejecting channel open from peer: bad target"), false},
	}
	for _, c := range cases {
		if got := isSessionOver(c.err); got != c.over {
			t.Errorf("%s: isSessionOver = %v, want %v", c.name, got, c.over)
		}
	}
}

// Serve must return when the transport dies under it, so cmd/agent can
// reconnect with backoff. Before the fix this spun forever.
func TestServeReturnsWhenThePeerResetsTheConnection(t *testing.T) {
	rec := &recorder{}
	reg, err := toolplane.New(toolplane.Allowlist, rec)
	if err != nil {
		t.Fatal(err)
	}
	a, b := connPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	saasCh := make(chan *tunnel.Session, 1)
	go func() {
		s, _ := tunnel.Accept(ctx, b, tunnelproto.Negotiate)
		saasCh <- s
	}()
	agentSess, err := tunnel.Dial(ctx, a, tunnelproto.Hello{
		ClusterID: "c", Fingerprint: "f", AgentVersion: "0.1.0",
		ProtocolVersion: tunnelproto.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	<-saasCh

	srv := &Server{Tools: reg}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx, agentSess) }()

	// SO_LINGER 0 makes Close send an RST rather than a FIN, which is what the
	// agent saw in the field.
	if tc, ok := b.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	b.Close()

	select {
	case <-errCh:
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return after the peer reset the connection")
	}
}

// --- the human plane ---------------------------------------------------------

// echoSSHD is a local sshd stand-in: it upper-cases whatever it receives.
func echoSSHD(t *testing.T) console.Dialer {
	t.Helper()
	return func(ctx context.Context, address string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			buf := make([]byte, 256)
			for {
				n, err := server.Read(buf)
				if n > 0 {
					_, _ = server.Write([]byte(strings.ToUpper(string(buf[:n]))))
				}
				if err != nil {
					return
				}
			}
		}()
		return client, nil
	}
}

func TestConsoleChannelReachesLocalSSHD(t *testing.T) {
	saas, _ := harnessWithConsole(t, &console.Handler{NodeID: "sky141", Dial: echoSSHD(t)})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch, err := saas.OpenChannel(ctx, 1, tunnelproto.ChannelConsole,
		tunnelproto.Target{Kind: tunnelproto.TargetSSH, Name: "sky141"})
	if err != nil {
		t.Fatalf("open console channel: %v", err)
	}
	defer ch.Close()

	if _, err := ch.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = ch.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(ch, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "HELLO" {
		t.Errorf("echo = %q, want HELLO", buf)
	}
}

// The refusal must carry no node name: a SaaS that could tell "wrong node"
// from "no sshd" could map the cluster by probing names.
func TestConsoleChannelForAnotherNodeRefusesWithoutNamingIt(t *testing.T) {
	saas, _ := harnessWithConsole(t, &console.Handler{NodeID: "sky141", Dial: echoSSHD(t)})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch, err := saas.OpenChannel(ctx, 2, tunnelproto.ChannelConsole,
		tunnelproto.Target{Kind: tunnelproto.TargetSSH, Name: "sky142"})
	if err != nil {
		t.Fatalf("open console channel: %v", err)
	}
	defer ch.Close()

	_ = ch.SetDeadline(time.Now().Add(5 * time.Second))
	body, _ := io.ReadAll(ch)
	if strings.Contains(string(body), "sky142") || strings.Contains(string(body), "sky141") {
		t.Errorf("refusal names a node: %q", body)
	}
}

// An agent with no console configured must not guess which node it is.
func TestConsoleChannelIsRefusedWhenNoConsoleIsConfigured(t *testing.T) {
	saas, _ := harness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch, err := saas.OpenChannel(ctx, 3, tunnelproto.ChannelConsole,
		tunnelproto.Target{Kind: tunnelproto.TargetSSH, Name: "sky141"})
	if err != nil {
		t.Fatalf("open console channel: %v", err)
	}
	defer ch.Close()

	_ = ch.SetDeadline(time.Now().Add(5 * time.Second))
	body, _ := io.ReadAll(ch)
	if !strings.Contains(string(body), tunnelproto.RefusedReason) {
		t.Errorf("body = %q, want the generic refusal", body)
	}
}

// Acceptance criterion: the AI plane has no path to a console channel. The
// protocol refuses a console channel that names a tool, and the tool handler
// refuses a console channel outright — both directions, so neither package
// can grow into the other by accident.
func TestThePlanesCannotReachEachOther(t *testing.T) {
	toolOnConsole := tunnelproto.ChannelOpen{
		Kind:   tunnelproto.ChannelConsole,
		Target: tunnelproto.Target{Kind: tunnelproto.TargetTool, Name: "cluster_check"},
	}
	if err := toolOnConsole.Validate(); err == nil {
		t.Error("a console channel naming a tool validated; the AI plane has a path to the console")
	}

	consoleOnTool := tunnelproto.ChannelOpen{
		Kind:   tunnelproto.ChannelTool,
		Target: tunnelproto.Target{Kind: tunnelproto.TargetSSH, Name: "sky141"},
	}
	if err := consoleOnTool.Validate(); err == nil {
		t.Error("a tool channel naming a node validated; a tool call could open a shell")
	}
}
