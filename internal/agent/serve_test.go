package agent

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

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
	rec := &recorder{}
	reg, err := toolplane.New(toolplane.Allowlist, rec)
	if err != nil {
		t.Fatalf("registry: %v", err)
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

	srv := &Server{Tools: reg, CallTimeout: 5 * time.Second}
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
func callTool(t *testing.T, saas *tunnel.Session, id uint32, name string, args map[string]string) Result {
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
	var res Result
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

	for _, r := range []Result{unknown, badArg} {
		if r.OK {
			t.Errorf("a refused call reported success: %+v", r)
		}
		if r.Error != refusedReason {
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
	done := make(chan Result, 1)
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
	big := strings.Repeat("a", maxArgsBytes+10) + "\n"
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
