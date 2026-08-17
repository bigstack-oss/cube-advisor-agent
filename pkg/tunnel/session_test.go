package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

func goodHello() tunnelproto.Hello {
	return tunnelproto.Hello{
		ClusterID:       "acme-prod-01",
		Fingerprint:     "SHA256:abc",
		AgentVersion:    "0.1.0",
		ProtocolVersion: tunnelproto.Version,
	}
}

// connPair returns two connected endpoints over loopback TCP.
//
// Deliberately not net.Pipe: that is fully synchronous with zero buffering, so
// every write blocks until the peer reads. A multiplexer assumes a buffered
// stream underneath, and the combination deadlocks once the scheduler stops
// papering over it — which it does at GOMAXPROCS=1, i.e. on a small CI runner
// but not on a workstation. A loopback socket has kernel buffering and behaves
// like the wss connection this runs over in production.
func connPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- res{c, err}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-accepted
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() { client.Close(); r.c.Close() })
	return client, r.c
}

// pair wires an agent-side and SaaS-side session over a loopback conn, so the
// protocol is exercised without leaving the machine.
func pair(t *testing.T, hello tunnelproto.Hello, admit func(tunnelproto.Hello) tunnelproto.HelloAck) (agent, saas *Session, dialErr error) {
	t.Helper()
	if admit == nil {
		admit = tunnelproto.Negotiate
	}
	a, b := connPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	type res struct {
		s   *Session
		err error
	}
	saasCh := make(chan res, 1)
	go func() {
		s, err := Accept(ctx, b, admit)
		saasCh <- res{s, err}
	}()

	agent, dialErr = Dial(ctx, a, hello)
	r := <-saasCh
	saas = r.s

	t.Cleanup(func() {
		if agent != nil {
			agent.Close()
		}
		if saas != nil {
			saas.Close()
		}
	})
	return agent, saas, dialErr
}

func TestHandshakeAcceptsACurrentAgent(t *testing.T) {
	agent, saas, err := pair(t, goodHello(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if agent == nil || saas == nil {
		t.Fatal("both sides should have a session")
	}
	if !agent.Ack().Accepted || agent.Ack().ProtocolVersion != tunnelproto.Version {
		t.Errorf("ack = %+v", agent.Ack())
	}
}

// A refused agent must still learn why: the reason is what an operator acts on.
func TestRefusedAgentReceivesTheReason(t *testing.T) {
	old := goodHello()
	old.ProtocolVersion = tunnelproto.MinSupportedVersion - 1

	_, _, err := pair(t, old, nil)
	if err == nil {
		t.Fatal("an out-of-window agent was admitted")
	}
	if !strings.Contains(err.Error(), "acme-prod-01") {
		t.Errorf("refusal should name the cluster, got: %v", err)
	}
}

func TestChannelRoundTrip(t *testing.T) {
	agent, saas, err := pair(t, goodHello(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	accepted := make(chan *Channel, 1)
	go func() {
		ch, err := saas.AcceptChannel(ctx)
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- ch
	}()

	conn, err := agent.OpenChannel(ctx, 1, tunnelproto.ChannelTool,
		tunnelproto.Target{Kind: tunnelproto.TargetTool, Name: "cluster_check"})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	go func() { _, _ = conn.Write([]byte("ping")) }()

	ch := <-accepted
	if ch == nil {
		t.Fatal("channel was not accepted")
	}
	if ch.Open.Target.String() != "tool:cluster_check" {
		t.Errorf("target = %q", ch.Open.Target)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(ch, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("payload = %q", buf)
	}
}

// The receiving side re-validates, because it never trusts the sender. Proven
// by bypassing the sender's own validation and writing a bad open directly.
func TestReceiverRejectsAnAddressTargetFromThePeer(t *testing.T) {
	agent, saas, err := pair(t, goodHello(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Hand-roll the frame the sender's own validation would have blocked.
	raw, err := agent.mux.Open()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = raw.Write([]byte(`{"id":9,"kind":2,"target":{"kind":"ssh","name":"10.0.0.5:22"}}` + "\n"))
	}()

	if _, err := saas.AcceptChannel(ctx); err == nil {
		t.Fatal("receiver accepted a channel-open naming an address")
	}
}

// Flow control: a channel that floods without anyone reading must not stop
// another channel from making progress. This is the property that keeps a
// `tail -f` on a console from starving a tool call on the same connection.
func TestOneChannelCannotStarveAnother(t *testing.T) {
	agent, saas, err := pair(t, goodHello(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// The SaaS accepts both channels but deliberately never reads the noisy one.
	type accepted struct{ ch *Channel }
	got := make(chan accepted, 2)
	go func() {
		for i := 0; i < 2; i++ {
			ch, err := saas.AcceptChannel(ctx)
			if err != nil {
				return
			}
			got <- accepted{ch}
		}
	}()

	noisy, err := agent.OpenChannel(ctx, 1, tunnelproto.ChannelConsole,
		tunnelproto.Target{Kind: tunnelproto.TargetSSH, Name: "sky141"})
	if err != nil {
		t.Fatal(err)
	}
	quiet, err := agent.OpenChannel(ctx, 2, tunnelproto.ChannelTool,
		tunnelproto.Target{Kind: tunnelproto.TargetTool, Name: "cluster_check"})
	if err != nil {
		t.Fatal(err)
	}
	<-got
	<-got

	// Flood the console channel; nobody is reading it, so its window fills.
	flooding := make(chan struct{})
	go func() {
		defer close(flooding)
		blob := make([]byte, 64*1024)
		for i := 0; i < 64; i++ {
			if _, err := noisy.Write(blob); err != nil {
				return
			}
		}
	}()

	// The tool channel must still round-trip while the console is blocked.
	done := make(chan error, 1)
	go func() {
		_, err := quiet.Write([]byte("tool-call"))
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("tool channel write failed while the console was flooding: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a flooded console channel starved the tool channel — per-channel flow control is not working")
	}

	// Without this, the test would pass vacuously if the multiplexer simply
	// buffered all 4 MB: the tool call would succeed because nothing was ever
	// blocked. Assert the console writer really is stuck on a full window, so
	// the tool call demonstrably proceeded *past* a blocked peer channel.
	select {
	case <-flooding:
		t.Fatal("the console flood completed, so nothing was blocked and this test proves nothing " +
			"— increase the flood size above the per-stream window")
	default:
	}
}

// The kill switch drops everything, including channels mid-stream.
func TestCloseDropsLiveChannels(t *testing.T) {
	agent, saas, err := pair(t, goodHello(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	accepted := make(chan *Channel, 1)
	go func() {
		ch, err := saas.AcceptChannel(ctx)
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- ch
	}()
	if _, err := agent.OpenChannel(ctx, 1, tunnelproto.ChannelConsole,
		tunnelproto.Target{Kind: tunnelproto.TargetSSH, Name: "sky141"}); err != nil {
		t.Fatal(err)
	}
	ch := <-accepted
	if ch == nil {
		t.Fatal("channel not accepted")
	}

	if err := agent.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := io.ReadAll(ch); err == nil && !saas.IsClosed() {
		t.Error("a live console channel survived the session closing")
	}
}

func TestOpenChannelRefusesInvalidTargetsBeforeSending(t *testing.T) {
	agent, _, err := pair(t, goodHello(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = agent.OpenChannel(context.Background(), 1, tunnelproto.ChannelConsole,
		tunnelproto.Target{Kind: tunnelproto.TargetSSH, Name: "10.0.0.5:22"})
	if err == nil {
		t.Fatal("an address target was sent")
	}
	if !errors.Is(err, err) || !strings.Contains(err.Error(), "addresses") {
		t.Logf("error text: %v", err)
	}
}

// Regression: the channel header and the first payload bytes arriving in ONE
// write must both survive.
//
// AcceptChannel parses the header with a json.Decoder, which reads in chunks
// and keeps whatever it over-read. Before the fix, that surplus — here the
// payload — was silently dropped, and the reader blocked forever waiting for
// bytes that had already been consumed. It only reproduced when the two landed
// in the same read, which a multi-core box almost never does and a
// single-CPU CI runner reliably does.
func TestChannelHeaderAndPayloadInOneWriteBothSurvive(t *testing.T) {
	agent, saas, err := pair(t, goodHello(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	accepted := make(chan *Channel, 1)
	go func() {
		ch, err := saas.AcceptChannel(ctx)
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- ch
	}()

	// Bypass OpenChannel so header and payload are guaranteed to coalesce.
	raw, err := agent.mux.Open()
	if err != nil {
		t.Fatal(err)
	}
	frame := `{"id":1,"kind":1,"target":{"kind":"tool","name":"cluster_check"}}` + "\n" + "payload-bytes"
	if _, err := raw.Write([]byte(frame)); err != nil {
		t.Fatal(err)
	}

	ch := <-accepted
	if ch == nil {
		t.Fatal("channel was not accepted")
	}
	buf := make([]byte, len("payload-bytes"))
	if err := ch.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ch, buf); err != nil {
		t.Fatalf("payload lost with the header: %v", err)
	}
	if string(buf) != "payload-bytes" {
		t.Errorf("payload = %q", buf)
	}
}
