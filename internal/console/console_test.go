package console

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSSHD stands in for the node's own sshd: it echoes what it is sent,
// upper-cased, so a test can prove bytes crossed in both directions.
func fakeSSHD(t *testing.T) (Dialer, func() int) {
	t.Helper()
	conns := 0
	dial := func(ctx context.Context, address string) (net.Conn, error) {
		if address != LocalSSH {
			t.Errorf("dialled %q, want the node's own sshd at %q", address, LocalSSH)
		}
		conns++
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
	return dial, func() int { return conns }
}

// rw is the tunnel side of the channel, driven by the test.
type rw struct {
	in  *io.PipeReader
	out *io.PipeWriter
}

func (c rw) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c rw) Write(p []byte) (int, error) { return c.out.Write(p) }

func TestConsolePipesBothWaysToLocalSSHD(t *testing.T) {
	dial, conns := fakeSSHD(t)
	h := &Handler{NodeID: "sky141", Dial: dial}

	toAgent, fromTest := io.Pipe()
	toTest, fromAgent := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- h.Serve(context.Background(), "sky141", rw{in: toAgent, out: fromAgent}) }()

	if _, err := fromTest.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if err := readFull(toTest, buf, time.Second); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf) != "HELLO" {
		t.Errorf("echo = %q, want HELLO", buf)
	}
	if conns() != 1 {
		t.Errorf("dialled %d times, want exactly one connection", conns())
	}

	// Closing the tunnel side ends the session rather than hanging.
	_ = fromTest.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve after close = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the tunnel side closed")
	}
}

// The check is on the node because the SaaS is never trusted to scope its own
// requests. With one agent per node this is the whole allowlist.
func TestConsoleRefusesAnyNodeButItsOwn(t *testing.T) {
	dial, conns := fakeSSHD(t)
	h := &Handler{NodeID: "sky141", Dial: dial}

	for _, target := range []string{"sky142", "", "sky141 ", "SKY141", "127.0.0.1"} {
		err := h.Serve(context.Background(), target, rw{})
		if !errors.Is(err, ErrNotThisNode) {
			t.Errorf("Serve(%q) = %v, want ErrNotThisNode", target, err)
		}
	}
	if conns() != 0 {
		t.Errorf("a refused target still dialled %d times; nothing should be dialled", conns())
	}
}

func TestConsoleReportsNoSSHDRatherThanHanging(t *testing.T) {
	h := &Handler{
		NodeID: "sky141",
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		},
	}
	err := h.Serve(context.Background(), "sky141", rw{})
	if !errors.Is(err, ErrNoSSHD) {
		t.Errorf("Serve with no sshd = %v, want ErrNoSSHD", err)
	}
}

// A cancelled context has to close the local connection, or a dropped tunnel
// leaves an ssh session open on the customer's node with nobody attached.
func TestConsoleCancellationClosesTheLocalConnection(t *testing.T) {
	var opened net.Conn
	h := &Handler{
		NodeID: "sky141",
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			client, server := net.Pipe()
			opened = server
			return client, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	toAgent, _ := io.Pipe()
	_, fromAgent := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx, "sky141", rw{in: toAgent, out: fromAgent}) }()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}

	_ = opened.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := opened.Read(make([]byte, 1)); err == nil {
		t.Error("the local connection is still open after cancellation")
	}
}

func readFull(r io.Reader, buf []byte, within time.Duration) error {
	type result struct {
		err error
	}
	ch := make(chan result, 1)
	go func() {
		_, err := io.ReadFull(r, buf)
		ch <- result{err}
	}()
	select {
	case res := <-ch:
		return res.err
	case <-time.After(within):
		return errors.New("timed out")
	}
}
