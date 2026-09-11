package console_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/console"
)

func writeAllowlist(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "web-targets.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The allowlist is the boundary. A name it does not contain is refused, and
// the refusal names no address — the caller learns nothing about the node.
func TestTheAllowlistRefusesWhatItDoesNotName(t *testing.T) {
	p := writeAllowlist(t, `{"dashboard":"127.0.0.1:8080","cmp-portal":"10.32.1.101:443"}`)
	a, err := console.LoadWebAllowlist(p)
	if err != nil {
		t.Fatal(err)
	}

	got, err := a.Resolve("dashboard")
	if err != nil || got != "127.0.0.1:8080" {
		t.Errorf("dashboard = %q, %v", got, err)
	}
	if _, err := a.Resolve("etcd"); !errors.Is(err, console.ErrNotAllowed) {
		t.Errorf("unlisted name: %v, want ErrNotAllowed", err)
	}
	// An address is not a name. Asking for one directly is refused too.
	if _, err := a.Resolve("10.32.1.101:443"); !errors.Is(err, console.ErrNotAllowed) {
		t.Errorf("address as name: %v, want ErrNotAllowed", err)
	}
}

// A malformed entry must fail at load, not at the first operator who uses it.
func TestAnEntryWithoutAPortIsRejectedAtLoad(t *testing.T) {
	p := writeAllowlist(t, `{"dashboard":"127.0.0.1"}`)
	if _, err := console.LoadWebAllowlist(p); err == nil {
		t.Fatal("a host with no port loaded without complaint")
	}
}

// No file means no web targets, which must be a clean empty allowlist rather
// than an error that stops the agent serving SSH.
func TestAMissingAllowlistIsEmptyNotFatal(t *testing.T) {
	a, err := console.LoadWebAllowlist(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("missing file: %v", err)
	}
	if len(a) != 0 {
		t.Errorf("missing file produced %d entries", len(a))
	}
}

// A web channel reaches the allowlisted address and nothing else, and what
// crosses it is bytes — the agent parses no HTTP.
func TestAWebChannelPipesToTheAllowlistedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		_, _ = c.Write([]byte("PONG:" + string(buf)))
	}()

	p := writeAllowlist(t, `{"dashboard":"`+ln.Addr().String()+`"}`)
	a, err := console.LoadWebAllowlist(p)
	if err != nil {
		t.Fatal(err)
	}
	h := &console.WebHandler{Allow: a}

	client, server := net.Pipe()
	go func() { _ = h.Serve(context.Background(), "dashboard", server) }()
	defer client.Close()

	if _, err := client.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 9)
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "PONG:PING" {
		t.Errorf("through the channel: %q", got)
	}
}

// An unlisted name never reaches a dialler at all.
func TestAnUnlistedWebTargetIsNeverDialled(t *testing.T) {
	p := writeAllowlist(t, `{"dashboard":"127.0.0.1:9"}`)
	a, err := console.LoadWebAllowlist(p)
	if err != nil {
		t.Fatal(err)
	}
	dialled := false
	h := &console.WebHandler{
		Allow: a,
		Dial: func(context.Context, string) (net.Conn, error) {
			dialled = true
			return nil, errors.New("should not happen")
		},
	}
	_, server := net.Pipe()
	if err := h.Serve(context.Background(), "etcd", server); !errors.Is(err, console.ErrNotAllowed) {
		t.Errorf("unlisted target: %v, want ErrNotAllowed", err)
	}
	if dialled {
		t.Error("an unlisted target reached the dialler")
	}
}
