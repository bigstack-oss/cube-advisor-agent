package console

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

type relayRecord struct {
	node    string
	allowed bool
}

func relayHandler(t *testing.T, dial Dialer, nodes []string, err error) (*Handler, *[]relayRecord) {
	t.Helper()
	var recs []relayRecord
	h := &Handler{NodeID: "ctl1", Dial: dial,
		Peers: func(context.Context) ([]string, error) { return nodes, err },
		Audit: func(node string, allowed bool, _ string) { recs = append(recs, relayRecord{node, allowed}) },
	}
	return h, &recs
}

func TestRelayPipesAPeerToTheLocalSSHD(t *testing.T) {
	dial, conns := fakeSSHD(t)
	h, recs := relayHandler(t, dial, []string{"ctl1", "compute1"}, nil)

	toAgent, fromTest := io.Pipe()
	toTest, fromAgent := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- h.Serve(context.Background(), "compute1", rw{in: toAgent, out: fromAgent}) }()

	if _, err := fromTest.Write([]byte("ssh")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 3)
	if err := readFull(toTest, buf, time.Second); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf) != "SSH" {
		t.Errorf("echo = %q, want SSH", buf)
	}
	_ = fromTest.Close()
	<-done
	if conns() != 1 {
		t.Errorf("dialled %d times, want 1 (to the local sshd)", conns())
	}
	if len(*recs) != 1 || (*recs)[0] != (relayRecord{"compute1", true}) {
		t.Errorf("audit = %+v, want one allowed record for compute1", *recs)
	}
}

func TestRelayRefusesWhatIsNotAPeer(t *testing.T) {
	for _, target := range []string{
		"storage9",                   // not on the list
		"CTL1", "ctl1.local", // this node, under another spelling
		"-oProxyCommand=sh", "-oProxyCommand", "a b", "x;id", "root@compute1", "compute1:22", "",
	} {
		t.Run(target, func(t *testing.T) {
			dial, conns := fakeSSHD(t)
			h, recs := relayHandler(t, dial, []string{"ctl1", "compute1", "-oProxyCommand", "x;id"}, nil)
			err := h.Serve(context.Background(), target, rw{})
			if err == nil {
				t.Fatalf("Serve(%q) = nil, want a refusal", target)
			}
			if conns() != 0 {
				t.Errorf("Serve(%q) dialled sshd; a refusal must not", target)
			}
			if target == "" {
				return // no name: not a relay
			}
			if !errors.Is(err, ErrRelayRefused) {
				t.Errorf("Serve(%q) = %v, want ErrRelayRefused", target, err)
			}
			if len(*recs) != 1 || (*recs)[0].allowed {
				t.Errorf("audit = %+v, want one refused record", *recs)
			}
		})
	}
}

func TestRelayRefusedWhenTheNodeListFails(t *testing.T) {
	dial, conns := fakeSSHD(t)
	h, recs := relayHandler(t, dial, nil, errors.New("cubectl missing"))
	if err := h.Serve(context.Background(), "compute1", rw{}); !errors.Is(err, ErrRelayRefused) {
		t.Fatalf("Serve = %v, want ErrRelayRefused", err)
	}
	if conns() != 0 || len(*recs) != 1 || (*recs)[0].allowed {
		t.Errorf("conns=%d audit=%+v, want no dial and one refusal", conns(), *recs)
	}
}

func TestWithoutPeersAnotherNodeIsRefusedAsBefore(t *testing.T) {
	dial, conns := fakeSSHD(t)
	h := &Handler{NodeID: "ctl1", Dial: dial}
	if h.Relays() {
		t.Fatal("Relays() = true without a node list")
	}
	if err := h.Serve(context.Background(), "compute1", rw{}); !errors.Is(err, ErrNotThisNode) {
		t.Fatalf("Serve = %v, want ErrNotThisNode", err)
	}
	if conns() != 0 {
		t.Error("dialled sshd for another node with relaying off")
	}
}
