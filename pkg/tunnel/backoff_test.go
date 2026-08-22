package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDelayGrowsAndClamps(t *testing.T) {
	b := Backoff{Min: time.Second, Max: 30 * time.Second, Factor: 2} // Jitter 0 = deterministic
	want := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second, // clamped
		30 * time.Second,
	}
	for i, w := range want {
		if got := b.Delay(i); got != w {
			t.Errorf("Delay(%d) = %s, want %s", i, got, w)
		}
	}
	// A huge attempt count must not overflow into a negative or zero delay.
	if got := b.Delay(1000); got != 30*time.Second {
		t.Errorf("Delay(1000) = %s, want the max", got)
	}
	if got := b.Delay(-5); got != time.Second {
		t.Errorf("Delay(-5) = %s, want the min", got)
	}
}

// Jitter is what stops every enrolled cluster reconnecting in lockstep after a
// SaaS restart, so it has to actually spread — and never collapse to a busy loop.
func TestJitterSpreadsButNeverBusyLoops(t *testing.T) {
	b := Backoff{Min: time.Second, Max: time.Minute, Factor: 2, Jitter: 0.5}

	b.rand = func() float64 { return 0 } // worst case low
	low := b.Delay(3)
	b.rand = func() float64 { return 1 } // worst case high
	high := b.Delay(3)

	if low >= high {
		t.Fatalf("jitter did not spread: low=%s high=%s", low, high)
	}
	if low < b.Min {
		t.Errorf("jittered delay %s fell below the minimum %s — that is a busy loop", low, b.Min)
	}
}

func TestReconnectRetriesUntilSuccess(t *testing.T) {
	b := Backoff{Min: time.Millisecond, Max: time.Millisecond, Factor: 2}

	attempts := 0
	var slept []time.Duration
	sleep := func(ctx context.Context, d time.Duration) error {
		slept = append(slept, d) // no real time passes
		return nil
	}
	connect := func(context.Context) (*Session, error) {
		attempts++
		if attempts < 4 {
			return nil, errors.New("connection refused")
		}
		return &Session{}, nil
	}

	s, err := b.Reconnect(context.Background(), connect, sleep)
	if err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if s == nil {
		t.Fatal("expected a session")
	}
	if attempts != 4 {
		t.Errorf("attempts = %d, want 4", attempts)
	}
	if len(slept) != 3 {
		t.Errorf("slept %d times, want 3 (once between each failure)", len(slept))
	}
}

// The agent retries indefinitely — the tunnel is the customer's only path to
// support — so cancellation is the only thing that stops it.
func TestReconnectStopsOnContextCancel(t *testing.T) {
	b := Backoff{Min: time.Millisecond, Max: time.Millisecond, Factor: 2}
	ctx, cancel := context.WithCancel(context.Background())

	calls := 0
	connect := func(context.Context) (*Session, error) {
		calls++
		if calls == 3 {
			cancel()
		}
		return nil, errors.New("nope")
	}
	sleep := func(ctx context.Context, d time.Duration) error { return ctx.Err() }

	if _, err := b.Reconnect(ctx, connect, sleep); !errors.Is(err, context.Canceled) {
		t.Errorf("Reconnect returned %v, want context.Canceled", err)
	}
}

func TestDefaultBackoffIsSane(t *testing.T) {
	b := DefaultBackoff()
	if b.Delay(0) < 500*time.Millisecond {
		t.Error("first retry is too eager")
	}
	if b.Delay(50) > 5*time.Minute {
		t.Error("backoff grows beyond a useful ceiling")
	}
	if b.Jitter <= 0 {
		t.Error("the default must jitter, or a SaaS restart becomes a thundering herd")
	}
}

func TestFlapGuardEscalatesOnYoungDeaths(t *testing.T) {
	g := &FlapGuard{
		Threshold: 30 * time.Second,
		Backoff:   Backoff{Min: 10 * time.Second, Max: 2 * time.Minute, Factor: 2},
	}
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 2 * time.Minute, 2 * time.Minute}
	for i, w := range want {
		if got := g.SessionEnded(2 * time.Second); got != w {
			t.Fatalf("flap %d: got %s, want %s", i, got, w)
		}
	}
}

func TestFlapGuardResetsAfterALongSession(t *testing.T) {
	g := DefaultFlapGuard()
	g.Backoff.Jitter = 0
	if g.SessionEnded(time.Second) == 0 {
		t.Fatal("young death should wait")
	}
	if d := g.SessionEnded(time.Hour); d != 0 {
		t.Fatalf("a session that lived must not wait, got %s", d)
	}
	if got, want := g.SessionEnded(time.Second), g.Backoff.Min; got != want {
		t.Fatalf("after a reset the ladder restarts: got %s, want %s", got, want)
	}
}

func TestDefaultFlapGuardIsMuchSlowerThanTheConnectRamp(t *testing.T) {
	g := DefaultFlapGuard()
	if g.Backoff.Min < 10*time.Second {
		t.Error("flap floor must be tens of seconds, or two agents sharing an identity fight at reconnect speed")
	}
	if g.Threshold <= 0 {
		t.Error("a zero threshold disables the guard")
	}
	if g.Backoff.Jitter <= 0 {
		t.Error("flap waits must jitter, or the two fighting agents stay synchronised")
	}
}
