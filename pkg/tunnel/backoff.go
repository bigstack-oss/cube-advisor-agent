package tunnel

import (
	"context"
	"log"
	"math"
	"math/rand/v2"
	"time"
)

// Backoff schedules reconnect attempts.
//
// The agent's connection is the customer's only path to support, so it retries
// indefinitely rather than giving up — but it must not become a thundering herd
// when the SaaS restarts and every enrolled cluster reconnects at once. Hence
// the jitter, which is the part that matters at fleet scale.
type Backoff struct {
	Min    time.Duration
	Max    time.Duration
	Factor float64
	// Jitter is the fraction of the computed delay that is randomised, 0..1.
	// 0 makes the schedule deterministic, which is what the tests want.
	Jitter float64

	rand func() float64 // injectable for tests; nil uses math/rand
}

// DefaultBackoff is a sane reconnect schedule: fast enough that a brief SaaS
// restart is invisible, slow enough that an hour-long outage does not generate
// a million connection attempts.
func DefaultBackoff() Backoff {
	return Backoff{Min: time.Second, Max: 2 * time.Minute, Factor: 2, Jitter: 0.2}
}

// Delay returns the wait before attempt n, counting from 0.
func (b Backoff) Delay(n int) time.Duration {
	if n < 0 {
		n = 0
	}
	min, max, factor := b.Min, b.Max, b.Factor
	if min <= 0 {
		min = time.Second
	}
	if max <= 0 || max < min {
		max = min
	}
	if factor < 1 {
		factor = 2
	}

	d := float64(min) * math.Pow(factor, float64(n))
	if d > float64(max) || math.IsInf(d, 1) {
		d = float64(max)
	}
	if b.Jitter > 0 {
		r := b.rand
		if r == nil {
			r = rand.Float64
		}
		// Symmetric jitter around d, clamped at min so a jittered delay never
		// becomes a busy loop.
		spread := d * b.Jitter
		d = d - spread + 2*spread*r()
		if d < float64(min) {
			d = float64(min)
		}
	}
	return time.Duration(d)
}

// Reconnect calls connect until it returns without error or ctx ends, waiting
// per the backoff schedule between attempts. sleep is injectable so the retry
// policy can be tested without real time passing.
//
// It returns the first successful session, or ctx.Err().
func (b Backoff) Reconnect(
	ctx context.Context,
	connect func(context.Context) (*Session, error),
	sleep func(context.Context, time.Duration) error,
) (*Session, error) {
	if sleep == nil {
		sleep = sleepCtx
	}
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s, err := connect(ctx)
		if err == nil {
			return s, nil
		}
		d := b.Delay(attempt)
		log.Printf("tunnel: connect attempt %d failed (%v) — retrying in %s", attempt+1, err, d.Round(time.Millisecond))
		if err := sleep(ctx, d); err != nil {
			return nil, err
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// FlapGuard escalates the wait between reconnects when sessions keep dying
// young.
//
// The case it exists for is two agents sharing one identity: the SaaS
// supersedes the older session on every reconnect, each agent's connect
// succeeds instantly, its session dies moments later, and the pair fight at
// full speed — the lab run measured ~17k tunnel log lines in two minutes. The
// agent cannot tell it was superseded: the SaaS closes the old mux without a
// reason frame, and adding one would be a wire change for a signal this guard
// gets from timing alone. So it watches the symptom instead — connect
// succeeded, session ended within Threshold — which also covers a
// crash-looping SaaS and a misrouting load balancer.
//
// A session that lives past Threshold resets the guard: normal operation pays
// nothing.
type FlapGuard struct {
	// Threshold is the lifetime below which an ended session counts as a flap.
	Threshold time.Duration
	// Backoff schedules the wait for consecutive flaps. Its floor should be
	// tens of seconds — the whole point is to be much slower than the connect
	// ramp.
	Backoff Backoff

	flaps int
}

// DefaultFlapGuard waits 10s, 20s, 40s… up to 2m between young deaths.
func DefaultFlapGuard() *FlapGuard {
	return &FlapGuard{
		Threshold: 30 * time.Second,
		Backoff:   Backoff{Min: 10 * time.Second, Max: 2 * time.Minute, Factor: 2, Jitter: 0.2},
	}
}

// SessionEnded records one session's lifetime and returns how long to wait
// before reconnecting: zero after a session that lived, an escalating delay
// after each one that died young.
func (g *FlapGuard) SessionEnded(lifetime time.Duration) time.Duration {
	if g.Threshold <= 0 || lifetime >= g.Threshold {
		g.flaps = 0
		return 0
	}
	d := g.Backoff.Delay(g.flaps)
	g.flaps++
	return d
}

// Sleep waits for d or until ctx ends, whichever is first. Exported so the
// reconnect loop can honour a FlapGuard delay without reimplementing the
// context dance.
func Sleep(ctx context.Context, d time.Duration) error {
	return sleepCtx(ctx, d)
}
