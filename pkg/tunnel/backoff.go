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
