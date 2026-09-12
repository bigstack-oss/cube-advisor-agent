package toolplane

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// An oversized result is evidence, not a failure: the caller gets the capped
// bytes plus a marker, as a success, and the audit says the cut happened.
func TestOversizedOutputIsTruncatedNotRefused(t *testing.T) {
	r, rec, _ := newTestRegistry(t)
	const max = 64
	r.run = func(ctx context.Context, argv []string, maxBytes int) ([]byte, error) {
		return []byte(strings.Repeat("x", max)), fmt.Errorf("%w at %d bytes", ErrOutputTruncated, max)
	}

	out, err := r.Call(context.Background(), "cluster_check", nil, true)
	if err != nil {
		t.Fatalf("a truncated call must succeed, got %v", err)
	}
	if !strings.HasPrefix(string(out), strings.Repeat("x", max)) {
		t.Error("the capped bytes did not come back")
	}
	if !strings.Contains(string(out), "[truncated after 64 bytes by the executor's output cap]") {
		t.Errorf("marker missing or wrong: %q", out)
	}
	if len(rec.calls) != 1 || !rec.calls[0].Truncated {
		t.Error("the audit record does not say the result was truncated")
	}
	if rec.calls[0].Reason != "" {
		t.Errorf("truncation is not a failure; reason = %q", rec.calls[0].Reason)
	}
}

// A result exactly at the cap is not truncated: the detection reads one byte
// past the limit, so a fit is a fit.
func TestOutputExactlyAtTheCapIsUntouched(t *testing.T) {
	r, rec, _ := newTestRegistry(t)
	body := strings.Repeat("y", 32)
	r.run = func(ctx context.Context, argv []string, maxBytes int) ([]byte, error) {
		return []byte(body), nil
	}

	out, err := r.Call(context.Background(), "cluster_check", nil, true)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if string(out) != body {
		t.Errorf("output = %q, want it byte-identical", out)
	}
	if rec.calls[0].Truncated {
		t.Error("a fitting result must not be marked truncated")
	}
}

// A runner that reports truncation mid-rune must not hand the model half a
// character: the cut backs off to a rune boundary and the marker counts the
// bytes actually kept.
func TestTruncationNeverSplitsARune(t *testing.T) {
	r, rec, _ := newTestRegistry(t)
	raw := []byte("héllo")[:2] // 'h' + first byte of 'é', as a byte-capped runner would return
	r.run = func(ctx context.Context, argv []string, maxBytes int) ([]byte, error) {
		return raw, ErrOutputTruncated
	}

	out, err := r.Call(context.Background(), "cluster_check", nil, true)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.HasPrefix(string(out), "h\n") {
		t.Errorf("kept bytes = %q, want the split rune dropped", out)
	}
	if !strings.Contains(string(out), "[truncated after 1 bytes") {
		t.Errorf("marker should count the 1 byte kept after the rune cut: %q", out)
	}
	if !rec.calls[0].Truncated {
		t.Error("audit record missing the truncation")
	}
}
