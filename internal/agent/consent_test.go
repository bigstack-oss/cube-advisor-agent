package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnel"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// The wire field has to reach the registry, and only an end-to-end test can say
// so. This one exists because the obvious break — serveTool passing a hardcoded
// true instead of ch.Open.Approved — passed the entire suite. Every consent
// test in toolplane calls the registry directly, so none of them crosses the
// tunnel, and the plumbing between the two was asserted by nothing.
func TestApprovalOnTheOpenFrameReachesTheRegistry(t *testing.T) {
	for _, c := range []struct {
		name     string
		approved bool
		wantOK   bool
	}{
		{"a person approved it", true, true},
		{"nobody approved it", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			saas, rec := consentHarness(t, toolplane.ConsentAlways)

			res := callConfiguringTool(t, saas, 1, c.approved)
			if res.OK != c.wantOK {
				t.Fatalf("result OK = %v, want %v (%+v)", res.OK, c.wantOK, res)
			}

			calls := rec.snapshot()
			if len(calls) != 1 {
				t.Fatalf("audit recorded %d calls, want 1", len(calls))
			}
			if calls[0].Allowed != c.wantOK {
				t.Errorf("audit Allowed = %v, want %v", calls[0].Allowed, c.wantOK)
			}
			if !c.wantOK && !strings.Contains(calls[0].Reason, "requires a person") {
				t.Errorf("audit reason = %q, want it to name the missing person", calls[0].Reason)
			}
		})
	}
}

// A cluster that asks nobody serves the same call without one, over the same
// path. Without this the test above would pass for an agent that refuses every
// configuring call whatever its setting.
func TestAClusterAtNeverServesAnUnapprovedCallOverTheTunnel(t *testing.T) {
	saas, rec := consentHarness(t, toolplane.ConsentNever)

	if res := callConfiguringTool(t, saas, 1, false); !res.OK {
		t.Fatalf("a cluster at consent never refused an unapproved call: %+v", res)
	}
	if calls := rec.snapshot(); len(calls) != 1 || !calls[0].Allowed {
		t.Fatalf("audit = %+v", calls)
	}
}

// consentHarness is harness with the dial set and a write path wired, so a
// configuring call can reach the point where consent decides.
func consentHarness(t *testing.T, c toolplane.Consent) (*tunnel.Session, *recorder) {
	t.Helper()
	return harnessWith(t, func(r *toolplane.Registry) {
		toolplane.WithLevel(toolplane.LevelOperate)(r)
		toolplane.WithConsent(c)(r)
		r.ConfigureInstanceProfile(toolplane.InstanceProfile{
			Flavor: "m1.large", Image: "ubuntu-24.04",
			Network: "tenant-net", Project: "acme-prod",
		})
		r.SetWriterForTest(toolplane.BackendOpenStackCompute, approvingPoster{}, nil)
	})
}

// approvingPoster stands in for OpenStack: the write itself is not what these
// tests are about, so it succeeds and records nothing.
type approvingPoster struct{}

func (approvingPoster) Post(context.Context, string, []byte, string, int) ([]byte, error) {
	return []byte(`{"id":"i-1"}`), nil
}

// callConfiguringTool opens a tool channel for a call the consent dial gates,
// marking it approved or not exactly as the SaaS would.
func callConfiguringTool(t *testing.T, saas *tunnel.Session, id uint32, approved bool) tunnelproto.ToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var opts []tunnel.OpenOption
	if approved {
		opts = append(opts, tunnel.ApprovedByPerson())
	}
	conn, err := saas.OpenChannel(ctx, id, tunnelproto.ChannelTool,
		tunnelproto.Target{Kind: tunnelproto.TargetTool, Name: "create_instance"}, opts...)
	if err != nil {
		t.Fatalf("open create_instance: %v", err)
	}
	if err := json.NewEncoder(conn).Encode(map[string]string{"{name}": "web-03"}); err != nil {
		t.Fatalf("send args: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var res tunnelproto.ToolResult
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		t.Fatalf("read result: %v", err)
	}
	return res
}
