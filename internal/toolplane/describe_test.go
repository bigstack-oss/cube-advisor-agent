package toolplane

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

func describe(t *testing.T, r *Registry) tunnelproto.InstanceProfile {
	t.Helper()
	out, err := r.Call(context.Background(), tunnelproto.DescribeInstanceProfile, nil, true)
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	var got tunnelproto.InstanceProfile
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("describe returned %s: %v", out, err)
	}
	return got
}

// The values a person is asked to approve come from this call, so it has to
// report the ones a create would actually use — not a summary, not a subset.
func TestDescribeReportsTheProfileACreateWouldUse(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	r.ConfigureInstanceProfile(InstanceProfile{
		Flavor: "m1.large", Image: "ubuntu-24.04", Network: "tenant-net", Project: "acme-prod",
	})

	got := describe(t, r)
	want := tunnelproto.InstanceProfile{
		Configured: true,
		Flavor:     "m1.large", Image: "ubuntu-24.04", Network: "tenant-net", Project: "acme-prod",
	}
	if got != want {
		t.Errorf("describe = %+v, want %+v", got, want)
	}
}

// An agent nobody has configured says so and invents nothing. The caller is
// composing a sentence for a person: empty strings rendered into it would
// promise a machine with no image.
func TestAnUnconfiguredAgentDescribesNoProfile(t *testing.T) {
	r, _, _ := newTestRegistry(t)

	got := describe(t, r)
	if got.Configured {
		t.Errorf("an unconfigured agent reports a profile: %+v", got)
	}
	if got.Flavor != "" || got.Image != "" || got.Network != "" {
		t.Errorf("an unconfigured agent named values: %+v", got)
	}
}

// A half-configured profile refuses every create, so reporting it as
// configured would put values in front of a person for a call that cannot run.
func TestAPartialProfileIsNotReportedAsConfigured(t *testing.T) {
	for _, p := range []InstanceProfile{
		{Image: "ubuntu-24.04", Network: "tenant-net"},
		{Flavor: "m1.large", Network: "tenant-net"},
		{Flavor: "m1.large", Image: "ubuntu-24.04"},
	} {
		r, _, _ := newTestRegistry(t)
		r.ConfigureInstanceProfile(p)
		if got := describe(t, r); got.Configured {
			t.Errorf("profile %+v reported as configured", p)
		}
	}
}

// It answers one question and takes nothing. A caller passing an argument has
// misunderstood what this reports, and ignoring it would let that
// misunderstanding reach an approval prompt.
func TestDescribeRefusesArguments(t *testing.T) {
	r, rec, _ := newTestRegistry(t)
	r.ConfigureInstanceProfile(InstanceProfile{Flavor: "f", Image: "i", Network: "n"})

	_, err := r.Call(context.Background(), tunnelproto.DescribeInstanceProfile,
		map[string]string{"cluster": "other"}, true)
	if !errors.Is(err, ErrBadArgument) {
		t.Fatalf("describe with an argument = %v, want ErrBadArgument", err)
	}
	if len(rec.calls) == 0 || rec.calls[len(rec.calls)-1].Allowed {
		t.Error("the refusal was not audited")
	}
}

// The describing tool reaches no probe runner, and an agent built without one
// still has to say what a create would make. This is the guard on the
// restructure that let a non-probe control op past the runner check.
func TestDescribeWorksWithoutAProbeRunner(t *testing.T) {
	r, err := New(Allowlist, &recorder{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if r.probes != nil {
		t.Fatal("a registry built without WithProbes has a runner")
	}
	r.ConfigureInstanceProfile(InstanceProfile{Flavor: "f", Image: "i", Network: "n"})

	if got := describe(t, r); !got.Configured {
		t.Errorf("describe without a probe runner = %+v, want the profile", got)
	}
}

// The model cannot choose a flavour or an image, so a tool reporting them has
// no business in its tool list. Unlisted is what lets the SaaS know that
// absence is deliberate rather than a list gone stale.
func TestDescribeIsNotOfferedToTheModel(t *testing.T) {
	var found bool
	for _, tool := range Allowlist {
		if tool.Name != tunnelproto.DescribeInstanceProfile {
			continue
		}
		found = true
		if !tool.Unlisted {
			t.Error("describe_instance_profile is listed to the model")
		}
		if tool.Impact != ImpactRead {
			t.Errorf("describe_instance_profile impact = %s, want read", tool.Impact)
		}
	}
	if !found {
		t.Fatal("the allowlist has no describe_instance_profile")
	}
}
