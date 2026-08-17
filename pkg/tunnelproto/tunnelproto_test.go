package tunnelproto

import "testing"

// The protocol's reason for existing: a channel-open cannot name an address.
// If any of these were accepted, a compromised or prompt-injected SaaS could
// use the tunnel to reach arbitrary hosts on the customer's network — the exact
// pivot ADR 0002 exists to prevent.
func TestAddressShapedTargetsAreRejected(t *testing.T) {
	addresses := []string{
		"10.32.10.141:22",
		"10.32.10.141",
		"[::1]:22",
		"::1",
		"localhost:8080",
		"http://10.0.0.5:8080",
		"https://internal.corp/admin",
		"ssh://node1:22",
		"root@10.0.0.5",
		"node1:22",
		"node1 22",
		"*.internal",
		"../../etc/passwd",
		"/dev/tcp/10.0.0.5/22",
		"node1;nc 10.0.0.5 22",
		"node1\n10.0.0.5",
		"192.168.1.1",
	}
	for _, a := range addresses {
		tg := Target{Kind: TargetSSH, Name: a}
		if err := tg.Validate(); err == nil {
			t.Errorf("Target{ssh, %q} was accepted; the protocol must not be able to express an address", a)
		}
	}
}

func TestSymbolicTargetsAreAccepted(t *testing.T) {
	valid := []Target{
		{TargetSSH, "sky141"},
		{TargetSSH, "sky141.lab.bigstack.co"}, // FQDN node names are legitimate
		{TargetSSH, "node_1"},
		{TargetSSH, "control-plane-0"},
		{TargetWeb, "dashboard"},
		{TargetWeb, "ceph-dashboard"},
		{TargetTool, "cluster_check"},
	}
	for _, tg := range valid {
		if err := tg.Validate(); err != nil {
			t.Errorf("Target%v rejected: %v", tg, err)
		}
	}
}

func TestTargetRejectsUnknownKindAndOversizedName(t *testing.T) {
	if err := (Target{TargetKind("shell"), "anything"}).Validate(); err == nil {
		t.Error("unknown target kind accepted")
	}
	if err := (Target{TargetSSH, ""}).Validate(); err == nil {
		t.Error("empty target name accepted")
	}
	long := make([]byte, MaxTargetNameLen+1)
	for i := range long {
		long[i] = 'a'
	}
	if err := (Target{TargetSSH, string(long)}).Validate(); err == nil {
		t.Error("oversized target name accepted; a name must not double as a data channel")
	}
}

// The two planes are separated at the protocol layer, not by agent convention.
// This is what makes "the AI has no path to a console" a structural claim.
func TestPlanesCannotCross(t *testing.T) {
	cases := []struct {
		name string
		open ChannelOpen
		ok   bool
	}{
		{"tool channel to a tool", ChannelOpen{1, ChannelTool, Target{TargetTool, "cluster_check"}}, true},
		{"console channel to ssh", ChannelOpen{2, ChannelConsole, Target{TargetSSH, "sky141"}}, true},
		{"console channel to web", ChannelOpen{3, ChannelConsole, Target{TargetWeb, "dashboard"}}, true},
		{"tool channel to ssh", ChannelOpen{4, ChannelTool, Target{TargetSSH, "sky141"}}, false},
		{"tool channel to web", ChannelOpen{5, ChannelTool, Target{TargetWeb, "dashboard"}}, false},
		{"console channel to a tool", ChannelOpen{6, ChannelConsole, Target{TargetTool, "cluster_check"}}, false},
		{"ctl is not openable", ChannelOpen{7, ChannelCtl, Target{TargetTool, "cluster_check"}}, false},
		{"unknown channel kind", ChannelOpen{8, ChannelKind(9), Target{TargetTool, "cluster_check"}}, false},
	}
	for _, c := range cases {
		err := c.open.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: unexpected rejection: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: accepted, want rejection", c.name)
		}
	}
}

func TestNegotiate(t *testing.T) {
	base := Hello{ClusterID: "acme-prod-01", Fingerprint: "SHA256:abc", AgentVersion: "0.1.0"}

	ok := base
	ok.ProtocolVersion = Version
	if ack := Negotiate(ok); !ack.Accepted || ack.ProtocolVersion != Version {
		t.Errorf("current version refused: %+v", ack)
	}

	old := base
	old.ProtocolVersion = MinSupportedVersion - 1
	ack := Negotiate(old)
	if ack.Accepted {
		t.Error("an agent below the support window was accepted")
	}
	// A refused agent is a human's problem to fix, so the reason has to name
	// the cluster and what to do about it.
	for _, want := range []string{"acme-prod-01", "upgrade"} {
		if !contains(ack.Reason, want) {
			t.Errorf("refusal reason %q should mention %q", ack.Reason, want)
		}
	}

	future := base
	future.ProtocolVersion = Version + 1
	if ack := Negotiate(future); ack.Accepted {
		t.Error("an agent newer than the SaaS was accepted")
	}

	for _, bad := range []Hello{
		{Fingerprint: "SHA256:abc", ProtocolVersion: Version},
		{ClusterID: "acme-prod-01", ProtocolVersion: Version},
	} {
		if ack := Negotiate(bad); ack.Accepted {
			t.Errorf("incomplete hello accepted: %+v", bad)
		}
	}
}

func TestChannelKindString(t *testing.T) {
	if ChannelCtl.String() != "ctl" || ChannelTool.String() != "tool" || ChannelConsole.String() != "console" {
		t.Error("channel kind names are part of operator-facing logs; keep them stable")
	}
	if ChannelKind(9).Valid() {
		t.Error("an unknown channel kind must not validate")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
