// Package tunnelproto is the wire protocol between the on-cluster CubeCOS AI
// Advisor agent and the Bigstack SaaS.
//
// It lives in this public repository, and the private SaaS imports it. The
// dependency direction is deliberate and one-way: nothing public depends on
// anything private, so the component that holds console access on a customer's
// cluster stays auditable by that customer.
//
// # Shape
//
// The agent dials out (wss over 443) and the SaaS multiplexes channels back
// over the single stream. There are no inbound rules and no VPN. Three channel
// kinds exist:
//
//	ChannelCtl     — enrollment, heartbeat, kill switch
//	ChannelTool    — AI plane: read-only tool calls, allowlist enforced agent-side
//	ChannelConsole — human plane: recorded PTY / web proxy; the AI has no path here
//
// # The property this package exists to guarantee
//
// A channel-open names a *symbolic target* — never an address. The protocol
// cannot express "connect to 10.0.0.5:22", so a compromised or prompt-injected
// SaaS cannot use the tunnel to reach arbitrary hosts on the customer's
// network. The agent resolves symbolic targets against its own local allowlist.
// Everything in Target below serves that one guarantee.
package tunnelproto

import (
	"fmt"
	"strings"
)

// Version is the protocol version this build speaks.
//
// Bump it only for a breaking change. Additive changes — a new channel kind, a
// new target kind — do not bump it, because the SaaS must keep serving the
// prior version while pinned clusters exist and every bump widens that window.
const Version = 1

// MinSupportedVersion is the oldest protocol version a peer may speak and still
// be served. The window is a policy choice: enterprises that forbid
// self-updating privileged daemons pin their agents deliberately, and the
// window is what makes that supportable rather than a bug.
const MinSupportedVersion = 1

// ChannelKind discriminates multiplexed streams on one tunnel.
type ChannelKind uint8

const (
	ChannelCtl ChannelKind = iota
	ChannelTool
	ChannelConsole
)

func (k ChannelKind) String() string {
	switch k {
	case ChannelCtl:
		return "ctl"
	case ChannelTool:
		return "tool"
	case ChannelConsole:
		return "console"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(k))
	}
}

// Valid reports whether k is a channel kind this build understands. An unknown
// kind from a newer peer is refused rather than guessed at.
func (k ChannelKind) Valid() bool { return k <= ChannelConsole }

// Hello is the agent's opening frame, sent after the mTLS handshake.
type Hello struct {
	ClusterID       string `json:"clusterId"`
	Fingerprint     string `json:"fingerprint"`     // agent identity, shown at enrollment verify
	AgentVersion    string `json:"agentVersion"`    // release of the agent binary
	ProtocolVersion int    `json:"protocolVersion"` // what this agent speaks
}

// HelloAck is the SaaS's response. Accepted=false carries an operator-readable
// Reason: a refused agent is something a human has to fix, and "handshake
// failed" in a log is not enough to act on.
type HelloAck struct {
	Accepted        bool   `json:"accepted"`
	ProtocolVersion int    `json:"protocolVersion"` // what the SaaS will speak
	Reason          string `json:"reason,omitempty"`
}

// Negotiate decides whether to serve an agent's Hello.
//
// The returned HelloAck is always safe to send back; when Accepted is false its
// Reason names the versions involved and what to do, because the person reading
// it is trying to get a cluster back online.
func Negotiate(h Hello) HelloAck {
	switch {
	case h.ClusterID == "":
		return HelloAck{Reason: "hello carried no cluster id"}
	case h.Fingerprint == "":
		return HelloAck{Reason: "hello carried no agent fingerprint"}
	case h.ProtocolVersion < MinSupportedVersion:
		return HelloAck{Reason: fmt.Sprintf(
			"agent speaks protocol v%d; this SaaS serves v%d and newer — upgrade the agent on %s",
			h.ProtocolVersion, MinSupportedVersion, h.ClusterID)}
	case h.ProtocolVersion > Version:
		return HelloAck{Reason: fmt.Sprintf(
			"agent speaks protocol v%d; this SaaS speaks up to v%d — the SaaS is behind its agents",
			h.ProtocolVersion, Version)}
	}
	// Serve at the lower of the two, so a newer agent talks down to an older SaaS.
	served := h.ProtocolVersion
	if served > Version {
		served = Version
	}
	return HelloAck{Accepted: true, ProtocolVersion: served}
}

// TargetKind is the class of thing a console or tool channel connects to.
// Adding a kind is an additive change and does not bump Version.
type TargetKind string

const (
	// TargetSSH is a cluster node's own sshd, named by node.
	TargetSSH TargetKind = "ssh"
	// TargetWeb is one of the cluster's own web endpoints, named symbolically.
	TargetWeb TargetKind = "web"
	// TargetTool is a registered read-only tool on the AI plane.
	TargetTool TargetKind = "tool"
)

func (k TargetKind) Valid() bool {
	switch k {
	case TargetSSH, TargetWeb, TargetTool:
		return true
	}
	return false
}

// Target names what a channel should connect to, symbolically.
//
// Name is a label the agent resolves against its own allowlist — a node name, a
// web endpoint name, a tool name. It is deliberately not an address, and
// Validate rejects anything that looks like one. The agent enforces the
// allowlist regardless; this validation exists so the protocol itself cannot
// carry the request in the first place.
type Target struct {
	Kind TargetKind `json:"kind"`
	Name string     `json:"name"`
}

func (t Target) String() string { return string(t.Kind) + ":" + t.Name }

// MaxTargetNameLen bounds a name so a peer cannot use it as a data channel.
const MaxTargetNameLen = 64

// Validate returns nil when the target is a well-formed symbolic reference.
//
// The rules are deliberately narrow — letters, digits, hyphen, underscore, dot,
// and nothing else. That excludes every shape an address can take: ports
// (`host:22`), IPv6 (`[::1]:22`), URLs (`http://…`), credentials (`user@host`),
// paths and globs. A name that survives this cannot be read as a network
// address by any resolver, which is the point.
//
// Dots are allowed because node names are frequently FQDNs. That does mean a
// name can *look* like a hostname — which is fine: the agent still resolves it
// against a local allowlist of known nodes, so "looks like a hostname" and "is
// dialable" remain unrelated.
func (t Target) Validate() error {
	if !t.Kind.Valid() {
		return fmt.Errorf("tunnelproto: unknown target kind %q", t.Kind)
	}
	if t.Name == "" {
		return fmt.Errorf("tunnelproto: target %s has an empty name", t.Kind)
	}
	if len(t.Name) > MaxTargetNameLen {
		return fmt.Errorf("tunnelproto: target name is %d bytes, max is %d", len(t.Name), MaxTargetNameLen)
	}
	for _, r := range t.Name {
		if !isNameRune(r) {
			return fmt.Errorf(
				"tunnelproto: target %s:%s contains %q — targets are symbolic names, not addresses",
				t.Kind, t.Name, r)
		}
	}
	// A name of only dots and digits is an IPv4 literal in every resolver that
	// matters, and no legitimate node name looks like that.
	if isDottedNumeric(t.Name) {
		return fmt.Errorf(
			"tunnelproto: target %s:%s is an address literal — targets are symbolic names",
			t.Kind, t.Name)
	}
	return nil
}

func isNameRune(r rune) bool {
	return r >= 'a' && r <= 'z' ||
		r >= 'A' && r <= 'Z' ||
		r >= '0' && r <= '9' ||
		r == '-' || r == '_' || r == '.'
}

func isDottedNumeric(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return strings.Contains(s, ".")
}

// ChannelOpen asks the agent to open a channel to a symbolic target.
type ChannelOpen struct {
	ID     uint32      `json:"id"`
	Kind   ChannelKind `json:"kind"`
	Target Target      `json:"target"`

	// Approved is the SaaS's claim that a person agreed to this call
	// (ADR 0011's consent dial, amended).
	//
	// A claim, not a proof: it arrives over the tunnel, so a compromised SaaS
	// can set it on a call nobody saw. The action level is the control that
	// survives that, because the agent answers it from its own state. This
	// carries the honest failure instead — a stale mirror or a bug skipping
	// the question — and makes it a refusal the agent audits rather than an
	// unattended call nobody notices.
	//
	// Absent means false, and false is the safe reading: an older SaaS that
	// never sets it has its configuring calls refused by a cluster whose own
	// dial asks for a person, rather than served as though one had. No
	// deployed cluster has a consent file yet, so nothing working today
	// changes.
	//
	// Omitted when false so an unapproved open is byte-identical to what
	// every SaaS sent before the field existed.
	Approved bool `json:"approved,omitempty"`
}

// Validate checks an open request before the agent acts on it. The SaaS is
// never trusted: every field is re-checked agent-side even though the SaaS
// validates before sending.
func (c ChannelOpen) Validate() error {
	if !c.Kind.Valid() {
		return fmt.Errorf("tunnelproto: unknown channel kind %d", uint8(c.Kind))
	}
	if c.Kind == ChannelCtl {
		return fmt.Errorf("tunnelproto: the ctl channel is not opened by request")
	}
	if err := c.Target.Validate(); err != nil {
		return err
	}
	// The two planes are separate by construction: a tool channel can only
	// reach a tool, and a console channel can never reach one. This is what
	// keeps "no free-form shell for the AI" true at the protocol layer rather
	// than by convention in the agent.
	switch c.Kind {
	case ChannelTool:
		if c.Target.Kind != TargetTool {
			return fmt.Errorf("tunnelproto: tool channel may not target %s", c.Target.Kind)
		}
	case ChannelConsole:
		if c.Target.Kind == TargetTool {
			return fmt.Errorf("tunnelproto: console channel may not target a tool")
		}
	}
	return nil
}

// KillSwitch is sent agent→SaaS when the customer disables the agent. The SaaS
// must drop every open channel, including live console sessions.
type KillSwitch struct {
	Reason string `json:"reason,omitempty"`
}
