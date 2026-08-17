# cube-advisor-agent

The on-cluster agent for the CubeCOS AI Advisor, and the wire protocol it speaks.

## Why this repository is public

The agent runs on customer clusters and holds console access. A component with
that reach should be readable by the people whose clusters it runs on — "open
source" and "shipped in the vendor's image" are independent properties, and this
one is the former without being the latter.

The split is deliberate ([ADR 0003](https://github.com/bigstack-oss/bigstack-handbook/blob/develop/kb/cube-ai-advisor/adrs/0003-signed-agent-artifact-enrolled-by-the-os.md)):

| Repo | Visibility | Owns |
|---|---|---|
| `cubecos` | public | the operator enroll command, **the verifier**, and the release public key baked into the OS image |
| **`cube-advisor-agent`** | **public** | **the agent and `pkg/tunnelproto`; released as signed per-arch artifacts** |
| `cube-ai-advisor` | private | the SaaS — agent loop, prompts, knowledge, tenancy. Imports `pkg/tunnelproto` |

Two consequences worth stating plainly:

- **The verifier lives in `cubecos`, not here.** A verifier must not share a
  build pipeline with the artifact it verifies, or one compromised pipeline
  defeats both.
- **Dependency direction is private → public, never the reverse.** The SaaS
  imports this module. Nothing here may import anything private.

## `pkg/tunnelproto`

The agent dials **outbound only** (wss over 443) and the SaaS multiplexes
channels back over the single stream. No inbound rules, no VPN.

The protocol's central guarantee is what it *cannot* express:

> A channel-open names a **symbolic target** — `ssh:sky141`, `web:dashboard`,
> `tool:cluster_check` — never an address. `Target.Validate` rejects ports, IP
> literals, URLs, credentials, paths and shell metacharacters.

So a compromised or prompt-injected SaaS cannot use the tunnel to reach an
arbitrary host on the customer's network: the request is unrepresentable, not
merely refused. The agent additionally resolves every symbolic target against
its own local allowlist, because the SaaS is never trusted.

The two planes are separated at the protocol layer as well — a `tool` channel
may only target a tool, and a `console` channel may never target one. That is
what makes "the AI has no path to a shell" a structural claim rather than a
convention in the agent's code.

## Status

Early. `pkg/tunnelproto` defines the protocol, version negotiation and target
validation; the agent itself (tool plane, console plane, transport) is not built
yet. Tracked in the private SaaS repo's issue #6.

## Licence

Apache-2.0.
