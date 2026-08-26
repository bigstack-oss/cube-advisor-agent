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

## Releases and verification

`mkrelease` builds one binary per architecture and writes `manifest.txt` beside
them — deliberately **unsigned**. The release signing key lives in the SaaS
repository's CI, not in this public one (ADR 0003): a build pipeline that could
also sign is a pipeline that can mint releases.

```sh
go run ./cmd/mkrelease -out dist -version 0.2.0
```

The manifest is sha256sum's own format, with metadata in comment lines that
`sha256sum -c` ignores. That is not incidental — the verifier lives in
**cubecos**, is plain shell, and must be short enough for a reviewer to read in
full:

```sh
openssl dgst -sha256 -verify release.pub -signature manifest.txt.sig manifest.txt
sha256sum -c manifest.txt
```

Two commands, no bespoke parser on the verifying side, because a bespoke parser
written in shell is where the bugs would be. The public key is baked into the
CubeCOS image; this repository is not its source.

The verifier itself is **not** in this repository, and must not be: a verifier
that shares a build pipeline with the artifact it verifies means one compromised
pipeline defeats both.

## Running as a service

`contrib/systemd/cube-advisor-agent.service` runs `cube-advisor-agent run` with
no arguments — enrolment persists the tunnel address, so the unit does not need
one — and restarts it on failure. The OS image installs the unit but enables it
only after `enroll` succeeds; an un-enrolled node has nothing to connect with.
The agent already reconnects with backoff on its own, so the unit's only job is
to keep the process alive.

## Status

Early, but no longer only a protocol. Built and tested: the wire protocol and
its target validation, the multiplexed transport with flow control and
reconnect, the read-only tool plane and its allowlist, the serve loop joining
the two, the enrolled per-cluster identity, and the release manifest.

Not built: the console plane, the daemon that wires the pieces into a running
agent (`cmd/agent` is a stub), and the OS-side verifier — which belongs in
cubecos, not here. Tracked in the private SaaS repo's issues #6 and #7.

## Licence

Apache-2.0.
