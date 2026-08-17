## What

<one-line summary>

## Why

<the problem this solves; link the blueprint section if design-relevant>

## Checklist

- [ ] Branch is rebased on `develop` (fast-forward only — merge happens via the `done` label workflow, don't click the button)

- [ ] Agent-side invariants untouched or strengthened: symbolic targets only (the protocol cannot name an address), tool and console planes cannot cross, and the agent re-validates everything the SaaS sends
- [ ] `go vet ./...` and `go test ./...` pass, including the `GOMAXPROCS=1` race pass — concurrency bugs here hide on multi-core machines
- [ ] No dependency on anything private: this module is imported by the SaaS, never the reverse (ADR 0003)
