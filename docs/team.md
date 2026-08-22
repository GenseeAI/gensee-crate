# Gensee Crate Team

Gensee Crate Team is the self-hosted path for small teams and businesses that
operate coding agents on prepared remote Linux hosts. The team keeps control of
its source, policy, credentials, runtime, evidence, and lifecycle decisions.

The goal is not merely to record what an agent did. It is to decide what
authority the work receives, execute risky operations inside a bounded and
inspectable environment, and require evidence before results become durable.

```text
intent
  → capability decision
  → lease, mediator, cell, or workspace fork
  → observed effects
  → merge, promote, or discard
  → revocation and cleanup
```

## What Team adds

- **Transactional workspace forks.** `tclone` creates low-latency,
  whole-workspace forks for one or several approaches. A human can inspect and
  test each result before merging, promoting, or discarding it.
- **Bounded authority.** Request-scoped capability decisions and short-lived
  leases limit filesystem, network, repository, workload-identity, database,
  and external-action authority.
- **Host-owned credentials.** The capability broker gives isolated cells opaque
  lease IDs, scoped handles, or trusted gateway endpoints instead of broad
  credentials.
- **Independent evidence.** Host observation, process lineage, effect manifests,
  replay plans, promotion receipts, and cleanup journals explain what occurred
  and whether it stayed within the granted authority.
- **Evidence-gated persistence.** Manifest violations, failed cleanup, expired
  authority, incomplete evidence, or missing commit tokens can prevent work
  from becoming durable.

The strongest end-to-end enforcement today is in tclone capability cells and
network mediation. Additional capability adapters are under active development;
see the [roadmap](roadmap.md) for the current boundary.

## Install on a Linux host

Install Gensee Crate:

```bash
curl -fsSL https://raw.githubusercontent.com/GenseeAI/gensee-crate/main/scripts/install_oss.sh | bash
export GENSEE_HOME="${GENSEE_HOME:-$HOME/.gensee}"
```

Then prepare the host with the tclone-enabled
[`os4agent`](https://github.com/GenseeAI/os4agent) runtime, rootful Podman using
the `btrfs` storage driver, and a tclone image. The exact storage, wrapper, and
host checks are documented in [Tclone runtime integration](tclone.md).

## Run and fork agent work

Start the source agent in the prepared runtime:

```bash
gensee-tclone run --runtime tclone -- codex
```

Create parallel approaches from another terminal:

```bash
gensee-tclone run list --json

gensee-tclone run fork <source-run-id> \
  --copies 2 \
  --name try-upgrade \
  --approach 'minimal compatible upgrade' \
  --approach 'aggressive latest-version upgrade' \
  --attach tmux:right \
  --json
```

## Examine results and decide what persists

```bash
gensee-tclone run summary <fork-id> --json
gensee-tclone run diff <fork-id> --json
gensee-tclone run compare <parallel-fork-id> --json

# After an explicit human decision:
gensee-tclone run choose <parallel-fork-id> --merge
# or: --promote
# or: --discard-all
```

Use `gensee timeline`, `gensee status --json`, and the local
[dashboard](dashboard.md) to examine policy decisions, runtime evidence,
effects, cleanup, and promotion outcomes.

## Continue with the control plane

- [Tclone runtime integration](tclone.md) — host preparation, forks, compare,
  merge, promotion, and cleanup.
- [Capability broker](capability-broker.md) — short-lived leases, host-owned
  credentials, mediated gateways, commit tokens, and signed evidence.
- [Linux host support](linux.md) — process attribution, fanotify, seccomp,
  cgroups, and nftables controls.
- [Safety policy](policy.md) — deterministic decisions shared across local and
  remote deployments.
- [Architecture](architecture.md) — workspace components, data model, and
  current security boundaries.
