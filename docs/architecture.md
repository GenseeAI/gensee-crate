# Architecture

Gensee Crate is an open-source control layer for AI coding agents. It has two
deployment paths built on the same deterministic policy and evidence model:

- **[Gensee Crate Personal](personal.md)** reviews local agent work, creates
  recovery points, audits configuration, and can independently verify supported
  process and file activity on macOS.
- **[Gensee Crate Team](team.md)** runs agents on prepared Linux hosts with
  disposable workspace forks, scoped capabilities, short-lived leases,
  host-owned credentials, and evidence-gated promotion.

The current implementation exposes these core workflows:

- `gensee watch` — sidecar audit of workspace effects and macOS system events
  for users who do not want Gensee launching their agent. See [watch.md](watch.md).
- `gensee run` — managed launch of an agent with optional macOS sandbox
  confinement and staged workspace review/discard. See
  [run-and-sandbox.md](run-and-sandbox.md).
- `gensee run --runtime tclone` — launch, fork, compare, merge, promote, or
  discard live agent environments on prepared Linux tclone hosts. See
  [tclone.md](tclone.md).
- `gensee policy` — inspect the active policy source, initialize
  `$GENSEE_HOME/policy.json`, validate policy files, walk through
  dashboard-style setup, and edit supported configuration keys with `get`/`set`.
  See [policy.md](policy.md).
- `dashboards/` — the React + Tauri evidence inspector backed by the same
  `GENSEE_HOME` store as the CLI. See
  [dashboard.md](dashboard.md).
- `macos/GenseeCrate` — the Gensee Crate Personal SwiftUI app for request
  review, recovery points, Config Audit, the signed Endpoint Security
  extension, sensor policy, and installed harness protection. It
  embeds the monorepo's `gensee` CLI rather than implementing a separate
  backend. See [macos-app.md](macos-app.md).

The tclone container runtime is available on prepared Linux hosts. The signed
Gensee Endpoint Security system extension is the default macOS system-event
backend; `eslogger` remains only a manual compatibility path. Linux host support
includes `/proc` process attribution, capability planning, fanotify
sensitive-path enforcement, seccomp launcher profiles for dangerous syscalls,
and cgroup/nftables network controls. See
[endpoint-security.md](endpoint-security.md), [linux.md](linux.md), and
[tclone.md](tclone.md).

## Workspace layout

| Path | Purpose |
| --- | --- |
| `crate/gensee-crate-core` | Platform-agnostic event, session, and cross-session primitives |
| `crate/gensee-crate-attribution` | Agent/session/request/tool attribution graph and correlation evidence |
| `crate/gensee-crate-rules` | Deterministic detection rules and the data-driven [policy engine](policy.md) |
| `crate/gensee-crate-store` | Local storage and migrations |
| `crate/gensee-crate-macos` | macOS EndpointSecurity integration |
| `macos/GenseeCrate` | Native Swift security console and signed Endpoint Security system extension |
| `crate/gensee-crate-linux` | Experimental Linux capability detection, `/proc` monitoring, policy decisions, fanotify planning/debug probes, seccomp launcher profiles, and cgroup/nftables egress controls |
| `crate/gensee-crate-cli` | `gensee` CLI entry point, including run/watch/timeline/policy commands |
| `crate/gensee-crate-config-audit` | Static, read-only coding-agent configuration inventory and security/privacy rules; Codex is the first adapter |
| `crate/gensee-crate-ml` | Behavioral model experiments |
| `integrations/claude-code` | Claude Code hook bridge |
| `integrations/codex` | Codex hook bridge |
| `integrations/omnigent` | Thin Omnigent sidecar/managed-launch integration |
| `integrations/vscode` | VS Code / GitHub Copilot hook bridge and setup guide |
| `integrations/cursor` | Cursor native hook bridge |
| `integrations/mcp` | Optional MCP bridge |
| `integrations/generic-launcher` | `gensee run -- <agent>` launcher integration |
| `models` | Future model artifacts and notes |
| `dashboards` | Native dashboard for timeline, lineage, policy, transactions, and review workflows (React + Vite + Tauri) |
| `scripts` | Local development and benchmark helpers |
| `docs` | This documentation |

## Local data

Gensee writes its local state under `~/.gensee/` by default. Set `GENSEE_HOME`
to override the data directory for development or managed deployments — use the
same `GENSEE_HOME` for `watch`, hooks, and `timeline` when you want the signals
to appear together.

| File | Contents |
| --- | --- |
| `$GENSEE_HOME/sessions.jsonl` | Local run records from `gensee run` |
| `$GENSEE_HOME/workspace-effects.jsonl` | Filesystem effects observed by `gensee watch` |
| `$GENSEE_HOME/system-events.jsonl` | Normalized process/file/auth events from the signed Endpoint Security sensor (or manual `gensee ingest eslogger`) |
| `$GENSEE_HOME/hooks.jsonl` | Agent hook events |
| `$GENSEE_HOME/gensee.db` | Normalized SQLite [lineage graph](lineage-graph.md) |
| `$GENSEE_HOME/gensee.key` | Local store encryption key; keep private and do not share with telemetry snapshots |
| `$GENSEE_HOME/policy.json` | User policy document created by `gensee policy setup` or `gensee policy init` and auto-loaded when `GENSEE_POLICY_FILE` is unset |

Fresh telemetry stores are encrypted at rest by default. Existing plaintext
development stores remain readable rather than breaking hooks; move or remove
the old `GENSEE_HOME` to start a fresh encrypted store. Set
`GENSEE_STORE_ENCRYPTION=0` only for disposable local debugging stores.

## Roadmap / not yet solved

- FSEvents remains path/time reconciliation only. Endpoint Security now supplies
  exact process identities and actor attribution for supported process/file
  events; unobserved operations and packet-level network activity remain gaps.
- Hook enforcement is deterministic and path/tool based; it does not yet use
  semantic prompt analysis.
- Content rules and the executable resolver are deterministic and best-effort —
  an evadable floor for obscure `eval`/subshell forms and content obfuscation.
- Network egress lineage is detected from hook/tool intent today, not from a
  system-level packet sensor. Full IP egress/ingress capture on macOS needs a
  Network Extension, packet filter, or similar privileged network sensor, plus
  process attribution back to agent sessions.
- Resource governance is enforced in the hook path for read sizes, fan-out,
  session tool/network quotas, proxy-required egress, and host allowlists. CPU
  and memory hard limits still need OS/container enforcement.
- Prompt injection, malicious tool output, exfiltration, and cross-session
  attack chains can be surfaced as graph patterns, but the defense rules are
  still early and mostly deterministic.
- Linux fanotify can arm supported sensitive-path marks from
  `gensee run --sandbox linux --linux-fanotify` or
  `gensee watch --pid <pid> --linux-fanotify`; seccomp can hard-deny dangerous
  syscalls for processes launched with `gensee run --sandbox linux`, and
  cgroup/nftables can scope egress controls to an attached agent process tree or
  to policy-managed Linux runs. The long-running daemon, recursive
  suffix-pattern coverage, eBPF telemetry, Landlock/AppArmor generation, and
  prompt/speculation brokers are still future work.
- Recovery points and tclone merge/promote/discard workflows are available.
  Broader automatic rollback for databases, remote actions, ignored files, and
  effects outside a selected workspace remains future work.
