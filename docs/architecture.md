# Architecture

Gensee Crate is a local-first runtime security layer for AI coding agents. The
current v0.1 release is a macOS-first runtime focused on four workflows:

- `gensee watch` — sidecar audit of workspace effects and macOS system events
  for users who do not want Gensee launching their agent. See [watch.md](watch.md).
- `gensee run` — managed launch of an agent with optional macOS sandbox
  confinement and staged workspace review/discard. See
  [run-and-sandbox.md](run-and-sandbox.md).
- `gensee policy` — inspect the active policy source, initialize
  `$GENSEE_HOME/policy.json`, validate policy files, walk through
  dashboard-style setup, and edit supported configuration keys with `get`/`set`.
  See [policy.md](policy.md).
- `dashboards/web` — local timeline, lineage, policy, and review UI backed by
  the same `GENSEE_HOME` store as the CLI. See [dashboard.md](dashboard.md).

Container mode is future work. `eslogger` is the default `gensee watch`
system-event backend on macOS when available and can be disabled by policy,
while a signed EndpointSecurity client remains a future enrichment. Experimental
Linux host support now includes `/proc` process attribution, capability
planning, a fanotify sensitive-path permission backend, a seccomp launcher
profile for dangerous syscalls, and cgroup/nftables network controls. See
[endpoint-security.md](endpoint-security.md) and [linux.md](linux.md).

## Workspace layout

| Path | Purpose |
| --- | --- |
| `crate/gensee-crate-core` | Platform-agnostic event, session, and cross-session primitives |
| `crate/gensee-crate-attribution` | Agent/session/request/tool attribution graph and correlation evidence |
| `crate/gensee-crate-rules` | Deterministic detection rules and the data-driven [policy engine](policy.md) |
| `crate/gensee-crate-store` | Local storage and migrations |
| `crate/gensee-crate-macos` | macOS EndpointSecurity integration |
| `crate/gensee-crate-linux` | Experimental Linux capability detection, `/proc` monitoring, policy decisions, fanotify enforcement, seccomp launcher profiles, and cgroup/nftables egress controls |
| `crate/gensee-crate-cli` | `gensee` CLI entry point, including run/watch/timeline/policy commands |
| `crate/gensee-crate-ml` | Future v0.2 behavioral model experiments |
| `integrations/claude-code` | Claude Code hook bridge |
| `integrations/codex` | Codex hook bridge |
| `integrations/omnigent` | Thin Omnigent sidecar/managed-launch integration |
| `integrations/vscode` | VS Code/Cursor extension workspace |
| `integrations/mcp` | Optional MCP bridge |
| `integrations/generic-launcher` | `gensee run -- <agent>` launcher integration |
| `models` | Future model artifacts and notes |
| `dashboards/web` | Local dashboard for timeline, lineage, policy, and review workflows |
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
| `$GENSEE_HOME/system-events.jsonl` | Normalized exec/open/create/write/rename/unlink events from `gensee watch` system-event capture or `gensee ingest eslogger` |
| `$GENSEE_HOME/hooks.jsonl` | Agent hook events |
| `$GENSEE_HOME/gensee.db` | Normalized SQLite [lineage graph](lineage-graph.md) |
| `$GENSEE_HOME/gensee.key` | Local store encryption key; keep private and do not share with telemetry snapshots |
| `$GENSEE_HOME/policy.json` | User policy document created by `gensee policy setup` or `gensee policy init` and auto-loaded when `GENSEE_POLICY_FILE` is unset |

Fresh telemetry stores are encrypted at rest by default. Existing plaintext
development stores remain readable rather than breaking hooks; move or remove
the old `GENSEE_HOME` to start a fresh encrypted store. Set
`GENSEE_STORE_ENCRYPTION=0` only for disposable local debugging stores.

## Roadmap / not yet solved

- FSEvents does not prove which process caused a file effect; it is path/time
  correlation only, so "modified outside the agent" drives `ask`, not `deny`.
  EndpointSecurity exec/actor attribution is the planned upgrade.
- `eslogger` gives `gensee watch` useful macOS exec/file system-event context,
  but it is still an interim source. A signed EndpointSecurity client is the
  durable path for production-grade actor attribution and tighter event control.
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
- Linux fanotify can enforce supported sensitive-path marks today, seccomp can
  hard-deny dangerous syscalls for processes launched with
  `gensee linux exec-seccomp`, and cgroup/nftables can scope egress controls to
  an attached agent process tree. The long-running daemon, recursive
  suffix-pattern coverage, eBPF telemetry, Landlock/AppArmor generation, and
  prompt/speculation brokers are still future work.
- Automatic rollback, merge-back review, deny-default policies, and container
  confinement are future work.
