# Roadmap

Gensee Crate supports macOS and Linux today, with Claude Code, Codex,
Antigravity, and VS Code / GitHub Copilot hook support, local policy
enforcement, staged workspace runs, local telemetry, and a browser dashboard.
Linux host support includes `/proc` process attribution, capability planning,
fanotify sensitive-path enforcement, seccomp launcher profiles, and
cgroup-scoped nftables egress controls. This roadmap is directional and may
change as agent interfaces and operating-system controls evolve.

## Linux System Enforcement

Gensee Crate's Linux support will focus on agents running directly on developer
machines, not only inside containers.

Available now:

- Process-tree attribution for Claude Code, Codex, Omnigent, and other local
  agents through `/proc`.
- Host capability reporting through `gensee status`.
- Sidecar attachment for existing Linux agent process trees through
  `gensee watch --pid <pid>`.
- Fanotify permission enforcement for `gensee run` and `gensee watch --pid`,
  with built-in credential-path rules and configurable `linux.fanotify.paths`
  for exact paths and prefix roots such as `~/.ssh/**`.
- Seccomp launcher profiles configured through policy and applied by
  `gensee run --sandbox linux -- <agent>` to hard-deny dangerous syscall
  families such as `ptrace`, `bpf`, kernel module loading, mount changes, and
  namespace switching.
- Cgroup/nftables egress controls through the preferred
  `gensee run --sandbox linux -- <agent>` launch workflow, scoped to a cgroup
  v2 agent process tree and policy-managed IP/CIDR allowlists, denylists, or
  deny-all mode. Low-level planning/apply commands live under `gensee debug`.

Planned work includes:

- Linux-native eBPF file, process, and network monitoring.
- Continuous fanotify ownership in a daemon, so sensitive-path permission events
  can survive policy reloads and multi-agent session lifecycle beyond the
  current `run` and `watch --pid` listeners.
- Recursive suffix-pattern coverage for rules such as `**/.env` and
  `**/.env.*`.
- Landlock and AppArmor profile generation where those systems are available.
- Richer audit trails that connect agent intent, child PID attribution,
  per-attempt network timestamps, file access, and policy decisions.

## Endpoint Security-Based Defense

On macOS, deeper system-level enforcement requires Apple's Endpoint Security
entitlement. GenseeAI is pursuing this path so Gensee Crate can move beyond
sidecar observation and sandboxed launches toward stronger host-level defense.

Planned work includes:

- Endpoint Security-based file, process, and network visibility on macOS.
- Stronger correlation between agent tool calls and OS-level events.
- Detection of bypass attempts that happen outside the agent's normal hook path.
- Policy enforcement that can complement agent hooks and sandboxed runs.

## Sandbox Support

Gensee Crate will continue improving sandboxed and staged execution for risky
agent actions.

Planned work includes:

- Stronger `gensee run` confinement for local agents.
- Reviewable staged workspace writes before changes reach the real project.
- Policy-aware sandbox modes for file access, network access, and command
  execution.
- Transactional or speculative execution experiments for coding-agent workflows,
  where risky actions can be evaluated before their effects are committed.
- Better support for managed Linux runtimes and cloud-based agent workspaces.

## ML-Based Policy and Rules

Current policy decisions are deterministic and rule-based. Future versions may
use ML-assisted policy to improve detection, reduce noise, and adapt to new
agent behaviors.

Planned work includes:

- Learning from controlled traces of policy decisions, blocked actions, and
  bypass attempts.
- Detecting retry patterns, tool substitution, path substitution, encoding
  tricks, delayed execution, and exfiltration-like behavior.
- Policy recommendations based on observed project and agent behavior.
- Optional ML-assisted risk scoring alongside deterministic rules.
- Evaluation datasets for comparing rule-only and ML-assisted defenses.

## Integrations

Gensee Crate aims to work with the agent and security tools developers already
use.

Planned integration areas include:

- Additional coding agents and assistants such as ChatGPT and Gemini. Cursor
  and GitHub Copilot hook support are available today.
- Agent orchestration frameworks such as Omnigent.
- Security tooling such as CrowdStrike and other endpoint or detection systems.
- LLM gateways, MCP servers, and policy/control-plane tools.
- Export formats for sharing local audit trails, alerts, and policy decisions
  with external systems.
