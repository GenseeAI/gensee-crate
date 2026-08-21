# Gensee Crate Personal for macOS

Gensee Crate Personal is a local companion for developers who delegate work to
AI coding agents. It lets agents keep moving without constant supervision,
independently checks what happened on your Mac, and brings you back only when
work drifts beyond the request, verification is missing or stale, or a risky
action needs review.

Instead of another agent transcript, you get one calm review queue across
Codex, Claude Code, Cursor, GitHub Copilot, Antigravity, and Omnigent—with the
original request, commands, files touched, verification evidence, policy
decisions, and a recovery point when one was created. Your activity and policy
stay on your Mac.

**[Download the latest notarized macOS app](https://github.com/GenseeAI/gensee-crate/releases/latest/download/Gensee-Crate.dmg)**

Requires macOS 13 or later.

## Why use Gensee Crate Personal?

- **Supervise less.** Let routine agent work continue while Gensee calls your
  attention to exceptions and outcomes that actually need a decision.
- **Catch scope drift.** Compare an agent's declared tool intent with
  independently observed file activity and highlight changes that do not match.
- **Review work across agents.** See completed Codex, Claude Code, Cursor,
  GitHub Copilot, Antigravity, and Omnigent work in one queue.
- **Recover from risky changes.** Create a Git-backed recovery point before the
  first risky or mutating action in a request, then restore it from the review.
- **Check what can influence an agent.** Audit instructions, skills, MCP
  servers, hooks, permissions, plugins, and command rules without executing
  them.
- **Keep evidence local.** Gensee runs on your Mac and does not require a cloud
  account or a separate developer toolchain.

## Get started

1. **Download and install.** Open the disk image and move **Gensee Crate.app**
   to `/Applications`.
2. **Try the demo.** Explore realistic synthetic activity without installing
   hooks, changing policy, creating a database, or requesting Apple permissions.
3. **Run the setup assistant.** Gensee prepares its local backend and encrypted
   event store, scans installed coding agents, and explains each optional step.
4. **Enable the agents you use.** Choose **Enable Protection** for an installed
   harness. Gensee preserves unrelated hooks and settings.
5. **Restart or reload the agent when prompted.** Codex also asks you to review
   and trust the Gensee hook commands. An integration becomes **Protected**
   only after a real event reaches the local store.
6. **Add independent Mac verification when you are ready.** The setup assistant
   guides you through the optional system extension and Full Disk Access
   approvals.

You can rerun the assistant at any time from **Settings → Run Setup
Assistant**.

## What you will use day to day

### Review Queue

The Review Queue groups work by agent session and request. Each review connects
the original task to elapsed time, tool calls, commands, files touched, grouped
findings, and observed verification commands.

Gensee keeps clean completions quiet. It can notify you when it detects:

- changes outside the agent's declared intent;
- a blocked or high-risk operation;
- verification that failed or became stale after another file change;
- incomplete Endpoint Security evidence; or
- a request that otherwise needs a human decision.

Open a request to inspect its timeline, findings, and files. When a recovery
point exists, the same review provides the Restore action.

### Smart recovery points

Each supported harness has three recovery modes:

- **Auto** — create one recovery point before the first risky or mutating tool
  call in a request. This is the recommended default.
- **Ask** — pause supported hook flows and ask before creating the point.
- **Off** — never create a recovery point automatically.

Recovery points use the repository's local Git object database without moving
your branch, creating a normal commit, or changing the staging area. Before a
restore, Gensee creates a rescue point of the current workspace.

Recovery points cover tracked files and untracked, non-ignored files in the
selected Git workspace. They cannot undo database changes, network requests,
remote repository actions, running processes, ignored files, nested
repositories, or files outside that workspace.

### Configuration Audit

Open **Harnesses** and choose **Audit Config** for Codex or GitHub Copilot.
Gensee performs a read-only review of the configuration that can change agent
behavior, including:

- instruction and skill files;
- MCP servers and plugins;
- hooks and permissions;
- command approval rules; and
- the sources that contributed to the final configuration.

Findings include evidence and a recommended action. The next audit compares
against the saved local baseline so you can focus on new and resolved drift.
Audits for additional harnesses are marked **Coming soon**.

### Daily Highlight and Watchlist

**Daily Highlight** summarizes today's agent turns, tool calls, alerts, and
compatible token totals, with rolling 53-week activity views.

**Watchlist** keeps persistent or sensitive files visible across sessions, so
you can investigate repeated access or changes without searching individual
agent histories.

## Optional Mac protection

Gensee provides useful features before you grant broad system access. Hook-based
reviews, smart recovery points, and Configuration Audit work without Full Disk
Access.

For independent verification, Gensee can install its signed Endpoint Security
system extension. This lets the app observe supported process and file activity
at the operating-system level, correlate it with active agent requests, and
detect effects that bypass or fall outside normal harness hooks.

macOS requires you to approve the extension and Full Disk Access yourself;
Gensee cannot silently grant either permission. You can start in observation
mode, confirm that evidence is arriving, and enable stronger protection later.
Unrelated applications remain outside Gensee's enforcement scope.

## Protection levels

- **Fast** — keeps agents moving and stops only clearly dangerous actions.
- **Review** — asks before broad or sensitive changes and enables configured OS
  enforcement.
- **Sensitive** — uses a stricter, fail-closed posture for managed agent work.

Use **Policy** when you want to customize the underlying decision rules,
protected paths, blocked executables, recording level, or retention. The same
local policy is used by the app, hooks, and embedded backend.

## Supported agents

| Agent | Protection | Configuration Audit |
| --- | --- | --- |
| Codex | Direct Gensee hooks | Available |
| Claude Code | Direct Gensee hooks | Coming soon |
| Antigravity | Direct Gensee hooks | Coming soon |
| Cursor | Direct Gensee hooks | Coming soon |
| GitHub Copilot in VS Code | VS Code agent hooks | Available |
| Omnigent | Gensee-managed launch | Coming soon |

An installed direct-hook agent can be enabled, disabled, scanned, and repaired
from **Harnesses**. If an integration points to an old backend or event store,
or is missing a required hook, Gensee shows **Needs repair** instead of claiming
that it is protected.

Omnigent currently requires a Gensee-managed launch because it does not expose
the same direct hook integration as the other supported agents.

## Local data and privacy

- Activity, policy, recovery metadata, audit baselines, and review feedback stay
  in the local Gensee store under `~/.gensee`.
- The app includes its own backend and SQLite support. It does not require
  Homebrew, Rust, Xcode, `jq`, or a separate SQLite installation.
- Full model responses and full tool output are not copied into periodic
  dashboard snapshots.
- Compatible Codex and Claude Code integrations store numeric per-turn token
  totals for activity summaries; they do not copy transcript content into that
  aggregate.
- Recording severity, raw-event scope, retention, and row limits are editable
  under **Policy**.

## Help

- [Read the macOS user guide](../../docs/macos-app.md)
- [Join the GenseeAI Discord](https://www.gensee.ai/discord)
- [Report a problem](https://github.com/GenseeAI/gensee-crate/issues)
