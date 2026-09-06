# Changelog

All notable changes to Gensee Crate will be documented in this file.

This project follows semantic versioning once stable release lines are
established. During the pre-1.0 period, minor versions may include breaking
changes.

## Unreleased

Use this section for user-visible changes after the initial open-source
release.

### Added

- Added a macOS-first Claude Cowork endpoint-visibility adapter with explicit
  `host-native`, `vm-mediated`, `cloud-mediated`, and `unattributed` execution
  origins, opt-in signed process-tree management, local audit ingestion,
  VM/cloud limitation evidence, and timeline labels.

### Changed

- NotebookRead and NotebookEdit hooks now receive the same active path-policy
  enforcement as other file-reading and file-editing tools.

## 0.3.1 - 2026-08-21

### Changed

- Added Settings and Quit commands to the menu-bar app so users can open the
  configuration screen directly or stop Gensee Crate completely.
- Setup now opens harness hook approval only after configuration succeeds and
  provides visible manual guidance when macOS cannot open the required System
  Settings pane automatically.

### Fixed

- Fixed large requests timing out while loading complete request evidence in
  Review Queue.
- Fixed setup audit results that reported findings without a way to inspect
  them.
- Fixed acknowledged Endpoint Security evidence-gap warnings resurfacing after
  reconnects because volatile ring-buffer measurements changed.

## 0.3.0 - 2026-08-20

### Added

- Added a developer-focused Review Queue that groups completed agent work by
  harness, session, and request, with request-scoped timelines, findings, file
  touches, test evidence, elapsed time, and decisions in one place.
- Added smart Git-backed recovery points with per-harness Auto, Ask, and Off
  modes, one recovery point before the first risky mutation, safe restore with
  a rescue point, and configurable retention and failure behavior.
- Added actionable native and menu-bar notifications for work that needs
  attention across Codex, Claude Code, Cursor, and other supported harnesses.
- Added a realistic, read-only product demo that stays active while navigating
  the app and does not modify the Mac.

### Changed

- Reworked the macOS app around outcomes that require a developer decision:
  scope drift, stale verification, blocked actions, and high-risk activity.
- Request details now load complete evidence by request ID instead of relying
  on bounded dashboard snapshots; answer-only turns show a clear lifecycle
  rather than an empty timeline.
- File activity now distinguishes declared and OS-verified mutations,
  undeclared effects, and ignored harness or temporary bookkeeping.
- Simplified navigation, review actions, findings grouping, search, loading
  feedback, configuration-audit presentation, and harness readiness states.

### Fixed

- Hardened recovery-point locking, cleanup, relocation, retention, and restore
  behavior while preserving the active branch, index, and ignored files.
- Fixed stale or missing request details, duplicate audit findings, file-touch
  attribution gaps, notification delivery, menu-bar deep links, dashboard
  refresh recovery, and Rust stable-channel lint compatibility.

## 0.2.0 - 2026-07-21

### Added

- Added the tclone transactional runtime for prepared Linux hosts, including
  managed source containers, live process-tree forks, tmux pane attachment,
  non-interactive execution and prompt handoff, machine-readable status/diff/
  summary output, and git or filesystem merges.
- Added Codex-mediated fork completion: Codex summarizes changed files and test
  results, asks whether to merge, promote, or discard, and runs the approved
  lifecycle command internally. Filesystem merges are transactional and roll
  back the source if application fails.
- Added named parallel fork groups with distinct approaches, right-stacked tmux
  panes, result comparison and recommendation, and approval-gated winner
  selection that discards sibling forks.
- Added a native React + Tauri dashboard with activity and severity charts,
  tool-call timelines, alerts, sessions, feedback, lineage, policy editing,
  live updates, and a transaction dependency/history view for tclone lifecycle
  events.
- Added native VS Code / GitHub Copilot and Cursor hook integrations, setup
  commands, policy normalization, schema-drift telemetry, installer onboarding,
  and documentation.
- Added `scripts/cleanup_tclone_host.sh` to reclaim Gensee-owned tclone state,
  optionally prune host-wide Podman data, clean Cargo artifacts, rebuild the
  release CLI, and reinstall it without deleting the tagged tclone image by
  default.

### Changed

- Hook setup now preserves unrelated user commands, updates only Gensee-owned
  entries, writes atomically, keeps configuration symlinks intact, and avoids
  unnecessary backups when nothing changed.
- Tclone workflows now keep source and fork work visible in tmux, automatically
  continue approved work in the fork, return lifecycle decisions to the source
  Codex session, and clean up resolved fork containers and panes.
- The dashboard records bounded, append-only transaction lifecycle telemetry
  without blocking the underlying tclone operation, and retains provenance for
  deleted environments.
- Refreshed the dashboard documentation and capability screenshots for the
  activity, timeline, lineage, and transaction views.

### Fixed

- Suppressed duplicate compatibility-hook processing when Cursor or VS Code
  imports Claude-compatible hooks alongside a verified native Gensee hook,
  while preserving fail-closed fallback behavior when detection is uncertain.
- Hardened tclone host-control routing, async fork status, source handoff,
  process reaping, readiness and quiet-state checks, environment preservation,
  fork-name collisions, merge isolation, approval expiry, rollback, and cleanup.
- Fixed tmux attachment and source reattachment behavior, recursive fork
  suggestions, repeated fork scheduling, and stale lifecycle artifacts.

## 0.1.1 - 2026-07-09

### Added

- Added Antigravity support: setup command, hook integration, daemon responses,
  installer wiring, and docs.
- Added Linux host support for direct agent process trees, including
  capability reporting, `/proc` process attribution, top-level `watch --pid`,
  and Linux-specific setup/docs.
- Added Linux system enforcement layers:
  - fanotify sensitive-path enforcement for `gensee run` and
    `gensee watch --pid`, including configurable `linux.fanotify.paths`
  - seccomp launcher profiles for dangerous syscall families
  - cgroup v2 + nftables network allow/deny enforcement and blocked-network
    timeline events
- Added Linux policy modeling for enforcement posture, per-rule `Speculate`,
  speculation backend reporting, network policy, seccomp policy, and
  fanotify-sensitive paths.
- Added Linux release documentation, roadmap updates, README platform copy, and
  debug/admin commands for Linux enforcement planning.

### Changed

- Promoted Linux from experimental README positioning to a supported native host
  target alongside macOS.
- Updated timeline behavior so managed `gensee run` sessions and Linux
  system-level file/network events show up correctly under `timeline --latest`.
- Improved Linux privilege and sudo/PATH guidance for Node/npm-installed agents
  such as Codex and Claude Code.

### Fixed

- Hardened fanotify listener startup, import/build issues, response handling,
  exec-open marks, and first-poll process monitoring behavior.
- Fixed Linux clippy issues and policy/default conversion drift in the new
  Linux support path.

## 0.1.0

Initial open-source release.

- Added the `gensee` CLI with local hooks, timeline, watch, run, policy, and
  feedback commands.
- Added Claude Code and Codex hook setup and enforcement.
- Added policy evaluation for sensitive reads, destructive operations,
  out-of-workspace writes, network egress, persistence writes, memory/skill
  poisoning, and related agent-risk patterns.
- Added a local SQLite/JSONL store, lineage tracking, tamper-evident alert
  chain, at-rest telemetry encryption, and dashboard.
- Added macOS-first installer and sandbox/watch workflows.
