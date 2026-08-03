# Changelog

All notable changes to Gensee Crate will be documented in this file.

This project follows semantic versioning once stable release lines are
established. During the pre-1.0 period, minor versions may include breaking
changes.

## Unreleased

Use this section for user-visible changes after the initial open-source
release.

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
