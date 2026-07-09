# Changelog

All notable changes to Gensee Crate will be documented in this file.

This project follows semantic versioning once stable release lines are
established. During the pre-1.0 period, minor versions may include breaking
changes.

## Unreleased

Use this section for user-visible changes after the initial open-source
release.

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
