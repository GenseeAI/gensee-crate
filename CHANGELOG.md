# Changelog

All notable changes to Gensee Crate will be documented in this file.

This project follows semantic versioning once stable release lines are
established. During the pre-1.0 period, minor versions may include breaking
changes.

## Unreleased

Use this section for user-visible changes after the initial open-source
release.

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
