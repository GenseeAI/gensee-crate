# Gensee Crate documentation

Local-first runtime security for AI agents. Start with the project
[README](https://github.com/GenseeAI/gensee-crate#readme) for the overview and
quick start, then dive into the topic guides below.

## Guides

- [Architecture](architecture.md) — the v0.1 wedge, workspace crates, and roadmap.
- [`gensee watch` (sidecar)](watch.md) — observe filesystem effects and macOS system events without launching the agent.
- [`gensee run` and the macOS sandbox](run-and-sandbox.md) — managed launch with `sandbox-exec` confinement and staged workspaces.
- [`gensee policy`](gensee-policy.md) — inspect, initialize, validate, and edit local policy settings.
- [Claude Code hooks](claude-code-hooks.md) — wire Claude Code prompts and tool intent into Gensee, and read the combined timeline.
- [Codex hooks](codex-support.md) — wire Codex prompts and tool intent into Gensee, and read the combined timeline.
- [Codex integration](https://github.com/GenseeAI/gensee-crate/tree/main/integrations/codex) — setup commands, hook samples, and smoke-test payloads.
- [Omnigent integration](https://github.com/GenseeAI/gensee-crate/tree/main/integrations/omnigent) — thin `watch`/`run` support and the deeper policy-bridge plan.
- [Safety policy](policy.md) — the data-driven allow/ask/deny policy engine and how to customize it.
- [Dashboard](dashboard.md) — inspect live activity, lineage, policy decisions, alerts, and policy edits.
- [SQLite lineage graph](lineage-graph.md) — the provenance schema, example queries, and what Gensee can flag today.
- [Endpoint Security spike](endpoint-security.md) — `eslogger` system events and the future signed EndpointSecurity path.

## Diagrams

Database design references (rendered by
[`render_database_design.py`](https://github.com/GenseeAI/gensee-crate/blob/main/docs/render_database_design.py)):

- Capture flow — [SVG](gensee_database_capture_flow.svg) · [PNG](gensee_database_capture_flow.png)
- Schema relationships — [SVG](gensee_database_schema_relationships.svg) · [PNG](gensee_database_schema_relationships.png)
- Policy flagging — [SVG](gensee_database_policy_flagging.svg) · [PNG](gensee_database_policy_flagging.png)
- Full design — [PDF](gensee_database_design.pdf)
