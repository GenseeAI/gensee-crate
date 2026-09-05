# Gensee Crate documentation

Gensee Crate is an open-source control layer for AI coding agents. Start with
[Gensee Crate Personal](personal.md) for local laptop protection and review, or
[Gensee Crate Team](team.md) for self-hosted remote Linux agent environments.

## Guides

- [Generic operation boundary](operation-boundary.md) — admit arbitrary commands before execution, bind an OS-observed execution subject, enforce an outbound-network envelope, and structurally gate staged products without claiming semantic safety.
- [Approved contract catalogs](contract-catalog.md) — sign organization-owned, versioned operation contracts and exact caller/class selectors so an untrusted workload cannot choose a more permissive envelope.
- [Generic capability providers](generic-capability-providers.md) — use typed scopes and one crash-safe lease lifecycle for credential, protocol, filesystem, and control-plane mediators.
- [Boundary extension authoring](boundary-extension-authoring.md) — add organization contracts, external intent analyzers, isolated semantic verifiers, and operational capability providers through stable, bounded protocols.
- [Distributed operation context](operation-context.md) — authenticate service hops, deadlines, generations, attenuated grant sets, and downstream effects back to the initiating operation.
- [Semantic-verifier receipts](semantic-verifier.md) — bind a catalog-approved verifier and policy version to the exact structural product, contract, verdict, and validation-effect digest.
- [Transactional promotion](transactional-promotion.md) — require unchanged structural evidence, an authenticated semantic verdict, terminal authority, compare-and-swap selection, and crash-safe rollback.
- [Privileged generic boundary proof](generic-boundary-proof.md) — run one domain-neutral Linux conformance scenario and independently verify its signed evidence bundle.
- [Generic end-to-end boundary demo](generic-end-to-end-demo.md) — start with operator-owned contract setup, then run one denied operation and one verified-and-promoted operation.
- [Gensee Crate Personal](personal.md) — local review, recovery points, configuration audit, and optional independent macOS verification.
- [Gensee Crate Team](team.md) — disposable workspace forks, scoped capabilities, host-owned credentials, and evidence-gated promotion.
- [Architecture](architecture.md) — shared policy and evidence model, workspace crates, and security boundaries.
- [Roadmap](roadmap.md) — current host controls and planned sandbox, sensor, ML policy, and integration work.
- [Linux host support](linux.md) — `/proc` process attribution, fanotify sensitive-path enforcement, seccomp launcher profiles, cgroup/nftables egress controls, and Linux capability planning.
- [Tclone runtime integration](tclone.md) — launch agents in cloneable Linux containers, fork live source containers, inspect diffs, keep workspaces, and discard forks.
- [Authenticated telemetry replay](replay.md) — merge heterogeneous evidence with explicit clock semantics, verify signed replay bundles, and evaluate bounded causal rules.
- [Operation network boundary](operation-network-boundary.md) — operation-scoped network envelopes, temporary in-place leases, a read-only HTTP mediator, revocation, and effect evidence.
- [Operation supervisor](operation-supervisor.md) — durable operation identity, lifecycle, process lineage, cgroup ownership, active envelopes, leases, and boundary-effect coordination.
- [Capability faults](capability-faults.md) — typed black-box boundary observations, subject binding, fail-closed backend routing, retry-after-lease semantics, and network counter evidence.
- [`gensee watch` (sidecar)](watch.md) — observe filesystem effects and macOS system events without launching the agent.
- [`gensee run` and the macOS sandbox](run-and-sandbox.md) — managed launch with `sandbox-exec` confinement and staged workspaces.
- [`gensee policy`](gensee-policy.md) — inspect, initialize, validate, and edit local policy settings.
- [`gensee audit`](config-audit.md) — statically review Codex and VS Code agent permissions, privacy, MCP, skills, hooks, extensions, rules, and instructions.
- [Claude Code hooks](claude-code-hooks.md) — wire Claude Code prompts and tool intent into Gensee, and read the combined timeline.
- [Claude Cowork endpoint visibility](https://github.com/GenseeAI/gensee-crate/tree/main/integrations/claude-cowork) — macOS pilot contract, local audit adapter, execution-origin labels, and explicit VM/cloud limitations.
- [Codex hooks](codex-support.md) — wire Codex prompts and tool intent into Gensee, and read the combined timeline.
- [Codex integration](https://github.com/GenseeAI/gensee-crate/tree/main/integrations/codex) — setup commands, hook samples, and smoke-test payloads.
- [Antigravity support](antigravity-support.md) — global hook setup, `.agents` policy coverage, and sidecar audit.
- [VS Code / GitHub Copilot hooks](vscode-support.md) — configure VS Code agent hooks, native tool parsing, and policy enforcement.
- [Cursor hooks](cursor-support.md) — native hook setup, enforcement behavior, and runtime verification.
- [Omnigent integration](https://github.com/GenseeAI/gensee-crate/tree/main/integrations/omnigent) — thin `watch`/`run` support and the deeper policy-bridge plan.
- [Safety policy](policy.md) — the data-driven allow/ask/deny policy engine and how to customize it.
- [Dashboard](dashboard.md) — run the cross-platform React/Tauri inspector for activity, lineage, policy, and transactions.
- [Gensee Crate Personal for macOS](macos-app.md) — install the app, connect harnesses, review work, create recovery points, audit configuration, and add optional Endpoint Security verification.
- [SQLite lineage graph](lineage-graph.md) — the provenance schema, example queries, and what Gensee can flag today.
- [Endpoint Security sensor](endpoint-security.md) — signed macOS process/file observation and managed-tree authorization.

## Diagrams

Database design references (rendered by
[`render_database_design.py`](https://github.com/GenseeAI/gensee-crate/blob/main/docs/render_database_design.py)):

- Capture flow — [SVG](gensee_database_capture_flow.svg) · [PNG](gensee_database_capture_flow.png)
- Schema relationships — [SVG](gensee_database_schema_relationships.svg) · [PNG](gensee_database_schema_relationships.png)
- Policy flagging — [SVG](gensee_database_policy_flagging.svg) · [PNG](gensee_database_policy_flagging.png)
- Full design — [PDF](gensee_database_design.pdf)
