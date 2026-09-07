# What’s new

This page describes merged functionality through **v0.3.3**. Download the
[latest notarized macOS app](https://www.gensee.ai/download/crate-macos.html?placement=docs-whats-new)
or read the [complete changelog](https://github.com/GenseeAI/gensee-crate/blob/main/CHANGELOG.md).

## v0.3.3 — quieter reviews and clearer approvals

- Routine workspace writes, temporary files, regular-file renames, and identified
  Claude, Xcode, Git, and Cargo housekeeping create fewer generic warnings.
  A missing hook-level file intent is not, by itself, a workspace violation.
  Protected paths, symlink escapes, unsafe directory moves, broad destructive
  operations, and blocked actions retain their protections.
- Background completions group under their originating requests when the evidence
  supports attribution. Historical evidence remains intact.
- Findings show one status: **Blocked**, **Approval requested**, **Warning**, or
  **Allowed**. Expanded details retain severity and the original policy response.
- Exact matching approvals can last for one action, one session, or one project.
  **This was a false positive** records feedback; **Always allow matching reads…**
  creates an explicit file/folder exception. Neither silently changes a whole rule.
- Credential-content findings describe possible credentials, not proof that a
  credential is live. Executable inspection resolves leading shell `cd` paths;
  approval previews explain unsupported or unavailable context in the sheet.
- Large histories use bounded refreshes and indexed classifications. Cowork is
  included in installed counts and the combined **Protected** summary.
- Monitoring gaps belong to Gensee health, not agent wrongdoing. Sensor callbacks
  do less work for unrelated traffic, and diagnostics separate callback pressure,
  replay-buffer loss, and ingestion backlog. Reconnect interrupts pending XPC waits
  and retry delays; event/configuration calls have five-second deadlines.

See [Review Queue and approvals](review-queue-approvals.md),
[feedback and read exceptions](scoped-feedback-triage.md), and
[sensor health](endpoint-security.md#health-and-reconnect).

## v0.3.2 — Claude Cowork endpoint visibility

A separate [Claude Cowork integration](claude-cowork.md) supports native host tools
and the local VM boundary, with explicit native, VM, cloud, and unknown origin
labels. Manual per-session audit collection complements the signed macOS sensor.
Guest commands, cloud execution, and automatic audit-to-sensor causal joining are
outside current coverage. Mac-wide protection levels live in Settings.

## Operation-bound protection

The repository also includes an application-neutral runtime beyond the macOS
harness UI: [operation admission](operation-boundary.md),
[signed contract catalogs](contract-catalog.md),
[typed capability providers](generic-capability-providers.md),
[authenticated service context](operation-context.md),
[isolated semantic verifiers](semantic-verifier.md), and
[transactional promotion](transactional-promotion.md).
Start with the [end-to-end demo](generic-end-to-end-demo.md). Supported effect
classes and host requirements are explicit; these are not automatic transactional
guarantees for every tool in every harness.

## Research and evaluation

The [security-trace collection](security-traces.md) now includes the experiment
study, animated timeline, and offline replay/scoring tools. Those experiments were
observe-only; use the separate boundary proof to evaluate enforcing behavior.

## Upcoming

[Glean and n8n support](roadmap.md) and model-assisted triage suggestions are
planned. The sensor-banner navigation and dismissal changes in
[PR #115](https://github.com/GenseeAI/gensee-crate/pull/115) are a separate build 13
candidate and are not part of the published v0.3.3 build 12 download.
