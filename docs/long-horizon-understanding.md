# Long-horizon understanding

Risk can develop across several requests: one task writes a script, a later task
changes it, and another session executes it. Gensee retains artifact provenance,
request history, and verification evidence so policy can evaluate more than the
current tool call.

## What is available

- **Cross-session artifact history.** File facts retain the last modifier and
  session, external modification signals, and executable, memory, persistence,
  and control-plane registry membership.
- **Content-bound execution checks.** Pre-execution inspection uses the current
  artifact digest. A risk tag for an old version does not establish that the
  current file is risky. Prior-session or externally modified executable content
  can require approval.
- **Verification freshness.** A later mutation can make earlier verification
  stale; request review keeps the affected files and evidence together.
- **Request continuity.** Supported Claude background task notifications attach
  to their originating requests when the stored identifiers establish that link.
  An unlinked completion retains its task summary rather than becoming a made-up
  user request. Raw events and original identifiers remain available.
- **Watchlist and lineage.** Persistent targets and relationships between requests,
  tools, and artifacts can be inspected across sessions.

For example, a script created in session A and executed in session B carries its
provenance into the execution decision. A narrowly remembered approval must still
match its provider, project, rule, input, target, and captured content where
required. Approving one script does not authorize later arbitrary scripts.

## Understanding is bounded by evidence

These controls use stored metadata, content inspection, and deterministic rules.
They do not claim a model understands every instruction or future outcome.
FSEvents path/time correlation is weaker than exact Endpoint Security process
identity, missing telemetry remains a coverage gap, and retention limits available
history. Scoped read exceptions are deliberate permissions, not learned intent.

Organization-approved intent analyzers in the [operation boundary](operation-boundary.md)
can use bounded references to earlier manifests. Their probabilistic classification
must satisfy the signed catalog; an analyzer cannot invent authority. Automatic
permission learning from approval clicks and model-assisted feedback suggestions
remain [planned work](scoped-feedback-triage.md).

Continue with [artifact lineage](lineage-graph.md), [Review Queue and approvals](review-queue-approvals.md),
[authenticated replay](replay.md), or [signed operation context across services](operation-context.md).
