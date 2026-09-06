# Review Queue and remembered approvals

The queue shows one **Status**: **Blocked**, **Approval requested**, **Warning**, or
**Allowed**. Expanded details retain the original risk severity and policy response.
A status describes the decision when the event happened; an old approval request
is not necessarily still waiting in the harness.

Endpoint Security can observe a child process removing or renaming files even
when the displayed shell command contains no `rm`. Build tools and Git perform
such operations internally. Ordinary workspace writes, temporary regular-file
renames, and narrowly identified runtime housekeeping stay quiet. Protected paths,
unsafe rename sources, directory moves, unknown scope, and blocks
still require attention. Historical filtering preserves raw records and their hash
chain. Routine hook-correlation and housekeeping alerts are persisted under the
configured severity/retention policy, then hidden only in the dashboard. Scratch
renames involving executable-registry paths remain visible.

Request rows are mutable current-state projections: a background continuation
updates its originating request's latest response and completion time. Earlier
responses remain in the append-only hook journal. Historical notification-to-origin
links are backfilled once in batches and retained in a derived table. Grouped detail
queries gather all members together. Alert display classifications are cached by
alert ID and policy/version; policy changes invalidate them. Historical classification
uses recorded paths and metadata, with no present-day filesystem reads or directory
walks. These presentation classifications must never authorize access.

## Gensee monitoring gaps

**Settings → Endpoint Security → Gensee monitoring gaps** contains the latest 100
retained sensor delivery-gap reports. Overview shows a monitoring-health indicator.
These records are excluded from agent findings, request warning counts, and review
notifications, including historical records that older versions attached to a tool.
The raw historical evidence and its hash chain remain unchanged. New reports have
no request association and bypass the agent minimum-severity filter.

The sensor detects kernel delivery loss using the client's unfiltered
`global_seq_num`. Apple's [sequence-number documentation](https://developer.apple.com/documentation/endpointsecurity/es_message_t/global_seq_num)
explains that this generally means the kernel produced more events than the client
could handle. Gensee's ingester does not infer loss from the filtered agent stream.
The next retained event carries the accumulated missing-event count; its process,
file, and active tool do not identify the cause or ownership of the missing events.
Reports are rate-limited per sensor boot, so summing their counts does not give an
exact total. Live sensor health has separate kernel-loss and replay-buffer counters.

The sensor currently subscribes to frequent system-wide file notifications and
authorization events, then filters unmanaged activity in its callback. Build bursts
can stress that path. Historical gap records alone cannot identify a specific
callback bottleneck; diagnosing it requires live throughput and latency profiling.
If the sensor is disconnected, zero counters are not proof of complete coverage.
Check the connection and Full Disk Access before interpreting them. Full Disk Access
denial prevents the sensor from starting and is distinct from a running sensor's
event-delivery loss.

## Approve a repeat

For a supported approval request, open its Review menu and choose **Approve similar
actions…**. Review the captured tool input, target, and project before choosing:

- **Allow once**: the next matching action in the same session, within 24 hours.
- **This session**: matching actions with the same session ID, until a recorded
  session termination or 24 hours.
- **This project**: matching actions in the same canonical project directory for
  30 days, including later sessions.

Saving an approval does not execute a historical command. Retry the action in the
harness. No approval is inferred from a successful execution, a PostToolUse event,
or a positive finding review. Settings → **Remembered Approvals** lists active
permissions with expiry, project, and target; **Revoke** stops future matches.

Matching requires the same provider, tool name and input (apart from the tool-call
ID), canonical project and target, and rule. Executable and credential-content
read approvals also require a complete digest captured during the original policy
inspection to match at preview, grant, and reuse. Changed content and older alerts
without that digest require a fresh request; unavailable-content alerts cannot be
remembered. Approval keys are versioned, so grants made before this content-binding
fix no longer match. Different arguments,
content, targets, providers, or projects require another decision. All ASK findings
for a call must match before a one-use approval is consumed. Block findings,
including strict/noninteractive enforcement floors, are never bypassed.

Supported rules cover writes outside the workspace, credential-content reads,
unmatched or prior-session executable modifications, and executable-content
availability. An unreadable/oversized artifact, dynamic shell command, redacted or
truncated tool input, or missing original capture cannot be remembered. The UI
recovers exact input from at most the latest 64 MiB of captured hook history; if it
is unavailable, retry the action to capture a fresh request. A display summary is
never treated as an exact authorization.

## Local storage and limits

The backend stores approvals in the owner-only `approvals.json` in the local
Gensee home. Records retain consumed, expired, and revoked entries, with a limit of
2,048 records / 4 MB. A nonblocking file lock and atomic replacement protect one-use
consumption across concurrent hooks; corruption, unsafe permissions, or lock
contention retain ASK. Repeated session/project matches do not rewrite the file.
Approval management accepts the installed, signed macOS Gensee app as its caller;
agent tool writes to the approval store are blocked by the local policy. Approval
memory shares the local policy's trust boundary and is not protection against a
compromised user account or administrator.

Read-only diagnostics: `gensee approval list` and
`gensee approval preview --alert-id <id>`. Grant and revoke are app-managed.

Dashboard refreshes evaluate housekeeping only for candidate rules and sort only
mutation warnings for time-window deduplication. Artifact summaries use the
existing identity index. The app permits one background projection at a time,
with a 90-second deadline and the previous snapshot visible while it completes.
`GENSEE_DASHBOARD_TIMING=1 gensee dashboard-state` writes phase durations to stderr
for local performance diagnosis.
