# Review Queue and remembered approvals

The queue shows one **Status**: **Blocked**, **Approval requested**, **Review**, or
**Allowed**. Expanded details retain the original risk severity and policy response.
A status describes the decision when the event happened; an old approval request
is not necessarily still waiting in the harness.

Endpoint Security can observe a child process removing or renaming files even
when the displayed shell command contains no `rm`. Build tools and Git perform
such operations internally. Ordinary workspace writes, temporary regular-file
renames, and narrowly identified runtime housekeeping stay quiet. Protected paths,
unsafe rename sources, directory moves, unknown scope, blocks, and collection gaps
still require attention. Historical filtering preserves raw records and their hash
chain.

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
read approvals also require an unchanged complete file digest. Different arguments,
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
