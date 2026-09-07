# macOS Endpoint Security sensor

Gensee Crate ships a first-party Endpoint Security system extension in
[`macos/GenseeCrate`](https://github.com/GenseeAI/gensee-crate/tree/main/macos/GenseeCrate):

- host app: `ai.gensee.crate`
- system extension: `ai.gensee.crate.endpoint-security`
- entitlement: `com.apple.developer.endpoint-security.client`

The extension replaces `sudo /usr/bin/eslogger` for normal use. A signed XPC
channel accepts only the signed Gensee host. The host pulls bounded batches and
streams versioned JSONL into a long-lived `gensee ingest endpoint-security`
process, which persists events in the active encrypted `GENSEE_HOME` store.

The native [macOS security console](macos-app.md) manages extension activation,
Full Disk Access navigation, sensor policy mode, health, and protection toggles
for installed agent harnesses. It delegates policy and hook configuration to
the embedded OSS `gensee` CLI rather than duplicating the Rust implementation.

## Captured evidence

The schema records the reboot ID, event ID, `(pid,pidversion)` process identity,
parent and responsible audit tokens, signing/team identity, executable path,
fork/exec targets, argv, script and cwd, file path plus device/inode, open flags,
and per-type/global Endpoint Security sequence numbers. Subscriptions cover:

- process: exec, fork, exit
- file access: open, readdir, mmap
- mutation: create, write, close, rename, unlink, truncate

The Rust ingester maintains an event-driven process graph and correlates exact
descendants with active `gensee run` session roots. Extension-side root
registration carries attribution to sessions started after the ingester.
FSEvents remains a reconciliation signal, not the source of actor identity.

An `open` event proves that a process obtained a descriptor with read intent;
it does not prove that bytes were consumed.

## Modes

Choose **Settings → Protection Level** for Mac-wide Fast (Observe), Review
(Protect), or Sensitive (Strict) presets. Sensitive also changes hook interactivity;
a sensor mode alone is not a per-harness permission. Use Policy for advanced edits,
or set the sensor mode directly with:

```bash
gensee policy set endpoint_security.mode observe
```

- `off` — respond allow to authorization messages and omit telemetry.
- `observe` — record notification evidence for completed operations; answer authorization callbacks promptly without ancestry/path evaluation or duplicate authorization telemetry; never deny (default).
- `protect` — deny configured protected-path and blocked-executable operations
  inside explicitly managed agent process trees.
- `strict` — the managed-tree fail-closed posture. Unrelated host processes
  remain outside the deny scope.

Additional policy keys:

```bash
gensee policy set endpoint_security.protected_paths /absolute/path,/another/path
gensee policy set endpoint_security.blocked_executables /usr/bin/osascript
```

The mutable event-store files in `GENSEE_HOME` are not protected implicitly
because hook binaries must update them. The app always protects
`$GENSEE_HOME/policy.json` and `$GENSEE_HOME/bin/`, preventing a managed agent
from replacing the policy or stable hook backend that governs its next action.
The extension recognizes its own processes only by the Gensee Team ID and
signing identifiers; executable paths and file-content hashes do not grant an
authorization bypass.

Authorization decisions are deterministic and local to the extension. The ES
callback never waits for the UI, XPC, SQLite, or human approval. Session-dependent
decisions use no authorization cache. The dashboard reports decisions, denials,
maximum observed authorization latency, and kernel/ring gaps.

## Alert correlation and noise control

The extension observes the OS event stream globally so it can maintain exact
process ancestry, but raw telemetry is not automatically a security finding.
The macOS host sends only active roots for harnesses whose protection toggle is
enabled. Removing a root also evicts its queued events and inherited process
attribution from the extension.

For hook-correlated activity, the Rust ingester attaches an event to a request
only while that session has an
unfinished `PreToolUse` or `PermissionRequest` event no more than 60 seconds old.
`PostToolUse`, `PostToolUseFailure`, a blocking decision, or expiry closes that
window. Outside it, the OS event still updates the ingester's in-memory ancestry
graph, but it is not written to the product event store and cannot produce a
hook-bypass finding. Cowork opt-in evidence and monitoring-gap records have
separate handling; a gap must remain durable even when it has no user request.
See [Cowork coverage](claude-cowork.md) and [monitoring-gap semantics](review-queue-approvals.md#gensee-monitoring-gaps).

Before findings are stored, known harness bookkeeping (including Crashpad,
transcripts, compiler/build output, test results, and harness SQLite sidecars)
is excluded. Build and test paths qualify only when they are fixed top-level
roots directly beneath the active tool's workspace and the actor is a known
build process; an agent-created directory with a build-like name is not enough.
Related `open`, `write`, and modified `close` notifications are coalesced into
one mutation. Alerts are then deduplicated for 10 seconds by session, exact
`(pid,pidversion)` identity, path, logical operation, and rule; the database
repeats this check so app restarts cannot replay the same alert.

## Safety and rollback

Start in `observe` and review evidence before using `protect`. Set mode back to
`observe` for immediate policy rollback. The Settings page can deactivate the
extension if necessary. Removal stops OS event coverage; it does not delete the
Gensee database or other host files.

`endpoint-spike` and `gensee ingest eslogger` remain available only as manual
diagnostic compatibility tools.

## Throughput diagnostics

Sequence accounting runs synchronously in the serial ES callback before filtering.
It never dispatches a ring-queue task for unrelated system-wide traffic. Observe/off
skip authorization ancestry and path evaluation; protect/strict retain authorization
decisions and notification evidence. Each callback has a bounded-lifetime autorelease
pool. No system-wide file-event muting is used, so newly adopted process generations
remain discoverable.

Settings exposes messages received, maximum callback time, current/peak pending
evidence, and maximum evidence-queue delay alongside kernel/ring loss and host-ingest
latency. These maxima cover this sensor lifetime, not only the latest sampling interval.
They distinguish callback pressure, ring-queue pressure, and host ingestion backlog;
they cannot reconstruct the cause of an older gap. Full Disk Access fixes client
startup permission, not throughput. Error 4 from `es_new_client` means TCC still
rejects the extension even when it is listed as activated.

## Health and Reconnect

Open **Settings → Endpoint Security** to inspect connection status, ingestion
health, backlog, dropped/rejected events, and **Sensor throughput diagnostics**.
The **Gensee monitoring gaps** section retains recent gap reports. These are not
agent policy violations and do not contribute to request warning counts.

A kernel-delivery gap means the sensor missed events before processing them. A
replay-buffer gap means the consumer fell behind retained history. The tool shown
near an old gap is not proof that it caused the loss. Use live diagnostics to
investigate current pressure; historical records cannot identify an exact past
bottleneck. Full Disk Access enables client startup but does not solve overload.

**Reconnect** interrupts the current XPC wait and retry delay. Event fetching and
configuration calls have five-second deadlines; failed connections recover with
backoff. A retry during durable ingestion waits for that bounded write to finish
so cursor ordering is preserved. Late replies from replaced connections cannot
complete a newer request. Configuration rejection remains separate from transport
failure.

Availability and loss evidence are separate: a recovered connection does not
restore missing history. Monitoring-loss banners therefore survive recovery until
acknowledged. In published v0.3.3 build 12, the **Sensor health** banner action only
selects Settings, and queued loss counts can restore a dismissed banner. Scroll to
Endpoint Security to inspect details. [Build 13 / PR #115](https://github.com/GenseeAI/gensee-crate/pull/115)
adds direct navigation and episode-aware dismissal; it is not yet in the public
build 12 download.
