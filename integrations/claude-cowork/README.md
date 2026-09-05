# Claude Cowork endpoint visibility (macOS pilot)

This local adapter records Claude Cowork audit boundaries and host effects on a Mac without
claiming visibility that the endpoint does not have. It combines the macOS
Endpoint Security stream with Cowork's local audit stream and assigns every
Cowork boundary event exactly one execution-origin label. Configuration, evidence,
and the dashboard stay on the endpoint. This integration adds no enrollment,
central policy service, fleet management, or remote-control API.

Execution-origin labels describe the available evidence:

| Label | Meaning |
| --- | --- |
| `host-native` | A local audit record identifies a known host tool, or an OS event has explicit host-tool context and verified signing identity. Audit intent alone does not prove an effect occurred. |
| `vm-mediated` | A local shell/code tool crossed the Linux VM boundary. Crate records the boundary and host-visible result, not guest commands or process lineage. |
| `cloud-mediated` | The session was explicitly identified as cloud mode. Crate records only effects bridged back through the endpoint; cloud execution is outside endpoint visibility. |
| `unattributed` | Available evidence cannot establish the execution surface. Crate does not guess. |

## Pilot contract

1. Crate records Cowork's local audit stream and independently observed process
   and file events. Local protected-path and blocked-executable policy applies
   at the supported Endpoint Security boundaries.
2. For local shell execution, Crate records the VM boundary and resulting
   endpoint changes but does not claim guest command-level visibility.
3. For cloud sessions, Crate records only local bridged effects and marks cloud
   execution as outside endpoint visibility.
4. Every Cowork boundary event carries one of the four labels above. Missing,
   legacy, and unknown records resolve to `unattributed`.

The label describes causal execution origin, not merely the process that
eventually issued a macOS syscall. A signed Claude helper can serve both local
and cloud sessions, so its signing identity alone is intentionally insufficient
to label an action `host-native`.

## Local audit ingestion

The macOS app lists **Claude Cowork** separately from **Claude Code** in
Harnesses. **Enable visibility** / **Disable visibility** changes only the
Cowork endpoint opt-in; it preserves Claude Code hooks and the Mac's current
Endpoint Security mode. Start in Observe mode in Settings for the pilot.
The Setup Assistant's bulk action enables hooks only; opt into Cowork separately.

Mac-wide protection is configured in **Settings → Protection Level**:
Fast (Observe), Review (Protect), and Sensitive (Strict). It changes sensor mode
and hook interactivity for all enabled harnesses. Protect and Strict enforce the
same Cowork host rules; Strict also converts risky hook approvals to denials.
Neither adds guest-command or cloud enforcement.

Expand **Session & evidence** to select the independently established session
mode (unknown by default) and inspect recent evidence. Sensor status and the
manual audit setup link stay visible in the row. **Verify** reads historical audit and Cowork sensor evidence from
the latest 2,000 stored system events. It shows event times separately for native,
VM, cloud, and unknown audit boundaries; no evidence in this bounded sample does
not mean no evidence exists in older history. The same metadata-only diagnostics
are available as `gensee cowork-status`.

The app does not start an audit collector or mark Cowork “Protected.” Start each
manual stream below separately, stop it in its terminal when finished, and
restart it after changing session mode. Disabling endpoint visibility does not
terminate independently started CLI collectors. Historical evidence is not a
collector heartbeat. Run native and VM test tasks and Verify again to confirm
that the relevant event times advance.

Enable the opt-in managed process root and set the independently established
session mode:

```sh
gensee policy set cowork_endpoint_visibility.enabled true
gensee policy set cowork_endpoint_visibility.session_mode local
```

In `protect` or `strict` Endpoint Security mode, the signed Claude Desktop root
and its host descendants are then subject to the configured protected-path and
blocked-executable rules. The system extension verifies Anthropic's signing and
team identities before trusting the PID supplied by the desktop app.

Cowork local-session audit records can be streamed into Crate without an
Anthropic API integration:

```sh
tail -F "$HOME/Library/Application Support/Claude/local-agent-mode-sessions/<account>/<org>/<session>/audit.jsonl" \
  | gensee ingest cowork-audit
```

For per-user installations the base is usually under the user's
`~/Library/Application Support/Claude` directory. Deployments should discover
the path rather than hard-code account, organization, or session identifiers.

The ingester defaults to `cowork_endpoint_visibility.session_mode`, keeping the
audit and Endpoint Security paths on one mode. `--session-mode` accepts `local`,
`cloud`, or `unknown`. A concrete flag conflicting with a concrete local policy
mode is rejected. Explicit `unknown` always collects conservatively without
claiming a mode, even when policy specifies one. An invalid local policy emits a
warning and ingestion continues as `unknown`, regardless of the requested mode.
The endpoint cannot reliably infer mode from the Claude process name; use
`unknown` for mixed or unverified sessions.

The ingester recognizes native file tools such as `Read`, `Write`, `Edit`,
`Glob`, and `Grep`, and the local VM shell tool `mcp__workspace__bash`. It stores
tool name, tool-use ID, session ID, timestamp, file path when present, origin,
and the applicable visibility limitation. File contents and shell commands are
omitted. Tool events require a session ID and a valid timestamp: RFC3339, or
integral epoch milliseconds from 1,000,000,000,000 through 4,102,444,800,000.
Numeric epoch seconds and fractional milliseconds are rejected rather than
silently dated to 1970 or retimed to the current moment.

The local audit format is not a public Anthropic compatibility contract. Treat
this parser as a versioned pilot adapter and fail to `unattributed` if the
format or tool identity is unknown.

## Endpoint Security correlation

The first-party macOS sensor records host-side process identity, parent PID,
signing identity, file reads/opens, writes, creates, closes, renames, truncates,
and deletes. The Cowork audit boundary timestamp, file path, session ID, and
tool-use ID provide the semantic side of correlation.

When visibility is enabled for an already-running Claude Desktop instance, the
host registers its current recursive descendant set as well as the app PID.
The extension validates each adoption candidate as an Anthropic-signed Claude
Desktop, Claude Code, or Desktop helper (including dotted helper variants), or
Apple's platform-signed VM process. Untrusted snapshot candidates can still
inherit independently verified parent-generation attribution. Later descendants
are learned from Endpoint Security fork/exec events. All candidates retain the
app's canonical root PID; enumeration order cannot change the recorded root.
Snapshot collection reserves growth capacity, retries boundedly, and logs failure.

Launchd-owned VM processes are also associated when Endpoint Security's
responsible audit token points to an already verified Cowork process generation.
This requires Apple's platform VM identity and an exact `(pid, pidversion)` match;
an unrelated VM or a reused responsible PID is not adopted. Association can only
start after evidence for the responsible process has been observed.

Apple's signed `com.apple.Virtualization.VirtualMachine` process is recognized
as a VM boundary. Seeing that boundary does not reveal the Linux process that
performed a command. A VM audit boundary is `vm-mediated`. Observing a resulting file on the Mac does
not by itself prove which guest command caused it.

Endpoint Security records include `cowork_visibility` evidence with the match
method, confidence, and visibility limitation. A Claude host process stays
`unattributed` without explicit tool evidence; a local-mode process tree alone
never produces a `host-native` label for caches, settings, or bridge activity.
The sensor currently emits unknown tool surface for non-VM processes. The local
audit stream separately records tool boundaries; automatic causal joining of its
session/tool IDs to the sensor's process-tree session is not implemented here.

## Enforcement boundary

This adapter uses the existing local Endpoint Security file/process controls.
It adds no network mediation and cannot enforce an individual syscall inside
Cowork's Linux VM or a command running in Anthropic's cloud. Claude Desktop can
share processes across activities, so the opt-in process-tree policy is broader
than one Cowork task. Start in `observe` mode and validate scope before enabling
`protect` or `strict` on the local machine.

## Pilot validation

For each supported Claude Desktop build, run both operations against a connected
test folder:

1. Ask Cowork's shell tool to create a file.
2. Ask Cowork's native file tool to create another file without shell.
3. Confirm the local audit boundary is `host-native` for the known file tool.
   Inspect independent Endpoint Security process, signing, and file evidence;
   non-VM sensor events remain `unattributed` without explicit tool context.
4. Confirm the shell audit boundary is `vm-mediated` and inspect any host-visible
   file effects without claiming guest commands or automatic causal correlation.
5. Repeat with an explicitly cloud-mode session and confirm bridged effects are
   `cloud-mediated` with the cloud visibility limitation.
6. Feed an unknown tool/mode and confirm it is `unattributed`.

## Regression checks

Run `scripts/test-cowork-endpoint-scope.sh` on macOS for the actual extension's
adoption, PID-generation, canonical-root, conservative tool-surface, and process
snapshot retry paths. It uses synthetic records without starting an ES client.
Rust Cowork tests cover timestamp/mode handling, origin classification, and
policy-enriched artifact ingestion without spurious unmatched-effect alerts.
Repeat signed, entitled live tests for each supported Claude/macOS build.

The signed macOS 15.1 / Claude Desktop 1.46388.4 regression run exercised native
Read/Write/Edit and `mcp__workspace__bash` in the local Linux VM. Independent
file evidence was captured for both, including the existing launchd-owned VM.
This is a compatibility result for that build, not a guarantee for other versions.
See [the validation notes](VALIDATION.md) for results and limitations.

## Sensor buffering and health

The endpoint retains a bounded 20,000-event circular replay buffer. Normal
eviction of consumed history does not count as loss. A consumer cursor behind
the oldest retained record reports the missing range once in health; the first
returned event carries the gap so durable ingestion can record it. A zero cursor
means a fresh or reset consumer and starts at retained history without counting
pre-attachment history as loss. Revocation erases buffered session payloads while
retaining cursor positions, so disabling a session cannot scramble a wrapped ring. Fetch retries
do not inflate the cumulative ring-loss counter. Kernel-reported loss remains
independent of ring retention. Gap alerts are limited to one per boot
per minute, while exact cumulative loss counters remain visible in sensor health.

The app drains acknowledged batches of up to 500 records with a short yield
while a backlog exists, and polls every 500 ms when idle or disconnected.
Fast draining requires the acknowledged cursor to advance; disconnected or
non-advancing iterations fall back to the idle delay. Backpressure does not
reduce the batch size. Ingestion timing excludes time spent waiting for input.
This improves burst recovery without changing the synchronous authorization
policy or claiming that a finite buffer can absorb unlimited load.


## Configuration compatibility

Malformed or incompatible Cowork roots exclude the entire affected Cowork
session and emit a diagnostic, while valid unrelated roots and sensor policy
updates continue applying. Invalid Cowork roots never fall back to unchecked
ordinary roots. The shared `signing-identity-fixture.json` is asserted by both
the Rust classifier tests and the native extension tests to catch trust-rule drift.
