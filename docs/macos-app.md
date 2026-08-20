# Native macOS security console

Gensee Crate for macOS is a SwiftUI security console and the host for Gensee's
first-party Endpoint Security system extension. Its source lives in
[`macos/GenseeCrate`](https://github.com/GenseeAI/gensee-crate/tree/main/macos/GenseeCrate).

The app does not implement a second Gensee backend. It embeds the `gensee` CLI
built from this monorepo and uses the existing Rust crates, policy engine, setup
commands, and `GENSEE_HOME` store. Activity recorded by hooks, `gensee watch`,
`gensee run`, and the system extension therefore appears in the same local
console.

## What the app manages

- A decision-first **Overview** page and **Review Queue** backed by the existing
  Rust CLI and local store. Requests are classified as Verified, Review
  recommended, Needs attention, or Incomplete evidence.
- A **Daily Highlight** view with today's summary and rolling 53-week heatmaps
  for agent turns, tool calls, alerts, and captured token usage. Selecting a
  day in any heatmap updates the summary above it.
- A nested **Review Queue** that expands sessions into user requests and paired
  tool calls, with parallel/sequential grouping, execution durations, affected
  files, grouped policy decisions, and expandable inputs and evidence. It
  promotes undeclared or sensitive changes and flags verification evidence that
  predates a later file mutation.
- A cross-session **Watchlist** for control-plane, agent-memory, and persistent
  targets, with the full relationship graph retained as a provenance drill-down.
- A menu-bar status window for sensor health, pending reviews, and the latest
  request.
- Installation, status, and removal of the signed Endpoint Security system
  extension.
- A replayable first-launch setup assistant that prepares the embedded backend,
  local event store, editable default policy, Apple permissions, and installed
  harness integrations without installing a developer toolchain.
- Navigation to Full Disk Access, which macOS requires for complete protected
  file visibility.
- Endpoint Security `off`, `observe`, `protect`, and `strict` policy modes.
- Harness protection for Codex, Claude Code, Antigravity, Cursor, GitHub
  Copilot, and Omnigent.
- Per-harness Config Audit actions backed by the shared OSS Rust audit library
  for static, read-only review of Codex and VS Code/Copilot configuration,
  including a saved local baseline and drift from the previous audit.
- Per-harness smart recovery points, created automatically or with approval
  before risky changes and restored from the relevant Review Queue item.

## First-launch setup

The signed app contains the universal `gensee` backend and its SQLite support.
On first launch, the setup assistant:

1. Copies the bundled backend to the stable `~/.gensee/bin/gensee` path used by
   hook files.
2. Initializes the encrypted local event store and writes an editable default
   policy to `~/.gensee/policy.json`.
3. Establishes smart-recovery behavior and a read-only Config Audit baseline,
   so the app demonstrates value before requesting broad Apple permissions.
4. Guides the user through optional Endpoint Security approval and Full Disk
   Access. These are Apple-controlled approvals and cannot be silently granted
   by the app.
5. Scans Codex, Claude Code, Antigravity, Cursor, GitHub Copilot for VS Code,
   and Omnigent, leaving unavailable harnesses visible but disabled.
6. Offers individual setup or **Enable All Installed** for direct-hook
   harnesses and provides the required reload step for each provider.
7. Waits for a real post-setup harness event before showing that integration as
   **Protected**.

Codex requires separate review for non-managed command hooks. **Open Codex Hook
Review** launches an installed Codex CLI—including the copy bundled with the
ChatGPT app when present—and copies `/hooks` so the user can review and trust
the exact Gensee command. A configured but untrusted or not-yet-exercised hook
remains **Restart & test**, not **Protected**.

Omnigent does not yet have a direct hook bridge. The assistant explains its
managed-launch requirement and can copy a `gensee run -- omnigent` starter
command. The assistant is optional and can be opened again from **Settings →
Run Setup Assistant**.

## Config Audit

Open **Harnesses** and choose **Audit Config** on the Codex or GitHub Copilot
row. Select a workspace and run the audit inline on the same page. Findings are
expandable with file-level evidence and remediation; Inventory, Sources, and
Manual Checks retain the same versioned report content as `gensee audit --json`.
Harnesses without a static audit adapter show a disabled **Audit
Config** action marked **Coming soon**.

Each completed audit becomes the local baseline for that target. The next run
shows new and resolved findings plus configuration sources that changed, so the
developer reviews drift instead of rereading the entire report.

The app invokes its embedded `gensee` backend. The audit bounds file size and
directory depth and never launches agents, extensions, hooks, skills, MCP
servers, or package runners. A partial report remains viewable when a specific
configuration layer cannot be reconstructed.

## Harness controls

The **Harnesses** page scans the Mac and always displays all six supported
harnesses:

| Harness | Protection path |
| --- | --- |
| Codex | Direct Gensee hooks |
| Claude Code | Direct Gensee hooks |
| Antigravity | Direct Gensee hooks |
| Cursor | Direct Gensee hooks |
| GitHub Copilot | VS Code agent hooks |
| Omnigent | Managed launch with `gensee run` |

Installed direct-hook harnesses have **Enable Protection** or **Disable
Protection** actions. Enabling calls the matching `gensee setup <provider>`
command; disabling calls its `--disable` form. Disable removes only
Gensee-owned hook entries and preserves unrelated user settings and hooks.
Harnesses that are not installed remain visible but muted and unavailable. Use
**Scan again** after installing or removing a harness outside Gensee Crate.

For enabled integrations, the app verifies that every supported lifecycle
event has a Gensee hook, every hook targets the app's active event store and
backend executable, and harness-level settings do not disable execution. An
unhealthy integration changes to **Needs repair** and offers **Repair
Protection**, so stale configuration is not presented as protection. Repair
safely replaces stale or partial Gensee-owned entries. For Claude Code, an
explicit repair also changes
`disableAllHooks` from `true` to `false` while preserving the rest of the
settings file. A healthy configuration remains **Restart & test** until a new
event from that provider reaches the active store; only then does it become
**Protected**.

Omnigent currently has no direct hook protection action. Launch it with `gensee run` to
place its process tree under Gensee monitoring and supported policy
enforcement.

## Daily activity and token totals

The **Daily Highlight** page aggregates directly from the local SQLite event
store. An agent turn is a stored request, a tool call is counted once at
`PreToolUse`, and alert totals use the same filtering as the rest of the native
dashboard.

For supported Claude Code and Codex JSONL transcripts, Gensee reads numeric
usage metadata when a turn completes and stores only that turn's total token
count. It does not copy transcript content into the activity aggregate. Token
history begins after this version is installed; prior turns remain at zero,
and harnesses that do not expose compatible usage metadata also report zero.

## Smart recovery points

Each hook-capable row on **Harnesses** has a **Smart recovery points** mode:

- **Auto** (default) creates one point before the first risky or mutating tool
  call in each request and Git workspace.
- **Ask** prompts in Gensee Crate first. Hooks that can wait do so briefly;
  Codex blocks the operation and asks the user to approve it in the app and
  retry the tool call.
- **Off** never creates a point automatically.

Gensee reuses policy findings, file intent, command risk, and broad-refactor
prompt signals to decide when a point is needed. It writes a private commit to
`refs/gensee/checkpoints/*`; it does not move the current branch, create a
normal commit, or alter the user's staging index. Tracked and untracked
non-ignored files are included. Retention and failure fallback are configured
under **Settings**.

Review Queue displays **Recovery point created before changes** on the matching
request. Restore is intentionally two-step: the app explains the affected
scope and requires **Create Rescue & Restore**; the backend also requires
`--yes`. Before changing the workspace, Gensee creates a rescue checkpoint of
its current state. Ignored files remain untouched, while non-ignored files
created after the selected point may be removed.

These checkpoints do not capture ignored files, nested repository contents,
files outside the workspace, processes, databases, credentials, or remote side
effects. They are a recovery aid for direct macOS work, not the same isolation
or transactional guarantee as the Linux tclone runtime.

## Endpoint Security modes

The bundled system extension records exact process identity and supported
process/file events. Configure its mode on the **Policy** page or with:

```bash
gensee policy set endpoint_security.mode observe
```

- `off` — allow authorization messages and omit telemetry.
- `observe` — record evidence without denying operations; this is the default.
- `protect` — enforce configured protected paths and blocked executables for
  explicitly managed agent process trees.
- `strict` — use the managed-tree fail-closed posture while leaving unrelated
  host processes outside the deny scope.

The app does not protect the mutable event-store files in `GENSEE_HOME`; hook
binaries must be able to update that encrypted store. It always protects
`$GENSEE_HOME/policy.json` and `$GENSEE_HOME/bin/`, so a managed agent cannot
replace its active policy or stable hook backend. The extension grants
process-level bypass only to Gensee binaries carrying the approved Gensee Team
ID and signing identifiers; it does not trust executable paths or file-content
hashes.

Harness protection toggles also scope Endpoint Security attribution. Disabled
hook harnesses are removed from the extension's managed roots immediately;
managed `gensee run` sessions remain eligible independently. User-facing bypass
findings require a bounded active tool-call window and pass through bookkeeping
filters, logical-operation coalescing, and durable deduplication. Raw OS events
are still observed in memory to maintain ancestry, but events outside an active
tool window are not persisted or surfaced as alerts.

See the [Endpoint Security sensor](endpoint-security.md) guide for captured
events, policy keys, safety boundaries, and rollback.

## Signing and installation

The host App ID is `ai.gensee.crate`; the extension App ID is
`ai.gensee.crate.endpoint-security`. Building the source does not grant the
managed entitlement. The signing team must have Apple's Endpoint Security
approval and matching provisioning for the intended Development or Developer
ID distribution method.

Activation only works from a correctly signed app installed in `/Applications`.
The first-launch assistant provides **Install & Enable**, opens the relevant
System Settings panes, and confirms sensor connectivity. The same controls
remain available on the Settings page.

Certificates, private keys, `.p12` files, provisioning profiles, notarization
credentials, archives, and built app/DMG artifacts must never be committed.
Entitlement plist files, bundle identifiers, and Xcode build configuration are
safe and intentionally versioned.

## Download and release

The latest notarized public build is available from the
[GitHub Releases download](https://github.com/GenseeAI/gensee-crate/releases/latest/download/Gensee-Crate.dmg).
Move **Gensee Crate.app** from the disk image to `/Applications` before
activating the system extension.

Maintainers publish with `scripts/release_macos_app.sh`. It creates a universal
Developer ID build, verifies the host app, Endpoint Security extension, and
embedded OSS CLI, submits the disk image to Apple's notarization service, and
staples the result. The script requires a `notarytool` keychain profile through
`NOTARYTOOL_PROFILE`; credentials and release artifacts stay outside version
control. See `macos/GenseeCrate/README.md` for the exact release procedure.
