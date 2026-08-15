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

- Dashboard, activity, alerts, transactions, and policy backed by the existing
  Rust CLI and local store.
- A **Daily Highlight** view with today's summary and rolling 53-week heatmaps
  for agent turns, tool calls, alerts, and captured token usage. Selecting a
  day in any heatmap updates the summary above it.
- Installation, status, and removal of the signed Endpoint Security system
  extension.
- Navigation to Full Disk Access, which macOS requires for complete protected
  file visibility.
- Endpoint Security `off`, `observe`, `protect`, and `strict` policy modes.
- Harness protection for Codex, Claude Code, Antigravity, Cursor, GitHub
  Copilot, and Omnigent.

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

Installed direct-hook harnesses have an enable/disable switch. Enabling calls
the matching `gensee setup <provider>` command; disabling calls its
`--disable` form. Disable removes only Gensee-owned hook entries and preserves
unrelated user settings and hooks. Harnesses that are not installed remain
visible but muted and unavailable. Use **Scan again** after installing or
removing a harness outside Gensee Crate.

For enabled integrations, the app verifies that every supported lifecycle
event has a Gensee hook, every hook targets the app's active event store and
backend executable, and harness-level settings do not disable execution. An
unhealthy integration remains visibly enabled but changes to **Needs repair**;
its Observe and Enforce indicators turn off so stale configuration is not
presented as protection. **Repair** safely replaces stale or partial
Gensee-owned entries. For Claude Code, an explicit repair also changes
`disableAllHooks` from `true` to `false` while preserving the rest of the
settings file.

Omnigent currently has no direct hook switch. Launch it with `gensee run` to
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

See the [Endpoint Security sensor](endpoint-security.md) guide for captured
events, policy keys, safety boundaries, and rollback.

## Signing and installation

The host App ID is `ai.gensee.crate`; the extension App ID is
`ai.gensee.crate.endpoint-security`. Building the source does not grant the
managed entitlement. The signing team must have Apple's Endpoint Security
approval and matching provisioning for the intended Development or Developer
ID distribution method.

Activation only works from a correctly signed app installed in `/Applications`.
After opening it, use **Install & Enable**, approve the system extension in
System Settings if prompted, grant Gensee Crate Full Disk Access, and confirm
the Settings page reports event delivery.

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
