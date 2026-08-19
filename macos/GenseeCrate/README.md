# Gensee Crate for macOS

This is the native macOS security console and Endpoint Security host for Gensee
Crate. It uses these explicit App IDs:

- Host app: `ai.gensee.crate`
- Endpoint Security extension: `ai.gensee.crate.endpoint-security`

The extension supports `off`, `observe`, `protect`, and `strict` policy modes.
It subscribes to process lifecycle, file access and mutation notifications, and
the corresponding Endpoint Security `AUTH` events. `observe` is the default and
never denies. `protect` and `strict` can deny configured operations only inside
explicitly managed agent process trees; unrelated host processes remain outside
the deny scope.

The host app embeds the `gensee` CLI built from this repository and uses it as
the product backend. The native console reads the local dashboard snapshot,
managed and transactional runs, policy settings, and agent-integration state
from the same `GENSEE_HOME` store as the CLI (default `~/.gensee`). Policy and
integration changes are submitted through the existing `gensee policy` and
`gensee setup` commands rather than reimplementing their behavior in Swift.

The console includes:

- An explicit, in-memory **synthetic demo** that can be entered before setup or
  from the app toolbar. It uses invented sessions, requests, tool calls,
  findings, artifacts, and activity history; a persistent banner identifies the
  data as synthetic. Entering the demo does not initialize a database, install
  hooks, request Apple permissions, change policy, or touch harness settings.
  Real configuration pages remain locked until the user exits the demo.
- A progressive protection ladder. **Observe** keeps Endpoint Security
  notification-only while existing hook decision rules still apply;
  **Guarded** enables configured OS authorization while keeping ask decisions
  interactive; **Unattended** selects strict OS authorization and escalates
  medium-or-higher asks to deny so an agent stops instead of waiting for an
  approval. The ladder changes these two policy controls atomically and never
  rewrites the user's decision rules.
- A first-launch setup assistant that installs the bundled backend at
  `~/.gensee/bin/gensee`, initializes the encrypted event store and default
  policy, guides Apple approvals, scans all six harnesses, and offers one-click
  setup for every installed direct-hook integration. It does not require a
  separate SQLite install, Homebrew, Rust, jq, or Xcode Command Line Tools.
- Overview, activity, alerts, and run inventory backed by `gensee dashboard-state`
  and `gensee run list --json`.
- A Daily Highlight page with today's summary and four rolling-year activity
  heatmaps for agent turns, tool calls, alerts, and token usage. Heatmap days
  are selectable and update the detailed summary.
- A Timeline page that expands sessions into their original requests and paired
  tool calls, including parallel/sequential relationships, duration bars,
  affected files, policy outcomes, and expandable event evidence.
- Policy controls backed by `gensee policy get/set/path`.
- A Harnesses page that detects Codex, Claude Code, Antigravity, Cursor,
  GitHub Copilot, and Omnigent. Installed direct-hook integrations can be
  enabled or disabled through `gensee setup`; unavailable harnesses remain
  visible but disabled. Codex and GitHub Copilot rows also open the native
  Config Audit workflow backed by `gensee audit --json`, with findings,
  evidence, remediation, inventory, source provenance, and manual checks.
  Other audit actions are visibly marked **Coming soon**. Enabled integrations
  are checked for complete hook coverage, the active event-store path, the
  current backend executable, and harness-specific blockers, with a one-click
  repair action when needed. A hook configuration becomes **Protected** only
  after a real event from that harness reaches the active local store.
- Endpoint Security installation, removal, and Full Disk Access navigation.

Token totals are captured from compatible Claude Code and Codex transcript
usage metadata when a turn completes. Only the numeric per-turn total is stored;
historical turns and harnesses without compatible usage metadata remain zero.

## Use the security console

The **Harnesses** page always lists the six supported harnesses. When Codex,
Claude Code, Antigravity, Cursor, or GitHub Copilot is detected, **Enable
Protection** installs the existing Gensee hook integration through the embedded
OSS CLI. A protected row instead offers **Disable Protection**. A harness that
is not installed remains visible with disabled, muted actions so users can see
what is supported without implying that it is active. **Scan again** refreshes
installation and protection state. If hooks are incomplete, disabled, or
routed to a different store or backend, **Repair Protection** reruns the
matching OSS setup command with this app's active store and embedded backend;
it changes only Gensee-owned hook entries.

After setup, follow the provider-specific restart or reload instruction and
start a new agent turn. Codex additionally requires trust review for
non-managed hooks: use **Open Codex Hook Review**, enter the copied `/hooks`,
and trust the Gensee commands. The one-time Terminal review closes automatically
after Codex records approval.
command in the opened CLI, and trust Gensee. The assistant can use the Codex
binary bundled with the ChatGPT app, so the user does not need a separately
installed command on `PATH`. Until the first real event arrives, the harness is
shown as **Restart & test** rather than **Protected**. Rerun the assistant from
**Settings → Run Setup Assistant** at any time.

Use **Audit Config** on the Codex or GitHub Copilot row to select a workspace
and open the read-only audit inline on the Harnesses page. Audit actions for
Claude Code, Antigravity, Cursor, and Omnigent remain disabled and marked
**Coming soon** until their static adapters are available.

Omnigent is shown in the same inventory, but it currently uses managed-launch
protection instead of a direct hook toggle. Launch it through `gensee run` to
associate its process tree with Gensee policy and Endpoint Security decisions.

Use **Settings → Protection Level** to move between Observe, Guarded, and
Unattended with a plain-language explanation of the tradeoff. Use **Policy**
for the underlying Endpoint Security mode, decision rules, protected paths, and
blocked executables. Use **Settings** to install, inspect, or remove the system
extension and to open the Full Disk Access pane. Start with Observe, confirm
event delivery, and review the local evidence before moving to an enforcement
level.

Disabling a direct-hook integration removes only Gensee-owned hook entries and
preserves unrelated harness settings and hooks. It also removes that harness's
active roots from Endpoint Security before the next event batch is fetched.
Only events inside a bounded active tool-call window can become findings;
runtime bookkeeping is filtered and related file events are coalesced and
durably deduplicated. Build-output filtering requires both a fixed top-level
root beneath the active workspace and a known build process. The app leaves
the mutable event store writable while always protecting
`$GENSEE_HOME/policy.json` and `$GENSEE_HOME/bin/`. Idle global OS events remain
available to the in-memory ancestry tracker but are not written to the
dashboard event store.

The Policy page controls local recording volume independently from
enforcement. By default Gensee records alerts at `info` or higher, persists raw
Endpoint Security events only during active agent tool calls, retains raw
events for 24 hours with a 100,000-row hard cap, and permanently deletes
`info`, `low`, and `medium` alerts after 48 hours. High and critical alerts are
not removed by the low-severity expiry. Users can change the severity floor,
raw-event scope, retention hours, and row cap without weakening inline policy
decisions. Settings reports extension backlog, batch latency, suppressed raw
events, and retention pruning so backpressure is visible instead of silently
stalling the console. Expiry runs in small bounded ingestion batches so it
never blocks dashboard projection work and catches up while the sensor runs.

## Apple Developer configuration

In Certificates, Identifiers & Profiles:

1. Register or select the explicit host App ID `ai.gensee.crate` and enable the
   **System Extension** capability.
2. Register or select the explicit extension App ID
   `ai.gensee.crate.endpoint-security` and enable the approved
   **Endpoint Security** managed capability.
3. Check the Endpoint Security capability's distribution details. Development
   access is sufficient for local testing; **Developer ID** access is required
   to ship the app independently.
4. Open `GenseeCrate.xcodeproj`, select the same GenseeAI development team for
   both targets, and let Xcode refresh their provisioning profiles.

The host carries `com.apple.developer.system-extension.install`. The embedded
extension carries `com.apple.developer.endpoint-security.client`.

These entitlement declarations and bundle identifiers are public build
configuration. Publishing them does not grant Endpoint Security access to
another Apple Developer account: each developer or distributor must receive
Apple's approval for their own account and sign with matching development or
Developer ID provisioning. Never commit certificates, private keys, `.p12`
files, provisioning profiles, notarization credentials, archives, or built
`.app`/DMG artifacts.

## Build and install

Generate the Xcode project, then build. The host build phase compiles
`gensee-crate-cli` and embeds the resulting executable in the app bundle.

```bash
xcodegen generate --spec project.yml

xcodebuild -project GenseeCrate.xcodeproj \
  -scheme GenseeCrate \
  -configuration Debug \
  build
```

System extension activation only works from a properly signed app installed in
`/Applications`. Copy the built `Gensee Crate.app` there, launch it, and click
**Install & Enable**. Approve the extension and grant Full Disk Access in System
Settings when macOS requests them.

Inspect the extension after activation:

```bash
systemextensionsctl list
log stream --predicate 'subsystem == "ai.gensee.crate.endpoint-security"'
```

For local extension replacement during development, Apple also provides system
extension developer mode:

```bash
systemextensionsctl developer on
```

That command requires administrator approval and should only be used on a
development Mac.

## Publish a macOS release

Public builds must be universal, Developer ID signed, notarized by Apple, and
stapled before upload. Store notarization credentials in the login keychain;
never put them in the repository or a shell script:

```bash
xcrun notarytool store-credentials gensee-crate \
  --apple-id "developer@example.com" \
  --team-id "3KWVB4M63F"
```

The command securely prompts for an app-specific password. Then run the
release script from the repository root with the version declared as
`MARKETING_VERSION` in `project.yml`:

```bash
NOTARYTOOL_PROFILE=gensee-crate ./scripts/release_macos_app.sh 0.2.4
```

The script builds the host, system extension, and embedded Rust CLI for both
Apple silicon and Intel; exports them with Developer ID signing; creates and
notarizes `dist/Gensee-Crate.dmg`; and staples Apple's ticket. Create the
GitHub release only after the script completes successfully. Keep the asset
name `Gensee-Crate.dmg` so the stable public URL remains:

```text
https://github.com/GenseeAI/gensee-crate/releases/latest/download/Gensee-Crate.dmg
```

## Regenerating the Xcode project

`project.yml` is the source of truth for target structure and signing
capabilities. With XcodeGen 2.46 or newer installed:

```bash
xcodegen generate --spec project.yml
```
