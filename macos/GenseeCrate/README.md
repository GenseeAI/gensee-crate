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

- Overview, activity, alerts, and run inventory backed by `gensee dashboard-state`
  and `gensee run list --json`.
- A Daily Highlight page with today's summary and four rolling-year activity
  heatmaps for agent turns, tool calls, alerts, and token usage. Heatmap days
  are selectable and update the detailed summary.
- Policy controls backed by `gensee policy get/set/path`.
- A Harnesses page that detects Codex, Claude Code, Antigravity, Cursor,
  GitHub Copilot, and Omnigent. Installed direct-hook integrations can be
  enabled or disabled through `gensee setup`; unavailable harnesses remain
  visible but disabled. Enabled integrations are checked for complete hook
  coverage, the active event-store path, the current backend executable, and
  harness-specific blockers, with a one-click Repair action when needed.
- Endpoint Security installation, removal, and Full Disk Access navigation.

Token totals are captured from compatible Claude Code and Codex transcript
usage metadata when a turn completes. Only the numeric per-turn total is stored;
historical turns and harnesses without compatible usage metadata remain zero.

## Use the security console

The **Harnesses** page always lists the six supported harnesses. When Codex,
Claude Code, Antigravity, Cursor, or GitHub Copilot is detected, its switch
enables or disables the existing Gensee hook integration through the embedded
OSS CLI. A harness that is not installed remains visible with a disabled,
muted switch so users can see what is supported without implying that it is
active. **Scan again** refreshes installation and protection state. If hooks
are installed but incomplete, disabled, or routed to a different store or
backend, the row stays switched on and shows **Needs repair**. **Repair** reruns
the matching OSS setup command with this app's active store and embedded
backend; it changes only Gensee-owned hook entries.

Omnigent is shown in the same inventory, but it currently uses managed-launch
protection instead of a direct hook toggle. Launch it through `gensee run` to
associate its process tree with Gensee policy and Endpoint Security decisions.

Use **Policy** to choose the Endpoint Security mode and configure protected
paths or blocked executables. Use **Settings** to install, inspect, or remove
the system extension and to open the Full Disk Access pane. Start with
`observe`, confirm event delivery, and review the local evidence before moving
to an enforcement mode.

Disabling a direct-hook integration removes only Gensee-owned hook entries and
preserves unrelated harness settings and hooks.

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
