# Gensee Crate for macOS

This is the native macOS security console and Endpoint Security host for Gensee
Crate. It uses these explicit App IDs:

- Host app: `ai.gensee.crate`
- Endpoint Security extension: `ai.gensee.crate.endpoint-security`

The extension is intentionally notification-only. It subscribes to process
execution/lifecycle and common file events, but it does not subscribe to
Endpoint Security `AUTH` events until the Crate policy response path is ready.

The host app embeds the `gensee` CLI built from this repository and uses it as
the product backend. The native console reads the local dashboard snapshot,
managed and transactional runs, policy settings, and agent-integration state
from the same `GENSEE_HOME` store as the CLI (default `~/.gensee`). Policy and
integration changes are submitted through the existing `gensee policy` and
`gensee setup` commands rather than reimplementing their behavior in Swift.

The console includes:

- Overview, activity, alerts, and run inventory backed by `gensee dashboard-state`
  and `gensee run list --json`.
- Policy controls backed by `gensee policy get/set/path`.
- A Harnesses page that detects Codex, Claude Code, Antigravity, Cursor,
  GitHub Copilot, and Omnigent. Installed direct-hook integrations can be
  enabled or disabled through `gensee setup`; unavailable harnesses remain
  visible but disabled.
- Endpoint Security installation, removal, and Full Disk Access navigation.

Disabling a direct-hook integration removes only Gensee-owned hook entries and
preserves unrelated harness settings and hooks. Omnigent remains a managed
launch integration for now: run it with `gensee run` for process-tree
monitoring and enforcement until the planned first-class policy bridge lands.

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

## Regenerating the Xcode project

`project.yml` is the source of truth for target structure and signing
capabilities. With XcodeGen 2.46 or newer installed:

```bash
xcodegen generate --spec project.yml
```
