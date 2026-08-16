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

Configure the sensor in the native Policy page or with:

```bash
gensee policy set endpoint_security.mode observe
```

- `off` — respond allow to authorization messages and omit telemetry.
- `observe` — record auth/notify evidence; never deny (default).
- `protect` — deny configured protected-path and blocked-executable operations
  inside explicitly managed agent process trees.
- `strict` — the managed-tree fail-closed posture. Unrelated host processes
  remain outside the deny scope.

Additional policy keys:

```bash
gensee policy set endpoint_security.protected_paths /absolute/path,/another/path
gensee policy set endpoint_security.blocked_executables /usr/bin/osascript
```

`GENSEE_HOME` is not protected implicitly because hook binaries must update the
encrypted store. The extension recognizes its own processes only by the Gensee
Team ID and signing identifiers; executable paths and file-content hashes do
not grant an authorization bypass.

Authorization decisions are deterministic and local to the extension. The ES
callback never waits for the UI, XPC, SQLite, or human approval. Session-dependent
decisions use no authorization cache. The dashboard reports decisions, denials,
maximum observed authorization latency, and kernel/ring gaps.

## Safety and rollback

Start in `observe` and review evidence before using `protect`. Set mode back to
`observe` for immediate policy rollback. The Settings page can deactivate the
extension if necessary. Removal stops OS event coverage; it does not delete the
Gensee database or other host files.

`endpoint-spike` and `gensee ingest eslogger` remain available only as manual
diagnostic compatibility tools.
