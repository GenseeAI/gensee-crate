# PR 112 review follow-up (5126198557)

This supersedes the affected lifecycle, cache, fingerprint, and scratch-evidence details in the round-3 notes.

1. AppKit's `applicationDidFinishLaunching` starts the sensor, policy load, status item, and monitoring sampler. The delegate owns the shared model and coordinator. Starting health sampling no longer depends on a SwiftUI window appearing.
2. The host records its configured monitoring mode before attempting an XPC update. That mode controls intentional-off suppression. A stale off report from the extension cannot silence an enabled monitor. Intentional pauses preserve accumulated event losses and their baseline/cooldown.
3. An unresolved outage emits one notification per incident kind, with a persistent banner. Thirty seconds of stable recovery rearms it. A stall can notify independently of an earlier disconnect. This uses incident latching rather than indefinite repeated reminders.
4. Monitoring durations use `SuspendingClock`, which is monotonic and excludes system sleep. Wake notifications add 30 seconds of recovery grace without discarding drop counters. Wall-clock corrections cannot extend alarm cooldowns. The existing 15-second stale threshold and 10-second outage grace apply after wake grace.
5. The cache key now includes the store's classifier contract as well as CLI, core, and rules.
6. Approval eligibility requires a supported provider and an exact captured PreToolUse match for the alert's request/tool identity at or before the finding. Both dashboard query paths label their attribution. Nearest-event display context emits null eligibility rather than borrowing another command's eligibility/error reason. Preview/grant still validates captured input and filesystem/content evidence.
7. Eight recently registered policy generations can coexist. Pruning only occurs on registration beyond that bound, removing obsolete rows and cursors together. A warm policy switch does not delete its neighbor or reclassify history.
8. Explicit per-crate classifier contract versions replace broad source hashing and the three duplicate build scripts. Test/comment-only edits no longer invalidate history. Semantic classifier changes require a version bump; see [the contract](classifier-cache-contract.md) for responsibilities and this deliberate maintenance tradeoff.
9. Scratch adjustments carry a structured boolean through policy evaluation into evidence. Modern classification no longer depends on prose. A tightly bounded legacy compatibility path remains for immutable records from older builds.
10. The public unversioned classifier wrapper is removed. Tests prove zero classifier calls and zero SQLite busy-handler calls on a warm refresh while another connection holds the writer lock. They also cover context coexistence, eviction, and rebuilding after eviction.

## Validation

Validation passed: 720 CLI, 73 store, 98 rules, and 25 database Rust tests; 98 macOS tests; Clippy for all four Rust crates/all targets with warnings denied; and the complete unsigned app build. Coverage includes independent contract-key contributors, structured scratch evidence and legacy fallback boundaries, exact versus future/fallback tool attribution, unsupported providers, schema 6-to-7 preservation, warm-cache locking, and monitoring lifecycle state transitions.

This pass changes PR source only. It does not install or activate a new local build. Real sleep/wake and native notification delivery during a windowless launch were not exercised against the installed app; timing and alarm transitions are covered with injected monotonic instants, and the app lifecycle wiring is compiled in the full build.
