# PR 112 review follow-up (5125873920)

This update addressed the nine review findings. The [next follow-up](pr112-review-round4.md) supersedes its monitoring startup, timer, cache-retention, fingerprint, and scratch-evidence mechanisms.

1. **Migration lifecycle.** The classification-table rebuild runs only for databases older than schema 6. It clears classification progress in the same savepoint. Future unrelated schema upgrades retain the cache and its cursor together.
2. **Monitoring lifetime and outages.** The app-owned notification coordinator samples health independently of dashboard windows and database reads. A stopped/disconnected sensor lasting 10 seconds, three connection interruptions in 60 seconds, or stalled polling raises a monitoring-health alarm. Polling becomes stale after 15 seconds without a response and uses the same 10-second outage grace. Alarms are rate-limited; intentional off mode is silent. The host records receipt time before waiting for ingestion, so stalled storage cannot masquerade as fresh sensor health. Existing event-loss baseline/cooldown behavior remains.
3. **Sanitized credentials.** Recognized FILTERED/REDACTED/MASKED/HIDDEN placeholders are excluded. Bracketed literal credentials remain detectable; this does not exempt arbitrary uppercase bracketed values.
4. **Approval eligibility.** The CLI emits exact-approval/read-exception eligibility using the backend's shell-syntax and input-completeness checks. Swift consumes it instead of duplicating the rule list. Rejected quoted dollar signs/backticks are named explicitly, and the failure sheet no longer points to an unavailable read-exception action. Filesystem and content checks still happen at preview/grant time.
5. **Fingerprint coverage.** CLI, core, and rules hash all their own source files, build script, and manifest. Moving a classifier helper within those crates cannot silently exclude it. This deliberately favors conservative invalidation over avoiding rebuilds after unrelated source edits.
6. **Isolated crate builds.** Each crate exports its own fingerprint; no build script reads sibling directories. The CLI combines the three fingerprints with the policy document and home directory.
7. **Legacy scratch evidence.** An absent resolved path permits lexical classification only for records originally saved as an allow with the routine-temporary-activity message. Explicit resolution failure, protected resolved targets, and legacy ASK/WARN records remain visible. This is deliberately narrower than the suggested blanket legacy fallback, which would reopen symlink-related suppression. New sensor evidence has an explicit source tag; old sensor payloads require the full schema/actor/event shape for compatibility.
8. **Bounded cache generations.** Switching classifier generations removes obsolete classifications and their progress markers under the same writer transaction. Each classification batch rechecks its cursor under that lock. Returning to a pruned generation rebuilds it; fully cached refreshes avoid taking the writer lock. Busy writers leave unclassified alerts visible.
9. **Shared classification and SQL.** The remaining ingestion attribution gate uses AlertKind. Group-membership and recovered-prompt expressions are shared compile-time SQL fragments. Prompt recovery loads only displayed request/alert roots, while request detail loads its selected root; the global legacy-placeholder scan is gone. Original requests and alert-chain evidence remain unchanged.

## Validation

- Rust: 717 CLI, 73 store, and 25 database tests passed.
- Clippy passed for those three crates and all targets with warnings denied.
- macOS: 95 harness/model tests passed; the complete app built with signing disabled.
- Isolated CLI/core/rules build-script checks passed with only each crate's own files present. Mutating approval_memory.rs or a dependency source changed its fingerprint; unchanged input was deterministic.
- Regressions cover schema/cursor reset, future migration preservation, generation pruning/rebuild, writer contention, legacy scratch safety, quoted shell patterns, placeholder credentials, prompt recovery, and monitoring outages/stalls/flapping.

These changes are source updates to PR 112. This review pass does not install a new app or replace the active sensor; native notification delivery with a closed window was not exercised against the installed app.
