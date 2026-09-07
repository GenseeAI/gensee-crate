# Lineage and dashboard query measurements

These measurements address the PR #117 reviews of `269b82a` and `29cd7dd`.
They describe query cost on specific fixtures, not a guarantee for complete
Endpoint Security batches or harness runtime.

## Producer requests: cover the artifact-side lookup

`29cd7dd` replaced a scan of historical request relationships with a scan of
all requests. That improved one local store, but still made every file read
pay for unrelated request history. A forced destination index alone also
performs poorly for artifacts with many system-event relationships.

Schema version 8 adds the explicitly named covering index
`idx_relations_artifact_producer` on
`(dst_kind, dst_id, src_kind, relation_type, src_id)`. The production query
constrains its first four columns and returns producer IDs in index order,
then checks the matching request records. Neither unrelated requests nor
system-event edges of the artifact participate in that index range.
Production no longer references an automatically assigned index name.

Reproduce with:

```sh
cargo run --release -p gensee-crate-db --example benchmark-lineage-lookups
```

The example uses the repository schema and the actual production lookup,
with 60,000 requests, 860,000 relations, and 800,000 system-event edges for
one popular artifact. That artifact has 100 producers; the rare artifact
has one. It compares results on every iteration, including an absent artifact.
The superseded baseline intentionally retains its old autoindex reference
inside the benchmark only.

Measured on Apple Silicon/macOS, release build, bundled SQLite/SQLCipher,
un-encrypted in-memory synthetic data, no `ANALYZE`, three warmups and 21
measured iterations. Medians in milliseconds:

| Query | Popular artifact | Rare artifact | Absent artifact |
| --- | ---: | ---: | ---: |
| `29cd7dd`: scan requests | 14.3991 | 14.1727 | 14.2703 |
| Force existing `idx_relations_dst` | 33.3577 | 0.0043 | 0.0038 |
| Named covering index, production lookup | 0.0137 | 0.0040 | 0.0038 |

The covering lookup's p95 was 0.0188 ms for the popular artifact and 0.0042 ms
for the rare artifact. Adding another 60,000 unrelated requests changed the
rare median to 0.0042 ms (p95 0.0046 ms), instead of doubling a request scan.
Index construction took 315 ms on this in-memory fixture. An existing,
encrypted, multi-gigabyte store will have a different one-time index-build
cost and additional index storage/write overhead. The versioned upgrade test
checks that a version-7 store gains the index while preserving its request
and relation evidence, and can subsequently reopen normally.

The query deliberately preserves its historical non-NULL prompt predicate,
including empty strings. The consumer-side `is_human_request` check is
stricter. Aligning those two definitions would change existing lineage
eligibility and is outside this performance change; the regression test now
explains the distinction.

## Overview: event-count scaling remains

The dashboard rewrite trades repeated historical per-artifact scans for
request-scoped event scans. This avoids the original popular-path pathology,
but still scales with the number of events in the selected groups, even if
those groups touch few visible artifacts. It is not bounded by the number
of displayed file paths.

A fresh measurement on the existing local encrypted store, using
`GENSEE_DASHBOARD_TIMING=1 gensee dashboard-state`, reported these cumulative
phase times:

| Phase completed | Cumulative time |
| --- | ---: |
| Visible alerts | 2.157 s |
| Request rollups | 2.332 s |
| File touches | 14.171 s |
| Native touches | 14.374 s |
| Artifacts and relations | 15.653 s |
| Command wall time | 21.509 s |

Thus file touches alone consumed **11.839 s**. This was a single live-store
measurement under concurrent activity, not a percentile estimate. The new
producer index does not remove this separate dashboard cost.

Reproduce the event-count scaling independently of private data:

```sh
cargo test --release -p gensee-crate-store \
  benchmark_overview_file_touches_with_noisy_sensor_history -- --ignored --nocapture
```

The ignored benchmark uses one request, one visible modified artifact, and
increasing numbers of unrelated sensor events in that request. It calls the
actual overview file-touch function five times per size and asserts that
the complete results remain unchanged.

| Sensor events in request | Visible artifacts | Median file-touch time | Maximum of five |
| ---: | ---: | ---: | ---: |
| 1 | 1 | 0.276 ms | 0.308 ms |
| 10,000 | 1 | 0.530 ms | 0.626 ms |
| 100,000 | 1 | 11.151 ms | 11.275 ms |
| 500,000 | 1 | 59.436 ms | 60.751 ms |

This synthetic store has much less relationship fan-out, cache pressure,
and concurrent work than the real store. It confirms event-count scaling;
it does not predict the real store's absolute duration.

The review's referenced two-second timer in `DashboardOverviewPages.swift`
resets the copied-verification-command indicator. Dashboard refresh actually
runs in `DashboardShell.swift`: after each refresh it waits for
`min(120, max(10, lastDashboardRefreshDuration * 2))` seconds, from
`ConsoleModel.dashboardPollingSeconds`. Refreshes therefore do not start
on a fixed two-second cadence.

No silent event cap was added: dropping older observations can alter
`MAX(ts)` or whether a path is shown as OS-verified, and the ignored-path
sample limit is not an equivalent contract for these evidence aggregates.
An exact incrementally maintained summary, or a different join strategy
benchmarked across both high event counts and popular artifacts, is the
appropriate next step. The remaining overview cost is disclosed rather
than presented as solved by the producer-index change.

## Other review cleanup

- `cargo fmt --all` applied; timing messages share the `dashboard-request`
  prefix and distinguish CLI, group, and detail phases.
- Temporary-directory cleanup in the evidence-scope test follows sibling
  tests' best-effort cleanup convention.
- The unrelated native cumulative-loss regression was removed from this PR;
  production sensor behavior was not changed by that test.
