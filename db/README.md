# db

SQLite schema, Rust storage module, and benchmark tooling for gensee-crate.

This is the local-only event store: no `api_key`, `project_id`, `user_id`, `ip`,
or server-side ingestion tables (`envelope`, `projects`). The Rust crate
(`gensee-crate-db`) uses `rusqlite` (sync, embedded) to match the rest of the
codebase — `open_store()` returns a `SqliteStore` with typed insert, lookup, and
update methods for the schema tables so callers do not need to execute raw SQL.
`SqliteStore::insert_request()` allocates and returns the `request_id`; event
insert methods likewise return generated event IDs where SQLite owns the key.
For lower-level integrations, `open()` still returns a single `Connection` with
`foreign_keys = ON`, a `busy_timeout`, and the configured
journal/synchronous/auto_vacuum pragmas applied, then ensures `schema.sql`
(idempotent, `CREATE ... IF NOT EXISTS`) is loaded.

`requests.events` is an optional JSON cache/summary of request-level event state.
The normalized event source of truth remains `agent_events` and `system_events`
keyed by `request_id`.

## Current schema model

The database models three layers:

- Human intent: `sessions` own `requests`. `sessions.agent_id` identifies the
  agent runtime, while each request stores the user's prompt and the final
  assistant response.
- Agent intent: `agent_events` belong to requests and capture hook/tool events,
  including parsed file intent from Bash commands and native Claude file tools.
- System impact: `system_events` belong to the best-correlated request and
  capture observed OS/workspace effects.

`artifacts` are durable objects that requests and events act on. A file artifact
uses `kind = 'file'` and a `file://...` URI. Artifacts are currently deduped by
`kind`, `uri`, and `digest`; most file observations use an empty digest, so
multiple content versions at the same path collapse to one artifact node.

`relations` is the typed lineage graph. It stores edges between `request`,
`agent_event`, `system_event`, and `artifact` nodes, with a relation type,
confidence, and JSON evidence. Direct ownership is stored on the event tables
instead of duplicating every request/event ownership edge in `relations`.

`alerts` stores deterministic risk findings over the graph and over `PreToolUse`
policy decisions. Each alert can point at a request and an optional agent-event,
system-event, or artifact entity. Alerts derived from passive workspace or
system observations may not have a `tool_use_id`, so they appear in the global
timeline alert list rather than under a specific tool call. It records severity, recommended
action (`allow`, `warn`, `ask`, `block`), rule ID, message, optional path, and
JSON evidence. The CLI timeline renders recent alerts as "Policy alerts".

Current edge meanings include:

- `produced`, `modified`, `deleted`: a request or event wrote to an artifact.
- `consumed_by`: an artifact was read or otherwise used by a request or event.
- `derived_from`: a later request or artifact was derived from an earlier
  request or artifact.
- `observed_as`: an agent-level file intent was correlated with a system-level
  filesystem effect.

Useful inspection queries:

```sql
-- Table counts.
select 'sessions' table_name, count(*) n from sessions
union all select 'requests', count(*) from requests
union all select 'agent_events', count(*) from agent_events
union all select 'system_events', count(*) from system_events
union all select 'artifacts', count(*) from artifacts
union all select 'relations', count(*) from relations
union all select 'alerts', count(*) from alerts;
```

```sql
-- All relations touching one artifact.
with target as (
  select artifact_id from artifacts
  where uri = 'file:///private/tmp/gensee-lineage/input.txt'
)
select rel.relation_id,
       rel.relation_type,
       rel.src_kind,
       rel.src_id,
       rel.dst_kind,
       rel.dst_id,
       rel.confidence,
       substr(rel.evidence, 1, 160) as evidence
from relations rel, target
where (rel.src_kind = 'artifact' and rel.src_id = target.artifact_id)
   or (rel.dst_kind = 'artifact' and rel.dst_id = target.artifact_id)
order by rel.relation_id;
```

```sql
-- Artifact-to-artifact lineage.
select src.uri as src_artifact,
       r.relation_type,
       dst.uri as dst_artifact,
       r.confidence,
       substr(r.evidence, 1, 160) as evidence
from relations r
join artifacts src on r.src_kind = 'artifact' and r.src_id = src.artifact_id
join artifacts dst on r.dst_kind = 'artifact' and r.dst_id = dst.artifact_id
where r.relation_type = 'derived_from'
order by r.relation_id;
```

```sql
-- Human request lineage.
select r.src_id as src_request,
       substr(src.original_user_prompt, 1, 80) as src_prompt,
       r.dst_id as dst_request,
       substr(dst.original_user_prompt, 1, 80) as dst_prompt,
       substr(r.evidence, 1, 160) as evidence
from relations r
join requests src on r.src_kind = 'request' and r.src_id = src.request_id
join requests dst on r.dst_kind = 'request' and r.dst_id = dst.request_id
where r.relation_type = 'derived_from'
order by r.relation_id;
```

```sql
-- Recent policy/risk alerts.
select a.created_at,
       a.severity,
       a.action,
       a.rule_id,
       r.session_id,
       substr(a.message, 1, 100) as message,
       a.path
from alerts a
left join requests r on r.request_id = a.request_id
order by a.created_at desc, a.alert_id desc
limit 50;
```

Known limits:

- FSEvents-based system events are path/time correlations, not process-proof
  causality.
- Claude hook policy is deterministic and path/tool based; semantic prompt
  injection and intent mismatch detection are future work.
- Relation vocabulary and artifact content-versioning are intentionally simple
  for now and may need tightening before policy enforcement depends on them.

## Initial setup

Requires `pyyaml`, `numpy`, and `matplotlib`:

```bash
pip3 install pyyaml numpy matplotlib
```

## Synthetic per-request event streams (`populate_agent_events.py`)

```bash
cd db
python3 populate_agent_events.py
```

Fills `sessions`, `requests`, `agent_events`, and `system_events` (against the database at `sqlite.path`, e.g. `db/gensee-crate.db`) with `NUM_REQUESTS` (500) synthetic requests: each request gets one row in `sessions` and `requests`, plus a random number — uniformly distributed between `MIN_AGENT_EVENTS`/`MIN_SYS_EVENTS` (10) and `MAX_AGENT_EVENTS`/`MAX_SYS_EVENTS` (80) — of `agent_events` (tool-call hook events) and `system_events` (kernel/process-level events), all sharing the request's `request_id`. This matches the access pattern in `queries.sql` — "fetch every event recorded for request X, oldest first" — and is the same generator `bench.py`'s `populate_requests()` uses for the query benchmarks.


## Running the benchmark

```bash
cd db
python3 bench.py
```

The script is self-contained: it reads config from `db/sqlite.yaml`, builds a temporary SQLite database (`bench.db`, created at the repo root and deleted again at the end), runs the benchmarks, writes plots to `db/output/`, and prints progress/summary stats to stdout.

## Configuring `sqlite.yaml`

It has two sections:

`sqlite:` — SQLite connection/pragma settings (`path`, `journal_mode`, `synchronous`, `auto_vacuum`, `shared_cache`). `bench.py` applies `journal_mode`, `synchronous`, `auto_vacuum`, and `shared_cache` as PRAGMAs in `make_db()`, so editing this section changes benchmark behavior. `path` is informational only (the benchmark always uses a temporary `bench.db`).

`make_db()` creates a single connection and reuses it for every benchmark, so these pragmas are in effect for the query benchmarks too — but `journal_mode`, `synchronous`, and `auto_vacuum` only govern how SQLite *writes* (how it manages the WAL/rollback journal, when it `fsync`s, and when it reclaims freed pages), which is why they affect write durability/locking rather than read performance. A plain `SELECT` doesn't touch the journal or call `fsync`, so these settings have little direct effect on `query_latency`/`query_throughput`. What *does* affect read latency is SQLite's in-memory page cache — which is what `query_latency_cold`'s `PRAGMA shrink_memory` isolates (see below).

### Pragma settings

- **`path`** — filesystem location of the database file. **Warning:** `populate_agent_events.py` deletes and recreates whatever file this points at (plus its `-wal`/`-shm` sidecars) on every run — never point it at a production or otherwise important database.
- **`journal_mode`** — how SQLite manages transaction journals. `wal` (write-ahead log) is recommended: it allows readers and writers to proceed concurrently without blocking each other, and is generally the fastest mode that's still crash-safe. The alternatives (`delete`, `truncate`, `persist`, `memory`, `off`) use a rollback journal that locks the whole database during writes; `memory`/`off` additionally risk corruption on a crash.
- **`synchronous`** — how aggressively SQLite calls `fsync` to flush writes to disk. `normal` syncs at critical moments and is safe when paired with `wal` (a crash can lose the last commit but won't corrupt the database) — a good speed/durability balance. `full` syncs after every transaction (safest, slowest); `off` never syncs (fastest, but a crash can corrupt the database).
- **`auto_vacuum`** — whether/how SQLite reclaims space from deleted rows. `full` reclaims pages on every commit, keeping the file size minimal at the cost of some write overhead. `incremental` defers reclamation until `PRAGMA incremental_vacuum` is run manually. `none` never reclaims automatically — the file only shrinks via a manual `VACUUM`.
- **`shared_cache`** — whether multiple connections to the same database file share a single page/schema cache. `true` reduces memory and I/O when many connections hit the same DB; `false` gives each connection its own independent cache (simpler locking semantics, more memory).

`bench:` — controls what `bench.py` actually does:

- **`tables`** — list of table names to benchmark inserts against. All tables in `db/schema.sql` are created regardless; this must be a subset of those defined in `bench.py`'s `TABLE_DEFS` (`sessions`, `requests`, `agent_events`, `system_events`). Remove entries to benchmark fewer tables.
- **`queries`** — list of read queries to benchmark (see `queries.sql`). Must be a subset of those defined in `bench.py`'s `QUERY_DEFS` (`request_agent_events`, `request_system_events`).
- **`evaluations`** — list of `latency`, `throughput`, `query_latency`, `query_latency_cold`, and/or `query_throughput`. Remove any to skip that benchmark entirely.

## What it shows

**Latency CDF** (`db/output/latency.png`): for each table, inserts 5,000 rows one at a time, recording the commit latency of each individual insert. Plots the cumulative distribution (x = latency in ms, log scale; y = cumulative fraction), with each table's p99 latency marked and labeled. Tells you the per-insert commit cost and tail latency for each table's schema.

**Throughput** (`db/output/throughput.png`): for each table, simulates Poisson-distributed insert arrivals at increasing target rates (2K → 500K req/s), measuring how many inserts/sec actually complete. Plots arrival rate vs. completed rate (both log scale) against an "ideal" diagonal (completed = arrival), with a star marking where each table's line falls below 85% of the ideal — i.e., where the table's insert throughput saturates.

Together these show per-table insert latency and the maximum sustainable write rate under SQLite's WAL/NORMAL settings.

**Query latency CDF** (`db/output/query_latency.png`) and **query throughput** (`db/output/query_throughput.png`): same methodology as above, but for the read queries in `queries.sql` instead of inserts. Before these run, `populate_requests()` fills `sessions`/`requests`/`agent_events`/`system_events` with synthetic per-request event streams (the same generator as `populate_agent_events.py` — see "Synthetic per-request event streams" below) so the queries have realistic data:

- **`request_agent_events`** — `SELECT * FROM agent_events WHERE request_id = ? ORDER BY ts`, with a random `request_id`.
- **`request_system_events`** — `SELECT * FROM system_events WHERE request_id = ? ORDER BY ts`, with a random `request_id`.

Both queries are served by the `idx_agent_events_request_ts` and `idx_system_events_request_ts` indexes in `schema.sql` (composite `(request_id, ts)` indexes, so the `WHERE` filter and `ORDER BY` are both satisfied by a single index scan). The `relations` table also has indexes on both request endpoints and each event endpoint for correlation lookups.

**Cold-cache query latency CDF** (`db/output/query_latency_cold.png`): same as `query_latency`, but runs `PRAGMA shrink_memory` before every query to drop SQLite's page cache, so each query has to re-read its b-tree pages instead of reusing pages cached by earlier iterations. This isolates SQLite-cache effects (it doesn't drop the OS file cache, which would require `sudo purge` and isn't practical per-iteration) — compare against `query_latency.png` to see how much warm-cache reuse is helping.
