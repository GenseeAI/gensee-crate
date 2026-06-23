# SQLite lineage graph

In addition to JSONL files, the local store writes a normalized SQLite database
at `$GENSEE_HOME/gensee.db` (or `~/.gensee/gensee.db`).

> Diagrams: [capture flow](gensee_database_capture_flow.svg) ·
> [schema relationships](gensee_database_schema_relationships.svg) ·
> [policy flagging](gensee_database_policy_flagging.svg) ·
> [full design (PDF)](gensee_database_design.pdf)

## Tables

| Table | Contents |
| --- | --- |
| `sessions` | One row per agent conversation or monitoring run. Agent identity belongs here, not on each request. |
| `requests` | Human-level prompts and final responses, owned by a session. |
| `agent_events` | Agent/tool intent events owned by a request — `PreToolUse`/`PostToolUse`, native file tools, and parsed Bash file intent. |
| `system_events` | Observed OS/workspace effects owned by the best-correlated request, or by a synthetic monitoring request when no human request is known. |
| `artifacts` | Durable objects such as files, keyed today by kind, URI, and an optional digest. File artifacts usually use `file://...` URIs. |
| `relations` | Typed graph edges between requests, events, and artifacts. |
| `alerts` | Deterministic risk findings over requests, events, and artifacts, including the recommended runtime action (see [policy.md](policy.md)). |
| `artifact_observations` | Bounded, redacted content snapshots of inspected artifacts (digest, size, content prefix), captured at write-time (`PostToolUse`) and pre-execution. |
| `artifact_risk_tags` | Risk findings over a specific artifact **content digest**, so a tag is ignored once the file content changes. Drives the fast pre-exec block path. |
| `artifact_facts` | One row per file **URI** (not per digest), summarizing provenance across content versions: last modifier/session, agent-authored vs. modified-outside-agent, registry membership (executable / memory / persistence / control-plane), and current risk. Updated at ingest; queried by exact-path lookup during `PreToolUse`. |

## Relationships

The graph can currently establish:

- **request → agent event**: direct ownership through `agent_events.request_id`
- **request → system event**: direct ownership through `system_events.request_id`
- **request/agent event → artifact**: produced, modified, or deleted file intent
- **artifact → request/agent event**: consumed file intent
- **artifact → artifact**: file-to-file lineage, e.g. copy source to copy
  destination, or a summary file derived from input files
- **request → request**: derived lineage when a later request consumes an
  artifact produced by an earlier human request
- **agent event → system event**: inferred correlation when an observed
  filesystem effect matches a nearby file intent path or tool window

## Example queries

```sql
-- Everything known about a file artifact.
with target as (
  select artifact_id from artifacts
  where uri = 'file:///private/tmp/gensee-lineage/input.txt'
)
select rel.relation_type,
       rel.src_kind,
       rel.src_id,
       rel.dst_kind,
       rel.dst_id,
       substr(rel.evidence, 1, 160) as evidence
from relations rel, target
where (rel.src_kind = 'artifact' and rel.src_id = target.artifact_id)
   or (rel.dst_kind = 'artifact' and rel.dst_id = target.artifact_id)
order by rel.relation_id;
```

```sql
-- Human request lineage: which later prompts derived from earlier prompts.
select r.src_id as src_request,
       substr(src.original_user_prompt, 1, 80) as src_prompt,
       r.dst_id as dst_request,
       substr(dst.original_user_prompt, 1, 80) as dst_prompt,
       r.evidence
from relations r
join requests src on r.src_kind = 'request' and r.src_id = src.request_id
join requests dst on r.dst_kind = 'request' and r.dst_id = dst.request_id
where r.relation_type = 'derived_from'
order by r.relation_id;
```

## What Gensee can flag today

- agent intent to read, write, copy, delete, or move files from hooks and
  parsed Bash commands
- native file-tool access when hooks include tool input
- runtime [policy](policy.md) decisions for `PreToolUse`, with `deny` for
  sensitive reads, destructive operations, and writes outside the current
  workspace
- dangerous content inside a script at execution time (assembled across
  fragments/sessions), via digest-keyed pre-execution inspection
- provenance-aware `ask` for executing an artifact authored in another session
  or modified outside the agent
- session-scoped `ask` for network egress that follows a sensitive-artifact read
  in the same session (read→exfil chain)
- filesystem create/modify/delete/rename effects under watched roots
- access to configured sensitive roots such as `~/.ssh`, `~/.aws`, and
  `~/.config/gcloud`
- suspicious data-flow shape, such as a sensitive/local artifact consumed by a
  later request that writes another artifact
- high-confidence lineage when a native tool or explicit Bash path names the
  artifact, and medium/low-confidence lineage for time-window or FSEvents
  inference

## Tamper-evident alert chain (T8)

The `alerts` table is an append-only **hash chain**: each row carries
`entry_hash = SHA-256(prev_hash || canonical(row content))`, and `prev_hash`
links to the previous alert's `entry_hash` (the first chained alert links to a
genesis hash of 64 zeros). The content is fed length-prefixed, so no field value
can be shifted into an adjacent field to forge a match.

```
gensee verify-log
```

walks the chain from genesis and reports the first break, exiting `0` if intact
and `2` if tampering is detected. It catches:

- **modification** of any chained row (its `entry_hash` no longer recomputes);
- **insertion** — including a forged row with NULL hashes appended after the
  chain start (every row at/after the start must be chained);
- **middle deletion / reorder** (the next row's `prev_hash` no longer links);
- **tail truncation** — deleting the newest alerts leaves the survivors linking
  cleanly, so it is caught against a single-row anchor (`alert_chain_head`) that
  records the latest `entry_hash` and chained count, advanced transactionally
  with each insert. A head/count mismatch reports a break "at the tail".

Legacy alerts written before the chain existed have a NULL `entry_hash` and are
excluded; the chain starts fresh at the first new alert.

**Threat model.** The chain + anchor detect accidental corruption and any
tampering by a party that cannot recompute the whole chain — including the agent
rewriting its own audit trail or truncating the tail. A local attacker who can
rewrite the *entire* database — recomputing every `entry_hash` **and** updating
the `alert_chain_head` anchor — is out of scope until the head is signed with a
key the agent cannot reach or shipped to an append-only / off-box sink (planned).

## What is not solved yet

- FSEvents does not prove which process caused a file effect; it is path/time
  correlation only, so "modified outside the agent" is a heuristic and drives
  `ask`, not `deny` (EndpointSecurity exec attribution is the planned upgrade).
- Hook enforcement is deterministic and path/tool based; it does not yet use
  semantic prompt analysis or user/session-specific policy files.
- Content rules are deterministic substring/shape matches over normalized
  content — an evadable floor, not a complete analysis.
- Network egress lineage is not yet tied to artifact contents or destinations.
- Prompt injection, malicious tool output, exfiltration, and cross-session
  attack chains can be surfaced as graph patterns, but the defense rules are
  still early and mostly deterministic.
- Automatic rollback, merge-back review, deny-default policies, and container
  confinement are future work.
