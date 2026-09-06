# PR 112 follow-up review (5125317605)

All ten findings are addressed:

1. Monitoring gaps have an independent runtime alarm. New kernel/ring losses totaling 100 events raise an in-app banner and an optional native notification, coalesced to at most one per minute. Startup counter history is seeded silently. Health sampling does not wait on dashboard database reads. These incidents stay out of agent request warnings.
2. Observe mode retains AUTH attempts targeting protected paths, as well as denials. Routine AUTH events still avoid serialization; NOTIFY remains their evidence source. This is a targeted attempt trail, not complete coverage of every failed syscall.
3. Bracketed credential literals and passwords containing brackets remain detectable. Identifier subscripts such as `document["secret_paths"]` remain excluded. The plural `api_keys` example is now recognized too (that key was not in the previous key list).
4. Remembered approvals conservatively reject dollar signs and backticks anywhere in shell input, including quoted interpreter programs. Literal quoted parentheses remain supported. This avoids claiming to understand every child interpreter's expansion rules.
5. Unavailable executable content cannot receive a content-bound remembered approval; the menu and backend eligibility agree. Cached content findings now carry the inspected content digest too.
6. Hook findings record their resolved target at evaluation time. Dashboard scratch filtering requires that evidence; legacy unresolved hook paths stay visible. Sensor vnode paths retain their normal treatment.
7. Legacy placeholder prompts recover their stored prompt on list, finding, and request-detail surfaces, including unlinked roots.
8. Classifier progress persists per policy key, and indexed SQL replaces the per-process set of every routine alert. Classification/group-backfill writer contention rolls back that batch and serves cached projections; unclassified findings remain visible. Schema 6 permits independent classifier versions. Its migration rebuilds only the derived classification cache.
9. The cache key includes a build-generated fingerprint of the classifier source files across the CLI, rules, and core crates, plus the policy document and home. Source changes automatically invalidate historical classification.
10. A central `AlertKind` mapping provides monitoring-health classification to ingestion, storage, and SQL, including legacy rows. Redundant ingest construction branches and duplicate visibility guards were removed. Existing alert evidence/hash-chain data is unchanged.

Validation covers protected-attempt capture, runtime alarm baselines and cooldowns, interpreter wrappers, credential literals versus subscripts, resolved hook targets, concurrent SQLite writers, classifier reuse across versions, prompt recovery, and the schema upgrade. These source changes require a newly signed/notarized sensor build before deployment; they do not alter the currently installed sensor.
