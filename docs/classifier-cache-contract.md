# Historical alert classification contract

The dashboard caches whether immutable alerts are routine. A stale classification can hide a finding, so changes to this contract require explicit versioning.

The key combines `CLASSIFIER_CONTRACT_VERSION` from CLI, core, rules, and store, plus canonical policy JSON and home directory. Each crate owns its constant. **Bump that crate's constant whenever a change can alter a cached classification**, including:

- CLI: the historical classifier, housekeeping/scratch triage, protected approval-store filenames, or any helper they call.
- Core: path normalization, recorded-path interpretation, executable/build-output detection, or other predicates used by that classifier.
- Rules: policy evaluation, routine/sensitive-path categories, scratch adjustments, or overrides used during historical classification.
- Store: candidate selection, injected evidence fields, workspace/operation extraction, source identity, or cache schema/interpretation.

If a new crate starts contributing to classification, include its contract version in the key before using its output. Key-composition tests ensure each existing contributor, the policy, and home affect the key. A pinned corpus digest additionally covers the default policy against 576 combinations of rules, paths, operations, and evidence shapes. Changes to covered behavior or contract versions fail that test and require a reviewed pin update. This finite corpus does not prove coverage of every classifier dependency; checking the version and expanding the corpus remain part of reviewing semantic changes. Test-only changes, comments, and unrelated commands do not require a bump. These constants replace whole-source hashing and its duplicate build scripts; isolated/package builds do not read sibling source directories.

The store requires a stable version key at its public classifier API. It retains eight policy contexts and evicts the least recently used. Reusing a context refreshes recency without reclassifying its alerts; the already-most-recent warm context requires no writer lock. Switching to another warm context writes only its recency metadata. Eviction removes classifications and their cursor together. A frequently accessed app context survives a stream of cold contexts; a genuinely cold evicted context rebuilds when used again.

The key canonicalizes the full policy JSON, so whitespace and object-key ordering do not invalidate history. It intentionally retains all policy fields rather than relying on an incomplete list of classifier dependencies: unrelated semantic policy edits may still create a context. SQL-function installation is separate and does not register a fake classifier key.

Historical alerts retain their evidence and chain hashes. Both pretool and observation scratch adjustments carry `scratch_adjusted: true` and resolved-path evidence from a shared adapter. The historical classifier honors the structured adjustment only after checking the resolved target, original allow decision, and current policy boundaries. A false/null structured flag does not fall through to legacy text matching. For old rows lacking both this flag and resolved-path evidence, compatibility recognizes only the two historical built-in scratch rule IDs, an original allow action, and the historical routine message. Explicit failed resolution remains visible. Future message edits do not affect structured records.
