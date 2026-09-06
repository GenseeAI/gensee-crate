# Historical alert classification contract

The dashboard caches whether immutable alerts are routine. A stale classification can hide a finding, so changes to this contract require explicit versioning.

The key combines `CLASSIFIER_CONTRACT_VERSION` from CLI, core, rules, and store, plus the policy document and home directory. Each crate owns its constant. **Bump that crate's constant whenever a change can alter a cached classification**, including:

- CLI: the historical classifier, housekeeping/scratch triage, protected approval-store filenames, or any helper they call.
- Core: path normalization, recorded-path interpretation, executable/build-output detection, or other predicates used by that classifier.
- Rules: policy evaluation, routine/sensitive-path categories, scratch adjustments, or overrides used during historical classification.
- Store: candidate selection, injected evidence fields, workspace/operation extraction, source identity, or cache schema/interpretation.

If a new crate starts contributing to classification, include its contract version in the key before using its output. Key-composition tests ensure each existing contributor, the policy, and home affect the key. They cannot detect a forgotten version bump: checking the version is part of reviewing a semantic classifier change. Test-only changes, comments, and unrelated commands do not require a bump. These constants replace whole-source hashing and its duplicate build scripts; isolated/package builds do not read sibling source directories.

The store requires a stable version key at its public classifier API. It keeps the eight most recently **registered** generations, allowing ordinary app/project-policy contexts to coexist. It prunes an older generation's classifications and cursor together when registering a ninth. Returning to an evicted generation rebuilds it. Merely alternating two warm contexts performs no reclassification and acquires no writer lock. Beyond eight distinct contexts, rebuilds remain possible; the bound controls storage growth rather than promising unlimited context reuse.

Historical alerts retain their evidence and chain hashes. New scratch adjustments carry `scratch_adjusted: true` from the policy evaluator into recorded evidence. A false/null structured flag does not fall through to legacy text matching. For old rows lacking both this flag and resolved-path evidence, compatibility recognizes only the two historical built-in scratch rule IDs, an original allow action, and the historical routine message. Explicit failed resolution remains visible. Future message edits do not affect structured records.
