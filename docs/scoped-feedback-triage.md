# Scoped feedback and local triage proposal

Status: the two feedback controls and explicit file/folder read exceptions are
implemented. Pattern suggestions and model-assisted triage below remain proposals.
The Review Queue no longer edits rules globally. Existing rule-wide overrides are
unchanged and can be reset in Policy. Exact-context approvals remain available.

“Always allow matching reads…” previews an exception for the current provider,
project, credential-content-read rule, and either the file or a selected containing
folder. The exception permits changing content and expires after 30 days. Settings
lists and revokes it. Dynamic commands, unresolved files, filesystem/home root
scopes, and non-read calls are rejected. `/tmp` and `/private/tmp` resolve to the
same scope on macOS. A separate block or unmatched approval requirement still
prevents execution. Historical decisions are preserved.

“This was a false positive” stores a separate local feedback label and marks the
finding read. It does not change policy, grant a permission, or silently suppress
future findings. The feedback can be withdrawn. Learning suggestions are not yet
implemented; no model service is called.

## Separate preference from detection feedback

“False positive” means the detector misinterpreted the evidence. Record a label,
matched indicator, detector version, operation, provider and project, with references
to original evidence. Do not infer that this approves future actions.

“Always allow matching reads…” means an explicit preference even if the detector
is correct. Open a preview of a new exception, rather than modifying the base rule.
Default scope is the provider, read operation, triggering rule, current project and
exact target. Offer an explicit directory-descendants scope and optional expiry.
For the reported case the user may choose `/private/tmp/` descendants; this applies
to the credential-content-read finding, not writes, execution, credential-path
protection, egress or other rules. Show this boundary in plain language.

Store exceptions locally, with ID, creator, source alert, timestamps, scope, expiry,
reason, usage count and revocation. Keep raw findings and record the exception ID
and resulting decision separately. Settings manages exceptions; Policy reserves
rule-wide controls for deliberate global changes. Historical evidence retains its
original decision and shows that a current exception matches it separately.

## Deterministic matching

Match canonical path components, not string prefixes (`/private/tmp2` must not
match). Resolve `/tmp` to its canonical equivalent. Reject unresolved, truncated,
symlink-escaping or dynamic targets. A read exception cannot authorize a mixed call
unless every other finding is independently allowed. Blocks and integrity rules
remain in force. Match provider and project unless the user explicitly expands
those scopes. Content-changing exceptions must be labeled as directory permission,
not as content-bound approvals.

Run: detection → mandatory protections → exact approvals / scoped exceptions →
remaining triage → final decision. Emit an auditable match reason. Do not require
network access or an LLM for the allow/ask/block decision.

## Learn suggestions, never silently expand permission

Aggregate explicit approvals and false-positive labels locally. Propose the narrowest
shared folder and operation only after examples from multiple sessions and distinct
paths; repeated clicks on the same alert are one example. Display covered examples,
recent unapproved findings that would also match, and the proposed scope. Several
approvals under `/private/tmp/aaa` and `/private/tmp/bbb` may justify suggesting their
parent; they do not authorize the parent. Never infer a filesystem/home root grant.
Use expiry, revocation, negative feedback and a preview-only evaluation period.

A later optional model can explain likely source-code/template false positives and
rank suggestions using redacted structured features. Treat file content and model
output as untrusted. The model cannot create exceptions, weaken blocks, or approve
action execution. Require user confirmation and compile accepted suggestions into
the same deterministic local matcher. Start with this local workflow; measure
repeat prompts, accepted/rejected suggestions and protected-case misses before
adding a model dependency.

## Migration and validation

Existing rule-wide overrides are too broad to convert automatically. Show their
current scope and let the user replace one with a previewed exception, atomically
restoring the base rule as that exception is installed. Do not silently reset or
broaden existing choices.

Test exact/prefix boundaries, `/tmp` aliases, symlink escape, different projects and
providers, mixed read/write/egress calls, changed content, mandatory block precedence,
expiry/revocation, concurrent updates, old override migration, immutable evidence,
and replay against labeled benign and malicious cases. Evaluate the credential
content detector separately: a Swift declaration or template is not proof that a
file contains a live credential; report “possible credentials” unless validated.

## Historical findings and approval previews

A quoted search pattern such as `"reconnect()"` is static shell input. Approval
previews accept literal parentheses but conservatively reject dollar signs and
backticks even inside quotes, because a child interpreter can expand them. Unquoted
subshells also require a fresh approval. Preview failures remain in the approval
sheet with recovery guidance instead of opening a generic application error.

An explicit read exception can refer to a cleaned-up temporary file or project.
Existing ancestors must resolve safely; dangling links, inaccessible paths, root
grants and unrelated targets remain invalid. Folder exceptions require an existing
containing folder. The preview still binds provider, project, read operation and
credential-content rule. This does not relax the original-content requirement for
exact approvals or grant permission for other operations.

Historical credential findings retain their recorded evidence but display “possible
credentials,” because a pattern match does not establish that a credential is live.
Routine Endpoint Security unlink records for ordinary scratch directories, as well
as files, are excluded from warning projections. Protected paths, denied actions,
symlinks, unknown types and directory renames remain visible; raw records and child
findings remain intact. This presentation filter never authorizes deletion.
