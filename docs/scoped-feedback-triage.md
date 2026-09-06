# Scoped feedback and local triage proposal

Status: proposed follow-up. The current implementation still supports rule-wide
review overrides and exact-context remembered approvals. It does not silently learn
folder exceptions. UI labels now explicitly identify rule-wide overrides.

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
