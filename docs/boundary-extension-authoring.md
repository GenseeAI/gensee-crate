# Boundary extension authoring

Gensee deliberately separates organization policy from domain integrations.
The organization decides **what may happen**; an extension implements **how a
particular system performs or checks that bounded operation**. An agent or
untrusted workload chooses neither.

## Ownership model

| Surface | Normally authored by | Normally approved/installed by | What Gensee keeps in core |
| --- | --- | --- | --- |
| Intent analyzer | Internal ML/platform team, vendor, or OSS contributor | Organization security/platform team | Observation schema, signed result binding, confidence/fallback rules, and class-to-contract resolution |
| Catalog and contract | Organization application/platform owner | Organization approver holding the catalog signing key | Schema validation, signatures, ownership/version checks, exact selector resolution, and safe templates |
| Semantic verifier | Domain team, vendor, or OSS contributor | Organization product/security owner | Exact product challenge, isolated execution, signed receipts, identity/policy pinning, and promotion gate |
| Capability provider | Service owner, vendor, or OSS contributor | Organization platform/security owner | Typed scopes, lease lifecycle, operation binding, deadlines, crash recovery, revocation, and effect receipts |

Contracts are policy data, not executable plugins. Reusable templates may come
from Gensee or the community, but an organization must review, own, sign, and
install the resulting catalog. Analyzer, verifier, and provider implementations
are trusted executable or service extensions with language-neutral JSON
protocols.

An extension is not allowed to redefine the surrounding security model:

- an analyzer nominates operation classes; it cannot name a contract or grant
  capabilities;
- a verifier returns a verdict about one exact product; it cannot grant
  authority or select a promotion destination;
- a provider receives one operation already attenuated to one active lease; it
  cannot widen the signed scope, generation, or deadline;
- only the signed catalog maps caller identity and operation class to policy.

The public Rust protocol types live in `gensee-crate-rules` under
`contract_catalog`, `semantic_verifier`, `provider_runtime`, and
`capability_broker`. Non-Rust implementations use the equivalent JSON shapes.
Every protocol rejects unknown fields.

These roles intentionally do not share one universal executable loader. An
analyzer may be a remote model service, a verifier must run without network or
filesystem mutation, and a provider may need narrowly mediated downstream
authority. Giving all three one ambient plugin environment would erase the
security boundary between them. They share versioned schemas, identity and
digest pinning, bounded I/O, and fail-closed selection, while retaining
role-specific runtimes and installation policy.

## Adding an intent analyzer

Input is an `IntentObservation`: bounded caller/command facts and references to
authenticated trajectory evidence. An external analyzer returns an
`IntentAnalyzerResult`:

```json
{
  "schema_version": 1,
  "analyzer_id": "organization_intent_v1",
  "model_identity": "model_release_2026_08",
  "candidates": [
    {
      "operation_class": "read_only_analysis",
      "confidence_bps": 9300,
      "rationale_code": "trajectory_model",
      "evidence_ids": ["effect_history_42"]
    }
  ]
}
```

The result intentionally omits the observation digest, inference ID, issuance
time, and expiry. The trusted wrapper adds those values and signs the complete
inference:

```console
gensee boundary intent sign-result \
  --catalog /etc/gensee/catalog.signed.json \
  --trusted-key /etc/gensee/organization-public.hex \
  --observation observation.json \
  --result analyzer-result.json \
  --analyzer-key /etc/gensee/analyzers/organization-intent.seed.hex \
  --ttl-seconds 60 --output inference.signed.json
```

To deploy it, the operator adds its ID, public key, immutable model identity,
allowed operation classes, and minimum confidence to the signed catalog. The
analyzer may be a local executable or remote service; transport credentials and
model hosting remain an operator concern. Keep the signing key in a narrow
trusted wrapper rather than in an agent-facing process. Test malformed output,
unknown/elevated classes, low confidence, ties, stale observations, incomplete
history, model rotation, and service failure. All must fail closed or select an
explicit catalog safe default.

The built-in scored-feature analyzer is only a runnable default. It is not the
required implementation model for external analyzers.

## Adding a catalog or contract

1. Start from `gensee boundary catalog template` or an organization template.
2. Declare exact caller selectors, operation classes, bounded capabilities,
   product slot/type/budgets, verifier profile, and optional promotion target.
3. Assign application/team ownership and a time-bounded approval.
4. Add only approved analyzer, verifier, service, and provider identities.
5. Run `catalog sign`, independently review the diff, and run `catalog verify`.
6. Install it into a root-controlled catalog root with `catalog install`.

The workload receives an observation and signed inference, not a contract
selector. Production admission resolves the approved contract from the signed
catalog. Adding a new contract therefore requires no core code change. Adding a
new capability *kind* or structural product *kind* does require a core schema
contribution and threat-model review.

## Adding a semantic verifier

The operator configuration is `IsolatedVerifierConfig`. It pins verifier ID,
policy version, executable path and SHA-256, fixed arguments, trusted working
directory, and runtime limit. The signed catalog approves the verifier public
key, allowed profiles/policy versions, isolation requirement, and digest of the
complete configuration.

At runtime the verifier receives `VerifierRequest` JSON on standard input and
the immutable product path in `GENSEE_VERIFIER_PRODUCT`. It writes exactly one
bounded `VerifierProgramResult` JSON object to standard output:

```json
{
  "verdict": "accept",
  "reason_codes": ["schema_and_policy_valid"],
  "validation_effect_manifest_digest":
    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}
```

Gensee runs the pinned executable in its verifier isolation profile and turns
that small result into a signed receipt bound to the exact request, operation,
contract, product digest, verifier identity, policy version, and isolation
evidence. Verifier code should never choose the product path or trust metadata
inside the product as its identity.

Test accept, reject, and indeterminate outcomes; malformed/oversized output;
timeouts; product mutation; policy-version mismatch; nondeterminism; and every
domain ambiguity that must not promote. A verifier is domain-specific by
design. Gensee authenticates and isolates it; Gensee does not infer domain
correctness itself.

## Adding a capability provider

The operator configuration is `ProviderRuntimeConfig`. It binds one adapter ID
to one resource kind, one executable digest, fixed arguments, trusted working
directory, and deadline. The lease selects that exact adapter ID; provider
dispatch rejects a different config even when it implements the same coarse
resource kind.

The provider reads one `ProviderInvocation` JSON object from standard input and
writes one bounded `ProviderAdapterResult` to standard output. It must:

1. authenticate the downstream service independently;
2. enforce the exact typed target/action/budgets in the invocation;
3. use idempotency and status/revoke operations supplied by the broker
   lifecycle where it creates external authority;
4. return no secret bytes—only opaque handles, mediated endpoints, digests, and
   effect metadata;
5. treat unknown state as indeterminate and fail closed.

Provider dispatch executes the pinned adapter snapshot inside an owned Linux
cgroup, drains all descendants, verifies the exact result bindings, and emits a
host-signed receipt. The provider implementation is still part of the trusted
computing base for its downstream protocol. For example, only a database-aware
provider can enforce transaction/read-only semantics against that database.

Implementations of existing resource kinds do not require core changes. A pull
request adding a new resource kind must add its typed scope, invocation variant,
attenuation rules, effect kind, adversarial conformance tests, and documentation
without embedding one customer's product names or credentials.

## Contributor checklist

- Keep domain logic in the extension; keep identity, lifecycle, signatures,
  deadlines, isolation, and promotion in the generic core.
- Use only the published JSON protocol and reject unknown fields.
- Never accept wildcard targets, caller-selected credentials, ambient proxy
  configuration, or caller-selected trust keys.
- Make configuration immutable and digest-pinned; make rotation explicit.
- Bound input/output bytes, runtime, concurrency, and durable state.
- Test crash points, replay, substitution, descendant escape, timeout,
  revocation, and malformed responses.
- Include one positive utility test and multiple negative authority-expansion
  tests.
- State precisely what the extension proves and what remains a domain or
  deployment assumption.

The examples under `integrations/boundary/extensions/` are protocol examples,
not pre-approved production policy. Operators must replace identities, paths,
digests, keys, classes, profiles, and targets, then sign the resulting catalog.
