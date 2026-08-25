# Authenticated semantic-verifier receipts

Structural product checks answer questions such as “is this the declared tree,
at the declared path, with these hashes and no unsafe filesystem objects?” They
do not answer “is this content correct or safe for its intended use?” Gensee
keeps those claims separate.

After a producer exits and structural verification succeeds, the host can
create a bounded verifier request from the host-authenticated operation manifest:

```console
gensee boundary verifier request \
  --manifest operation-manifest.json \
  --ttl-seconds 120 \
  --output verifier-request.json
```

The request binds a fresh nonce and request ID to the operation ID, contract ID
and digest, structural product type and digest, verifier profile, and deadline.
The verifier profile comes from the approved contract; the producer cannot
substitute it.

A trusted verifier returns a signed receipt containing the exact request
digest and nonce, all product and contract bindings, its verifier identity,
policy version, verdict (`accept`, `reject`, or `indeterminate`), bounded reason
codes, and a digest of its own validation-effect manifest. The signed
organization catalog pins verifier public keys, the profile/policy-version
combinations each verifier may claim, and whether the verifier must run inside
Gensee's isolation boundary.

For an isolation-required verifier, the operator installs a root-controlled
configuration containing the verifier ID, policy version, absolute executable
and working-directory paths, executable SHA-256, fixed arguments, and a runtime
deadline. The catalog pins the canonical configuration digest, so the caller
cannot substitute arguments, paths, deadlines, or executable bytes. Gensee
copies the digest-checked executable and the exact digest-bound product into a
private runtime directory before execution, clears inherited environment and
descriptors, passes the request on standard input, and names the read-only
product snapshot in `GENSEE_VERIFIER_PRODUCT`. It accepts one bounded JSON
result on standard output, so a verdict cannot be detached from the immutable
product snapshot:

```console
gensee boundary verifier run \
  --catalog /etc/gensee/catalog.signed.json \
  --trusted-key /etc/gensee/organization-public.hex \
  --manifest operation-manifest.json \
  --request verifier-request.json \
  --config /etc/gensee/verifiers/content-policy.json \
  --verifier-key /etc/gensee/verifiers/content-policy.seed.hex \
  --output verifier-receipt.json
```

On Linux the child is restricted by Landlock to read/execute filesystem access
and by seccomp to no networking and no process creation. On macOS Seatbelt
denies network access, process forks, and filesystem writes. Unsupported
platforms fail closed. The receipt binds the isolation profile and executable
digest; a catalog that requires isolation rejects a receipt made by the manual
`attest` or `sign` paths without those claims.

Before launch, the host authenticates the operation manifest, rechecks its
successful and fully drained execution state, resolves the exact product
contract from the signed catalog, re-hashes the staged product, and copies that
exact digest-bound product into the private verifier runtime. The verifier
receives its read-only path in `GENSEE_VERIFIER_PRODUCT`; it does not receive a
request containing only an unverifiable digest.

`gensee boundary run` signs the complete manifest with the root-owned key at
`/etc/gensee/operation-manifest-signing-key.hex`. Request creation verifies it
against `/etc/gensee/operation-manifest-public-key.hex` before trusting the
operation, contract, product, process, or enforcement fields. A producer-made
JSON manifest cannot initiate semantic verification.

```console
gensee boundary verifier verify \
  --catalog /etc/gensee/catalog.signed.json \
  --trusted-key /etc/gensee/organization-public.hex \
  --request verifier-request.json \
  --receipt verifier-receipt.json
```

Changing the product, contract, nonce, verdict, policy version, effect digest,
or verifier identity invalidates either exact binding or the signature. An
expired or unapproved receipt fails closed. An `accept` receipt is necessary
for semantic promotion, but it is not sufficient by itself: transactional
promotion must also prove authority revocation and an unchanged staged product.

Verifier implementations remain domain-specific. Gensee's generic role is to
make the verifier identity and policy explicit, bind the challenge and verdict
to immutable evidence, prevent a producer from substituting either, and enforce
the same isolation lifecycle independent of the verifier's domain.
