# Authenticated semantic-verifier receipts

Structural product checks answer questions such as “is this the declared tree,
at the declared path, with these hashes and no unsafe filesystem objects?” They
do not answer “is this content correct or safe for its intended use?” Gensee
keeps those claims separate.

After a producer exits and structural verification succeeds, the host can
create a bounded verifier request from the operation manifest:

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
organization catalog pins verifier public keys and the profile/policy-version
combinations each verifier may claim.

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
to immutable evidence, and prevent a producer from substituting either. A
deployment should execute verifier code under a separate constrained identity;
the privileged generic conformance test covers that isolation boundary.
