# Distributed operation context

An operation ID is useful across services only when the receiving service can
authenticate who issued it and prove that a hop did not add authority. Gensee
therefore propagates a signed context chain rather than a trusted-by-convention
HTTP header.

Each context binds:

- the initiating operation ID;
- the signed catalog and selected contract digests;
- issuer and audience service identities;
- a strictly increasing generation;
- issuance and expiry times;
- the exact parent-context digest;
- a set of capability-grant IDs, resource kinds, scope digests, lease
  generations, and deadlines.

The organization catalog registers each service's Ed25519 public key, whether
it may initiate an operation, and its exact downstream audiences. A child is
valid only when its issuer was the parent's audience, its generation is the
parent generation plus one, its operation/catalog/contract identities are
unchanged, its deadline is no later, and every grant is an unchanged or
shorter-lived subset of a parent grant. A service cannot introduce a new grant,
change a scope digest, replace a lease generation, or forward to an
unregistered audience.

For generation zero, the verifier recomputes the digest of the verified signed
catalog and requires the contract digest to identify one of that catalog's
approved contracts. A service cannot establish a root context with invented
but syntactically valid catalog or contract digests.

```console
gensee boundary context issue \
  --catalog /etc/gensee/catalog.signed.json \
  --trusted-key /etc/gensee/organization-public.hex \
  --claims context-claims.json \
  --service-key /run/keys/service-seed.hex \
  --output context-chain.json

gensee boundary context verify \
  --catalog /etc/gensee/catalog.signed.json \
  --trusted-key /etc/gensee/organization-public.hex \
  --chain context-chain.json \
  --audience worker-service
```

`--parent-chain` appends an attenuated hop after verifying the entire existing
chain. Chain depth is bounded. The service private key must match the
catalog-approved issuer; private key material never appears in the token.

## Downstream effects

A downstream service can sign an effect record containing the operation ID,
the exact received context digest, its own service identity, an effect-kind
token, the effect-manifest digest, time, and an optional previous-effect digest.
`effect-verify` authenticates the service key and checks that the record was
created for the final audience during the context lifetime. This provides an
end-to-end attribution link without treating the propagated operation ID as an
OS identity or as proof by itself.

Transport integrations carry the serialized chain through their authenticated
request mechanism. The protocol is transport-neutral; an HTTP gateway, local
socket service, task queue, or worker RPC can use the same verification rules.

## Transport middleware envelope

`transport-wrap` binds a bounded payload digest, content type, nonce, sender,
recipient, context-tail digest, and shorter deadline into an Ed25519-signed
envelope. `transport-verify` requires the service identity independently
derived by the transport—such as an mTLS SPIFFE identity or Unix peer
credential—to equal the signed sender before releasing the payload. Supplying
an operation ID in a plain header is not sufficient.

After signature, peer, context, deadline, and payload verification, the
recipient atomically records the context/recipient/nonce tuple in its private
state before releasing the payload. A second delivery of the same envelope is
denied even while its signature and TTL remain valid. The nonce store is part
of the receiving service's trusted deployment state and must not be shared
with an untrusted caller.

```console
gensee boundary context transport-wrap \
  --catalog catalog.signed.json --trusted-key organization.hex \
  --chain gateway-to-worker.json --payload request.bin \
  --content-type application_json --service-key gateway.seed \
  --ttl-seconds 30 --output request.envelope.json

gensee boundary context transport-verify \
  --catalog catalog.signed.json --trusted-key organization.hex \
  --chain gateway-to-worker.json --envelope request.envelope.json \
  --peer-service gateway --output verified-request.bin
```

The CLI's `--peer-service` is an integration boundary, not caller testimony:
production middleware must populate it from its authenticated channel. The
same verifier is reusable in HTTP, RPC, queue, and local-socket adapters.
