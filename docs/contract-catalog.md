# Approved operation-contract catalogs

An enforcement workload must not be allowed to choose its own capability
envelope. Gensee therefore treats an operation contract as organization-owned
configuration, not as a request field supplied by an agent or application.

Schema v1 catalogs contain:

- organization, application, and owning-team identity;
- monotonically versioned and expiring contract approvals;
- exact caller selectors made from trusted execution facts;
- operation-class-to-contract mappings with no wildcard precedence;
- approved intent-analyzer identities and public keys;
- minimum confidence and fail-closed ambiguity behavior;
- an optional explicitly approved safe-default contract.

The catalog is signed with an organization Ed25519 key. Verification checks
the signature, trusted public key, catalog and approval lifetimes, ownership,
contract validity, selector uniqueness, analyzer policy, and fallback target.
Changing any authority, selector, approval, or analyzer field invalidates the
signature.

```console
gensee boundary catalog sign \
  --catalog catalog.json \
  --key organization-seed.hex \
  --key-id organization-root-2026 \
  --output catalog.signed.json

gensee boundary catalog verify \
  --catalog catalog.signed.json \
  --trusted-key organization-public.hex
```

Signing is an administrative operation. Production admission should read only
signed catalogs from a root-controlled location and pin the trusted public
key. `gensee boundary run` pins that key at
`/etc/gensee/catalog-root-public-key.hex` and does not expose a key-selection
argument to the workload. The next admission stage observes the caller and command, verifies an
approved analyzer statement, and selects a catalog mapping. The analyzer can
nominate an operation class; it cannot provide a contract identifier or add a
capability.

This is intentionally generic. Contracts describe bounded effects and product
shapes; they do not contain protocol-specific request data,
application-specific rollback logic, or attack signatures.
