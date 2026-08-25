# Generic transactional promotion

The producer writes only to a staged product slot. After the complete
execution subject is drained, Gensee canonicalizes the eligible product to
read-only modes and computes the digest that a semantic verifier sees. A
trusted destination and active-pointer name are part of the
organization-signed operation contract; the producer cannot choose where its
result is installed.

`gensee boundary promotion apply` admits a product only after all of these
conditions hold under one destination lock:

1. the operation manifest is bound to the current signed catalog and exact
   contract digest;
2. a fresh structural scan matches the manifest's product type, digest, entry
   count, and byte count;
3. a catalog-approved semantic verifier signed an `accept` receipt for that
   exact operation, contract, product, nonce, profile, and policy version;
4. every broker lifecycle for the operation is synchronously driven to a
   terminal state, and a host-authenticated closure has no active or unresolved
   lease IDs;
5. a second structural scan proves the staged product did not change during
   revocation;
6. the caller's expected active target still matches, providing a
   compare-and-swap precondition.

The host preserves the sealed modes while copying the product into a
deterministic immutable object, re-scans both before and after its read-only
freeze, and atomically renames a relative symlink to select that object. The
manifest, verifier receipt, object, and public proof therefore retain one exact
mode-bound digest. Promotion supports every structural product class because
it operates on the declared product tree rather than a domain-specific
installation format.

A host-signed crash journal records `prepared`, `switching`, `complete`, and
`rolled_back` phases together with the old and new targets and all evidence
digests. Recovery uses the same global lock and restores the previous target
only if the active pointer still equals the interrupted transaction's new
target. A stale journal therefore cannot roll back a newer successful
promotion. Immutable receipts make identical completed promotion requests
idempotent.

```console
sudo gensee boundary promotion apply \
  --catalog /etc/gensee/catalog.signed.json \
  --trusted-key /etc/gensee/organization-public.hex \
  --manifest operation-manifest.json \
  --verifier-request verifier-request.json \
  --verifier-receipt verifier-receipt.json \
  --expected-current none \
  --output promotion-receipt.json
```

The destination must already be owner-controlled and non-group/world-writable.
Internal object, journal, receipt, and lock paths are host-owned. Promotion is
not application rollback: it atomically selects a verified staged product and
can restore the previous selection after an interrupted switch. It does not
repair arbitrary private state in an opaque producer that was denied midway
through its own transaction.
