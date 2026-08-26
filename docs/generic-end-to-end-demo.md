# Generic end-to-end boundary demo

This demo starts with operator policy authoring and ends with two independently
observable outcomes:

- a negative operation whose prohibited network effect is denied; and
- a positive operation whose exact allowed effect succeeds, whose descendants
  are revoked, and whose verified product is atomically promoted.

The scenario is deliberately protocol- and application-neutral. The opaque
workload is just a process that can open a TCP connection and produce a
structured result. The contracts use the generic `network` capability and
`structured_result` product types; there is no package manager, browser, API
vendor, or experiment-specific policy in the runtime.

## Run it

The enforcement path requires Linux, root, cgroup v2, nftables, and a build of
the Gensee CLI:

```console
sudo ./scripts/demo-generic-boundary.sh
```

Use a dedicated test host. The script refuses to overwrite pre-existing
Gensee catalog or operation-manifest trust keys under `/etc/gensee`, installs
ephemeral owner-only test keys for the run, and removes only those keys during
cleanup.

To use an existing binary and retain evidence at a chosen new path:

```console
sudo env \
  GENSEE_BINARY="$PWD/target/debug/gensee" \
  GENSEE_DEMO_ROOT=/tmp/my-gensee-demo \
  ./scripts/demo-generic-boundary.sh
```

The script prints a compact `demo-summary.json` and retains all intermediate
artifacts under the reported directory.

## What the operator configures

The operator—not the agent—does the following:

1. Generates two safe contract templates with `gensee boundary catalog
   template`.
2. Leaves the negative contract at `network: deny_all` with no product.
3. Gives the positive contract exactly one TCP endpoint and a predeclared
   `out/result.json` product slot.
4. Pins the caller selector, contract owners, approvals, expiry, intent-analyzer
   identity and key, verifier identity/key/executable/configuration, and trusted
   promotion destination.
5. Signs the catalog with the organization key, verifies it, and installs it in
   the root-controlled catalog store.

The caller supplies an ordinary command. It never supplies a contract ID,
capability envelope, verifier, or destination. A trusted intent analyzer emits
a signed class inference. Gensee combines that class with the OS-observed caller
identity and resolves exactly one contract from the installed catalog. An
ambiguous or low-confidence result fails closed.

The demo's tiny intent model consumes normalized host-telemetry labels. This is
a runnable stand-in for a learned long-horizon analyzer, not a claim that the
fixture's two labels solve intent inference. Importantly, analyzer uncertainty
cannot invent authority: its output is only an operation class, and the signed
catalog remains the upper bound.

## Negative path

The analyzer classifies the command as `restricted_network_probe`. The signed
catalog selects `restricted_network_probe_v1`, whose network envelope is
`deny_all`. Before the process starts, Gensee:

- creates an operation ID;
- binds the complete Linux execution subject to that operation with cgroup v2;
- installs the nftables boundary; and
- then releases the process start gate.

The opaque process attempts TCP port `18081`. The packet is denied, the test
server observes no accepted connection, and the operation manifest records the
denied packet count. The contract declares no product, so no verifier or
promotion path exists.

This demonstrates deterministic prevention after probabilistic classification:
the analyzer may be fallible, but the selected contract cannot silently grow
new authority while the operation is running.

## Positive path

The analyzer classifies the second command as `approved_structured_transform`.
Its catalog contract allows only TCP `192.0.2.2:18080` and predeclares one
structured JSON result. The ordinary request succeeds. The workload also leaves
a descendant holding an allowed connection; Gensee terminates the entire
operation execution subject, the server observes the established connection
close, and the manifest records a drained subject.

Gensee then performs three distinct gates:

1. **Structural gate:** rehash the declared staged output, enforce size and
   entry limits, and reject unsafe filesystem objects or modes.
2. **Semantic gate:** run the catalog-pinned domain verifier without network,
   filesystem-write, or process-creation authority. The verifier receives the
   exact read-only snapshot of the staged product, checks its content policy,
   and signs a verdict bound to the contract and product digests. Gensee hashes
   the source, copies it into the private runtime, and verifies that the sealed
   snapshot retains the same digest before the verifier starts.
3. **Promotion gate:** prove operation authority is closed, recheck the product
   and receipt, copy it into an immutable object, and compare-and-swap the
   operator-selected `current` pointer with crash recovery.

## Evidence map

The retained directory contains:

| Artifact | Meaning |
| --- | --- |
| `operator/catalog-store/current.json` | Installed organization-signed contracts and selectors |
| `*-observation.json` | OS-observed caller and command binding plus trajectory references |
| `*-inference.signed.json` | Short-lived signed intent classification |
| `*-resolution.json` | Selected operation class and catalog contract; no caller-selected contract ID |
| `*-operation-manifest.json` | Allowed/denied effects, execution binding and drain state, product evidence |
| `verifier-request.json` | Nonce-bound exact contract/product challenge |
| `verifier-receipt.json` | Signed semantic verdict and isolation claims |
| `promotion-receipt.json` | Product, verifier, authority-closure and active-target binding |
| `server.log` | External confirmation of allowed traffic, denied traffic absence, and connection revocation |
| `demo-summary.json` | Concise human-readable outcome |

## What this proves—and what it does not

The privileged run proves that the boundary is active before either target
starts; contract-external traffic is denied; exact traffic is usable; descendant
processes and established authority are terminated; semantic-verifier identity
and policy cannot be substituted; and only the verified staged product becomes
active.

It does not prove that intent inference is always correct or that the example
content policy generalizes to every domain. Domain experts still author verifier
implementations. Gensee's generic contribution is to constrain an inference to
an approved contract, enforce its lifecycle, give the pinned verifier the exact
immutable candidate in isolation, authenticate its verdict, and make promotion
transactional rather than trusting the opaque producer.
