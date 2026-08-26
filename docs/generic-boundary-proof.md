# Privileged generic boundary proof

The public conformance test exercises the unified boundary with an opaque
process and a generic `structured_result`. No application protocol, artifact
format, or attack signature is built into the enforcement path.

Run it as root on a Linux host with cgroup v2, nftables, `ip`, `jq`, `openssl`,
Python 3, and Rust installed:

```console
sudo ./scripts/test-generic-boundary-proof.sh
```

The script creates a temporary TEST-NET address and two TCP listeners. Its
signed catalog allows one exact endpoint and denies everything else for the
operation execution subject. It then:

1. signs an organization-owned catalog containing caller selection, an
   approved intent analyzer, an exact capability envelope, a verifier profile,
   and a predeclared promotion destination;
2. records preflight behavior, signs a probabilistic operation-class
   inference, and proves that catalog policy—not the workload—selects the
   contract;
3. installs the cgroup/nftables boundary before releasing the target start
   gate;
4. proves an ordinary allowed round trip succeeds and an unexpected endpoint
   is denied;
5. has a descendant create a new session while keeping an established allowed
   connection, then proves termination drains the entire cgroup and closes the
   connection before enforcement is removed;
6. structurally verifies a staged result, gives an immutable digest-bound copy
   to the catalog-pinned semantic verifier, makes the verdict depend on the
   expected result fields, and denies verifier filesystem mutation, networking,
   and process creation,
   authenticates its receipt, closes operation-scoped broker authority, and
   atomically promotes the unchanged result;
7. signs a fixed evidence bundle and runs `gensee boundary proof verify` to
   re-check its hashes, host-authenticated operation manifest, catalog, intent
   evidence, operation identity, network effects, verifier receipt, promoted
   content, and promotion bindings.

The Python programs are traffic/product fixtures, not trusted enforcement
components. Replacing them with another opaque executable does not change the
catalog, identity, enforcement, verifier, promotion, or proof protocols.

The conformance verifier deliberately asserts only the fixture's known
semantics. In production, a catalog-approved domain verifier must inspect the
product and return its own signed verdict. Gensee authenticates and binds that
verdict; it does not infer semantic safety from hashes or file layout.

## What the proof establishes

- An approved contract is resolved from an OS-observed caller and an
  authenticated, potentially fallible intent inference.
- The effective network boundary exists before target execution.
- Exact allowed traffic remains usable while unexpected traffic is denied.
- Descendants remain in the same OS enforcement subject even after changing
  process group or session, and terminal cleanup revokes that subject before
  removing its policy. The established connection is closed and the fixture
  observes no new connection from that subject after revocation.
- The semantic verifier runs from the catalog-pinned executable/configuration,
  reads the exact immutable staged product, and runs under an independent
  no-write/no-network/no-process-creation boundary.
- A structurally and semantically verified product can be promoted without
  giving the producer control of the destination.
- A verifier with only the bundle and trusted public keys can detect evidence
  or product substitution.

The proof signer and verifier both authenticate the operation manifest against
the separately provisioned host-manifest public key before using its operation,
process, network, or product fields. Signing a bundle cannot turn a fabricated
producer manifest into boundary evidence.

It does not establish that a probabilistic analyzer is always correct or that
one semantic verifier understands every domain. The deterministic safety
property is narrower: inference can select only an operation class already
approved for the observed caller, and ambiguity or out-of-policy expansion
fails closed.
