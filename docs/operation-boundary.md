# Generic operation boundary

`gensee boundary` is an application-neutral admission and execution path. It
does not recognize a specific application, protocol, or attack signature.

The v1 slice covers one effect class: outbound network authority. A contract is
admitted before the command starts. On Linux, Gensee installs a cgroup-v2
scoped nftables policy before the wrapper joins the cgroup and executes the
command. On macOS, the v1 `deny_all` profile uses a process-tree Seatbelt
network denial. Completed events are evidence; the enforcement boundary exists
before execution.

The manifest distinguishes enforcement from observation. Linux records
aggregate nftables allow/deny counters. The macOS Seatbelt path currently
reports `enforced_without_attempt_telemetry`; an empty denied-effect list is
not represented as proof that no attempt occurred.

The command runs against a staged workspace. The structural product gate
supports `blob`, `blob_set`, `directory_tree`, `workspace_patch`,
`structured_result`, and `environment_snapshot`. It binds an exact relative
slot, bounded entry and byte counts, file modes, and streaming hashes. It can
reject symlinks and special objects. `structured_result` also requires JSON.

These checks do **not** prove semantic correctness or absence of malicious
content. The manifest therefore reports `semantically_verified: false` and the
runtime does not promote anything. A later verifier-receipt layer must bind a
product-class verifier to the exact product digest. Even then, executable
products must run under a consumer capability envelope.

## Commands

```bash
gensee boundary validate \
  --contract integrations/boundary/offline-structured-result.json

gensee boundary audit \
  --contract integrations/boundary/offline-structured-result.json \
  --json

sudo gensee boundary run \
  --catalog /etc/gensee/catalog.signed.json \
  --trusted-key /etc/gensee/organization-public.hex \
  --observation /run/gensee/observation.json \
  --inference /run/gensee/inference.signed.json \
  --workspace /path/to/workspace \
  --manifest /tmp/gensee-effect-manifest.json \
  -- sh -c 'mkdir -p out && printf "{\\"ok\\":true}\\n" > out/result.json'
```

Linux cgroup/nftables enforcement requires root. macOS supports only
`network.mode: deny_all` in v1; exact endpoint envelopes fail admission rather
than silently degrading.

## Contract ownership

Gensee defines the schema and fail-closed semantics. A platform team can
publish reusable templates. The runtime generates the operation ID and binds it
to an OS execution subject: PID plus process start identity on supported hosts,
and cgroup membership on Linux. It also generates the staged output path,
deadlines, command digest, and effect manifest. The producer cannot choose a
trusted destination.

The enforcing `run` command does not accept a caller-selected contract.
Before execution, Gensee re-derives the effective OS user, canonical executable
hash, and command digest, then verifies that they match a preflight observation.
An organization-approved analyzer may use this observation plus bounded
references to earlier effect manifests to produce ranked, probabilistic
operation-class candidates. Its signed result is accepted only if its analyzer
and model identities, class scope, confidence threshold, observation digest,
and expiry match the signed catalog. The winning class is then mapped through
one exact caller selector to one approved contract.

This makes intent discovery fallible but prevents it from becoming an
authorization oracle: the analyzer cannot name a contract or add authority.
Ties, low confidence, novel classes, runtime mismatches, and expired evidence
deny execution unless the catalog explicitly names a safe default for that
caller.

`allow_exact` accepts resolved IP addresses and explicit protocol/port tuples.
Hostnames do not appear in the OS-enforced network envelope: DNS and credentialed HTTP
belong in a trusted protocol mediator.

## Current boundary

- V1 enforces outbound network authority and stages filesystem products.
- It does not yet accept authenticated semantic-verifier receipts.
- It does not promote products.
- It does not provide transparent mid-operation migration or application
  rollback.
- The runner drains the producer process group before scanning products. A
  stronger all-descendant lifecycle claim still requires the Linux cgroup/cell
  path; V1 never promotes the staged result automatically.
- Staging uses the managed-run exclusions for `.git`, `target`, `node_modules`,
  and Gensee control directories.

An opaque persistent service denied halfway through a private transaction may
still return an application error. Gensee does not claim to know how to roll it
back. Such a service must use a mediator from startup, or the uncertain
operation must begin in a disposable cell.
