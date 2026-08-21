# Capability faults

A capability fault is a provider-neutral observation from an enforced runtime
boundary. It says which operation and exact subject reached which resource; it
does not let the agent choose an executor, mediator, approval, promotion mode,
or grant.

Fault subjects are either a Linux `(pid, start_time_ticks)` identity or an
exact isolated network-peer address. Effects are typed across network
connections, file operations, syscalls/Linux capabilities, secret identities,
cloud/IAM, external applications, databases, and output promotion. The trusted
receiver validates the subject against the durable operation record and derives
a schema-v2 capability request from the observation.

The first connected backend is direct network egress. Submit a boundary fault
to the operation's supervisor socket:

~~~console
gensee run fault --socket /var/lib/gensee/network-operations/OP/supervisor.sock \
  --fault fault.json
~~~

The response has one generic action:

- `continue_already_authorized`: the exact effect was already in the active
  envelope;
- `retry_after_lease`: the trusted backend installed an exact, expiring
  IP/protocol/port generation and only then permitted a retry;
- `delegate`: another trusted executor must perform the effect; or
- `deny`: the subject, scope, policy, or required backend did not validate.

Unsupported effect types fail closed with
`capability_fault_backend_unavailable`; they are never treated as network
authority or implicitly allowed. An oversized, partial, slow, unknown-field,
or symlinked control message is rejected. Every parsed fault and resolution,
including invalid-subject and backend-error denials, is retained in the
owner-only `network-operations/OP/faults.jsonl` evidence stream.

## Counter evidence

The network backend samples nftables allow and default-deny counters every
second, computes monotonic deltas, and harvests the old policy generation before
revocation. Totals are written into both the network record and shared
operation record. Per-destination/protocol/port allow deltas and deny-reason
deltas are appended to the owner-only
`network-operations/OP/counters.jsonl`. A new policy generation establishes a
counter baseline before the old generation is removed, avoiding double counts
during their fail-closed overlap.

## Current boundary

This PR defines and connects the generic fault/response protocol, but a manual
CLI invocation is still only a test adapter. Automatic black-box capture still
requires a mandatory Linux boundary adapter, such as seccomp user notification
or an eBPF/cgroup connect hook, that pauses or rejects the original operation,
submits the fault, and retries only on an authenticated response. Filesystem,
kernel, secret, API, database, promotion, fresh-cell, and live-fork backends
must join the same router in later slices.
