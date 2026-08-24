# Capability broker

The capability broker is the host-owned authority boundary for short-lived
external service access, workload identities, mTLS identities, filesystem
handles, network leases, database roles, and external-action commit tokens.
Cells receive only opaque lease ids, opaque provider handles, and mediated
gateway endpoints. They do not receive the credential used by the host broker
to mint narrower authority, nor the minted token, private key, or database
password.

## Host-only commands

```console
gensee run broker adapter register --config adapter.json
gensee run broker adapter inspect repo-broker --json
gensee run broker lease issue --request broker-request.json --json
gensee run broker lease inspect broker_lease_... --json
gensee run broker lease revoke broker_lease_...
gensee run broker lease revoke-expired
```

Broker administration is rejected through the tclone agent bridge. Lease
metadata and signing material are stored under owner-only directories in
`$GENSEE_HOME/capability-broker`.

## External adapter protocol

A trusted host administrator registers an absolute, regular, non-symlink,
non-group/world-writable adapter executable:

```json
{
  "schema_version": 1,
  "adapter_id": "repo-broker",
  "resource_kinds": ["external_service_authority", "api_token"],
  "executable": "/opt/gensee/brokers/external-service-client",
  "args": [],
  "environment_allowlist": [],
  "lifecycle_v2": true,
  "max_ttl_seconds": 300,
  "legacy_revoke_acknowledgement": false
}
```

The executable is expected to be a client for a long-running provider-side
broker. Gensee clears its environment, writes a bounded JSON request on
standard input, and enforces a
30-second timeout and a 1 MiB output limit. The provider retains all credential
material. Every provider request includes a lease id and a stable idempotency
key:

```json
{
  "protocol_version": 1,
  "action": "mint",
  "lease_id": "broker_lease_...",
  "idempotency_key": "idem_...",
  "lease": {
    "protocol_version": 1,
    "request_id": "request_...",
    "operation_id": "op_...",
    "source_run_id": "source_...",
    "resource_kind": "external_service_authority",
    "adapter_id": "repo-broker",
    "audience": "repo.example.test",
    "scopes": ["service:one:read"],
    "ttl_seconds": 300,
    "constraints": {"service": "one"}
  },
  "provider_handle": null
}
```

Adapters must make `mint` and `revoke` idempotent for that key and implement a
read-only `status` action. A successful mint or active status returns only:

```json
{
  "protocol_version": 1,
  "provider_status": "active",
  "provider_handle": "opaque-provider-handle",
  "gateway_endpoint": "unix:///run/gensee/external-service.sock",
  "public_metadata": {"service": "one"},
  "effects": [],
  "effect_telemetry_complete": false
}
```

`status` reports `absent`, `active`, `revoked`, or `indeterminate`. For absent
or revoked authority, `provider_handle` and `gateway_endpoint` may be empty.
Legacy successful `mint` and `revoke` responses without `provider_status`
remain accepted. Legacy registration defaults `lifecycle_v2` to false and its
request shape omits `lease_id` and `idempotency_key`, including during revoke.
The wire mode is selected from the lease's retained lifecycle format, not the
current registration: upgrading an adapter registration to lifecycle-v2 does
not make pre-upgrade leases unrevokeable.
New external leases require an adapter to explicitly negotiate
`lifecycle_v2: true`, implement `status`, and accept the lifecycle fields.
Because inherited environment values could select a different provider tenant
after restart, lifecycle-v2 rejects a non-empty `environment_allowlist`.
Environment inheritance remains available only to explicitly legacy adapters.
All adapter processes run with `/` as their fixed working directory.
Lifecycle-v2 arguments are restricted to static ASCII alphanumeric, `_`, and
`-` tokens with an optional leading `--`; empty values, whitespace, `.`, `=`,
`/`, and `\` are rejected. Dynamic provider and request data belongs on stdin,
so recovery cannot depend on caller-relative files such as `provider.json` or
`--config=provider.json`. Legacy registrations retain their broader argv
compatibility.

A `revoke` response is successful only when it explicitly reports `absent` or
`revoked`. `active` and `indeterminate` leave the lifecycle indeterminate and
deny further grants. An adapter that predates provider status may omit it only
when its trusted registration explicitly sets
`legacy_revoke_acknowledgement: true`; the default is fail-closed.

Unknown response fields are rejected. Public metadata and opaque handles are
also rejected if they contain token-, password-, private-key-, certificate-, or
credential-shaped material. Adapter stderr is never copied into an error or
manifest; only its SHA-256 digest is retained in an error message. Gateway
endpoints must be Unix sockets, HTTPS, or loopback HTTP without URL userinfo.
The same adapter receives a `revoke` request with its opaque provider handle on
lease expiry, explicit revocation, or cell teardown. Its final response reports
typed, request-digested effects and explicitly attests whether that effect log
is complete. Gensee copies those effects into the cell manifest; missing or
incomplete gateway telemetry is a manifest violation and prevents promotion.

The host also authenticates the immutable manifest, request, exact command,
input/output tree digests, and replay plan with a domain-separated HMAC. The
underlying signing key remains in the owner-only broker state directory and is
never mounted into a capability cell. Promotion receipts use a separate
signature domain and an append-only verified ledger, so editing retained JSON
cannot erase prior promotion history or manufacture clean evidence.

The adapter contract supports `external_service_authority`, `api_token`,
`workload_identity`, `mtls_certificate`, and `database_role`. Provider-specific
minting remains outside the cell and outside the Gensee process; an adapter can
use OAuth token exchange, a workload-identity service, a SPIFFE workload API,
an internal certificate authority, or a database credential broker without
changing the cell protocol.

## Crash-safe provider lifecycle

Before calling an external adapter, Gensee copies its regular executable into
an owner-only per-lease snapshot and records the executable SHA-256 plus the
canonical adapter configuration. Recovery validates and invokes that exact
snapshot, so replacing a registered adapter cannot orphan authority from the
old provider or remint it through a new one. For each invocation, Gensee opens
and hashes the snapshot, creates an unpredictable private hard link, verifies
that link has the same device and inode as the open file, and executes the
bound link. A concurrent path replacement therefore cannot redirect execution.

Before calling the snapshot, Gensee persists a deny-only `preparing`
record containing the bounded request, deadline, and stable idempotency key. It
then records `activating` before `mint`, and does not create the usable public
lease until the provider result is durably recorded as `publishing`, any cell
cleanup attachment succeeds, and a final `active` transition is durable. A
recovered cell-bound grant that never reached that confirmation is revoked;
its public record remains non-active. Revocation
similarly records `revoking` before the adapter can tear authority down.
The cell cleanup attachment file and its parent directory are fsynced before
the broker is allowed to persist the authenticated `active` transition.

Lifecycle states are `preparing`, `activating`, `publishing`, `active`,
`revoking`, `revoked`, `expired`, `failed`, and `indeterminate`. Every transition is an
ordered, domain-separated host-HMAC record chained to the previous transition;
the signed claims bind the lease, idempotency key, provider operation, and
deadline, the pinned adapter snapshot, the provider handle and gateway, public
metadata, effects, telemetry completeness, and publication/attachment state.
A modified transition, response field, operation, or deadline fails
validation. Lifecycle writes fsync the file before rename and fsync the parent
directory before any provider effect. Newly created broker directories are
fsynced and then fsync their parent, from the state root through each leaf; a
retry repairs a directory creation interrupted before its parent sync.

After a host-client restart, the next trusted broker operation uses `status`
and the idempotency key to reconcile unfinished mint or revoke calls. An absent
mint can be retried, active authority can be materialized without minting a
second credential, and a confirmed revoked handle repairs stale local lease
state. Adapter failure or an explicit provider `indeterminate` result leaves
the lifecycle deny-only. Gensee denies new external grants while any provider
authority remains unresolved. Wall-clock expiry is bounded to the configured
maximum TTL and each record also carries a signed boot marker plus monotonic
deadline. Expiry is the earlier of the signed wall deadline and monotonic
deadline, so host suspend cannot extend the lease. The already-clamped TTL is
the value persisted, signed, included in the idempotency key, and sent to the
adapter. On the same boot, wall-clock regression cannot extend authority. A
reboot or monotonic-clock reset forces the provider into `revoking`; a failed
teardown is `indeterminate` and continues to block grants.

Every request carries a caller-generated stable `request_id`. Issuance durably
indexes the authenticated operation, source, optional cell, and `request_id` to
one lease id before minting, and stores a canonical request digest in that
signed index. Repeating `broker lease issue` resumes or returns that lease; a
reuse with changed request content is rejected, even when both TTLs would clamp
to equivalent provider authority. It cannot create a fresh UUID and a second
provider authority after a client crash. A terminal indexed issuance is
reported as terminal rather than silently replaced.

This lifecycle proves and repairs broker/provider state. It does not claim to
cancel an already-open upstream network socket; transport teardown belongs to
the network mediator and its privileged end-to-end enforcement tests.

## Lease binding

A capability-cell lease reserves its `cell_id` and `operation_id` before the
cell starts. A broker request that names a cell must match that unconsumed cell
lease, source run, operation, expiry, and declared capability. Gensee shortens
the broker TTL so it cannot outlive the cell lease, attaches the broker lease id
atomically, and exposes only the comma-separated opaque ids to the cell. If the
cell exits, times out, or fails during preparation, a cleanup guard revokes all
attached broker leases. Revocation failure becomes an effect-manifest violation
and blocks output promotion.

Cell activation also persists an owner-only cleanup journal before authority is
used. If the host client crashes, Podman's lease timeout still terminates the
container and the next trusted cell/broker operation reconciles the expired
journal, removes exact generated network state, and retries adapter revocation.
New authority issuance fails closed while an expired journal cannot be
reconciled; inspection commands remain available for diagnosis.

Built-in filesystem leases validate bounded path/access constraints and are
realized by exact read-only or read-write cell mounts. Built-in direct network
leases require IP/CIDR-pinned destinations plus exact TCP/UDP ports. On Linux,
Gensee starts a trusted gate in a private container network namespace, inspects
its assigned address, binds identical nftables forward and host-input
allowlists to that address, attaches the initial process tree to a fresh
cgroup, and only then releases the exact leased command. Applying the lease to
both routing paths prevents an allowed endpoint from redirecting the cell to an
unleased service on the Gensee host. Hostnames are not accepted for this path, so a
broker must resolve and pin addresses before issuing the lease. Allowed-rule
counters become network effects; blocked packets or incomplete counter
collection prevent promotion. On non-Linux hosts this path fails closed.

Brokered external service, identity, mTLS, browser, cloud, and database
capabilities instead mount only their exact Unix-domain gateway socket into a
cell whose IP network is disabled. The broad provider credential remains
behind that gateway.

## External-action commit tokens

`gensee.external-action` creates a host-stored HMAC-SHA-256 token bound to one
operation, source, lease, gateway, target, action, request SHA-256 digest,
expiry, and nonce. Consumption is host-only, exact-match, expiring, locked, and
one-use:

```console
gensee run broker commit consume commit_... \
  --gateway deploy-gateway \
  --target deployment/one \
  --action promote \
  --request-digest sha256:...
```

Revocation and consumption use a consistent lease-then-token lock order. A
consumed token is authoritative during reconciliation, preventing a crash
between token and lease record updates from making the external action
replayable.

The local HMAC key protects against accidental evidence drift, other local
users, and a compromised capability cell because the key never enters the
cell. It does not protect against code already running as the Gensee host user:
that principal can read or replace both the owner-only signing key and retained
evidence. Deployments needing host-user compromise resistance must place the
key in a separate service, hardware-backed keystore, or differently privileged
signer. In-memory key copies are zeroized when dropped.

The local HMAC transition chain authenticates its retained contents but, by
itself, cannot detect rollback or truncation to an older fully valid prefix by
the trusted host user. Deployments requiring rollback detection must anchor the
latest transition head in an external append-only store, TPM-backed counter, or
differently privileged service.

There is intentionally no silent signing-key rotation. `signing.key` must be an
owner-only regular file with mode `0600` containing exactly 64 lowercase
hexadecimal bytes plus one newline. Initial creation fsyncs both the file and
its parent directory before a signature can be returned. If the key is missing
while lifecycle, issue-index, commit-token, forensic, or promotion evidence is
retained, Gensee fails closed and does not generate a replacement. Revoke
outstanding leases and archive or verify retained evidence before an operator
performs an explicit rotation.
Reading an existing signing key or signed issuance index also fsyncs its parent
directory before returning, repairing a prior stop at the rename-to-parent-sync
boundary.
