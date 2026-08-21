# Capability broker

The capability broker is the host-owned authority boundary for short-lived
repository/API access, workload identities, mTLS identities, filesystem
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
  "resource_kinds": ["repository_token", "api_token"],
  "executable": "/opt/gensee/brokers/repository-client",
  "args": [],
  "environment_allowlist": ["BROKER_CLIENT_HANDLE"],
  "max_ttl_seconds": 300
}
```

The executable is expected to be a client for a long-running provider-side
broker. Gensee clears its environment, restores only explicitly allowlisted
variables, writes a bounded JSON request on standard input, and enforces a
30-second timeout and a 1 MiB output limit. The provider retains all credential
material and returns only:

```json
{
  "protocol_version": 1,
  "provider_handle": "opaque-provider-handle",
  "gateway_endpoint": "unix:///run/gensee/repository.sock",
  "public_metadata": {"repository": "one"},
  "effects": [],
  "effect_telemetry_complete": false
}
```

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

The adapter contract supports `repository_token`, `api_token`,
`workload_identity`, `mtls_certificate`, and `database_role`. Provider-specific
minting remains outside the cell and outside the Gensee process; an adapter can
use OAuth token exchange, a workload-identity service, a SPIFFE workload API,
an internal certificate authority, or a database credential broker without
changing the cell protocol.

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
its assigned address, binds an nftables forward allowlist to that address,
attaches the initial process tree to a fresh cgroup, and only then releases the
exact leased command. Hostnames are not accepted for this path, so a
broker must resolve and pin addresses before issuing the lease. Allowed-rule
counters become network effects; blocked packets or incomplete counter
collection prevent promotion. On non-Linux hosts this path fails closed.

Brokered repository, API, identity, mTLS, browser, cloud, and database
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

There is intentionally no silent signing-key rotation. Deleting or replacing
`signing.key` invalidates every outstanding external-action token and all
retained evidence signed by the old key. Revoke outstanding leases and archive
or verify retained evidence before an operator performs an explicit rotation.
