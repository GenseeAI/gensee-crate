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
  "public_metadata": {"repository": "one"}
}
```

Unknown response fields are rejected. Public metadata and opaque handles are
also rejected if they contain token-, password-, private-key-, certificate-, or
credential-shaped material. Adapter stderr is never copied into an error or
manifest; only its SHA-256 digest is retained in an error message. Gateway
endpoints must be Unix sockets, HTTPS, or loopback HTTP without URL userinfo.
The same adapter receives a `revoke` request with its opaque provider handle on
lease expiry, explicit revocation, or cell teardown.

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

Built-in filesystem and network leases validate bounded path/access and
destination/protocol/port constraints. They currently create authorization
records and opaque handles; the subsequent filesystem mount and network
namespace enforcement are described in the mandatory-mediation work and must
be active before the policy engine will authorize those capabilities.

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
