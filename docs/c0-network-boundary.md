# C0 network capability boundary

The C0 network supervisor is the first end-to-end capability path for a
long-lived operation. It is provider-neutral: decisions use resolved IP
addresses, protocols, ports, operation/process identity, expiry, and HTTP
semantics. It contains no package-manager or repository-product rules.

For each boundary event it returns exactly one disposition:

~~~text
within current envelope   -> allow and record
bounded and revocable     -> attach an operation-scoped network lease
HTTP effect               -> trusted, policy-scoped mediator performs it
anything else             -> deny and record
~~~

## Enforcement model

The supervisor owns one network record and joins the shared
[operation supervisor](operation-supervisor.md) for one enforcement subject:

- root_pid puts a local process tree in an operation cgroup and applies
  nftables output policy to that cgroup; or
- source_address applies identical forward and host-input policy to one
  isolated container address.

The baseline envelope and active leases become an exact IP/protocol/port
allowlist. Everything else is rejected. Gensee installs each new policy
generation before deleting the old one, making both grant and revocation
transitions fail closed. A supervisor timer removes expired leases.

The HTTP mediator accepts one configured client IP. It supports absolute HTTP
and HTTPS requests without exposing a CONNECT tunnel. For every hop it resolves
the authority, authorizes every returned address, pins the upstream socket to
the authorized address while preserving TLS hostname verification, replaces
Host, and strips client credentials and hop-by-hop headers. Request and response
bodies, redirect depth, connect time, and I/O time are bounded.

GET and HEAD are enabled by default. Other methods require explicit trusted
policy opt-in, an active mediator lease, and a one-use signed external-action
commit token bound to the exact gateway, URL, method, and request digest. A
credential can be injected from an owner-only, no-follow host file, but only
for exact configured URL prefixes and only while a lease is active. The broad
credential is never copied into the operation config or retained evidence.

The mediator follows only GET/HEAD redirects and re-authorizes each hop before
opening the next socket. Private, loopback, link-local, multicast,
metadata-range, and policy-restricted redirects are therefore denied inside the
same operation. A DNS answer containing any restricted address is denied as a
whole. Client-visible response headers are allowlisted; Set-Cookie and
authentication headers are not returned.

## Configuration

~~~json
{
  "schema_version": 3,
  "operation_id": "op_agent_fetch",
  "source_run_id": "run_agent",
  "source_address": "10.88.0.12",
  "envelope": {
    "grants": [
      {
        "destination": "10.88.0.1",
        "protocol": "tcp",
        "ports": [3128]
      },
      {
        "destination": "10.30.0.5",
        "protocol": "tcp",
        "ports": [4000]
      }
    ]
  },
  "policy": {
    "schema_version": 1,
    "restricted_destinations": [],
    "in_place_lease_destinations": [],
    "in_place_lease_protocols": ["tcp"],
    "max_in_place_lease_ttl_seconds": 60,
    "http_gateway_available": true,
    "prefer_http_gateway": true,
    "http_gateway_methods": ["GET", "HEAD"]
  },
  "proxy": {
    "listen": "0.0.0.0:3128",
    "client_address": "10.88.0.12",
    "max_request_bytes": 16777216,
    "max_response_bytes": 134217728,
    "max_redirects": 3,
    "connect_timeout_seconds": 10,
    "io_timeout_seconds": 30
  }
}
~~~

`restricted_destinations` adds deployment-specific deny ranges; it cannot
remove the built-in private, loopback, link-local, carrier NAT, metadata,
benchmark, multicast, reserved, and IPv4-mapped-private restrictions. An exact
baseline grant can deliberately reach a local gateway or model service even
when its address falls in a restricted CIDR. Restricted destinations remain
ineligible for newly issued authority.

Start the supervisor as a privileged host process:

~~~console
sudo env GENSEE_HOME=/var/lib/gensee \
  gensee run network serve --config operation.json
~~~

The control socket and evidence are retained under
GENSEE_HOME/network-operations/OPERATION_ID as supervisor.sock, record.json,
effects.jsonl, http-mediator.jsonl, faults.jsonl, and counters.jsonl. Effect
evidence retains request/response digests, status, byte counts, credential
handle IDs, and query-redacted redirect targets, never injected credential
values or raw transport errors. The generic lifecycle/envelope and cumulative
network-usage record is retained separately under
GENSEE_HOME/operations/OPERATION_ID/record.json.

Submit a structured direct-network capability fault:

~~~console
gensee run network event --socket /path/supervisor.sock --event event.json
~~~

The provider-neutral fault adapter is preferred for new integrations:

~~~console
gensee run fault --socket /path/supervisor.sock --fault fault.json
~~~

It binds a PID/start-time or isolated peer identity to the operation, and
returns retry permission only after the exact lease is active. See
[Capability faults](capability-faults.md).

Inspect the active envelope:

~~~console
gensee run network inspect --socket /path/supervisor.sock
~~~

Revoke a mediator lease immediately for new requests and redirect hops:

~~~console
gensee run network revoke-http --socket /path/supervisor.sock --lease lease_http_1
~~~

## Current boundary

The HTTP gateway is automatic because proxy requests arrive before the external
effect. Direct black-box connect attempts still need a mandatory system
boundary adapter to produce the generic fault and arrange a retry. The CLI
validates that protocol and installs or revokes the lease, but cannot pause an
arbitrary in-flight syscall or force an opaque program to retry.

Explicit mediator revocation prevents new requests and redirect hops. A request
already blocked in upstream I/O is bounded by the lesser of its configured I/O
timeout and remaining lease lifetime, but is not yet actively interrupted by a
revocation event. Active socket cancellation belongs in the privileged daemon
transport.

The supervisor currently runs as its invoking host principal. Moving authority,
signing, nftables state, and evidence into a differently privileged daemon
remains necessary before host-user compromise is in scope.
