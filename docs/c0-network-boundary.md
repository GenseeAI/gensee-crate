# C0 network capability boundary

The C0 network supervisor is the first end-to-end capability path for a
long-lived operation. It is provider-neutral: decisions use resolved IP
addresses, protocols, ports, operation/process identity, expiry, and HTTP
semantics. It contains no package-manager or repository-product rules.

For each boundary event it returns exactly one disposition:

~~~text
within current envelope   -> allow and record
bounded and revocable     -> attach an operation-scoped network lease
read-only HTTP effect     -> trusted gateway performs the request
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

The HTTP gateway accepts one configured client IP. It supports absolute HTTP
GET and HEAD requests, connects to the already-resolved address, pins the
upstream socket to that address, replaces the Host header, strips credentials
and hop-by-hop headers, rejects request bodies and uploads, and caps bytes and
time. HTTPS and CONNECT are rejected because an opaque TLS tunnel cannot
enforce read-only HTTP semantics.

The gateway does not follow redirects. It returns a redirect to the client,
whose next proxy request is resolved and authorized as a new effect. Private,
loopback, link-local, multicast, metadata-range, and policy-restricted
destinations are denied before an upstream socket is opened. A DNS answer
containing any restricted address is denied as a whole.

## Configuration

~~~json
{
  "schema_version": 2,
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
    "prefer_http_gateway": true
  },
  "proxy": {
    "listen": "0.0.0.0:3128",
    "client_address": "10.88.0.12",
    "max_response_bytes": 134217728,
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
effects.jsonl, faults.jsonl, and counters.jsonl. The generic lifecycle/envelope
and cumulative network-usage record is retained separately under
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

## Current boundary

The HTTP gateway is automatic because proxy requests arrive before the external
effect. Direct black-box connect attempts still need a mandatory system
boundary adapter to produce the generic fault and arrange a retry. The CLI
validates that protocol and installs or revokes the lease, but cannot pause an
arbitrary in-flight syscall or force an opaque program to retry.

The supervisor currently runs as its invoking host principal. Moving authority,
signing, nftables state, and evidence into a differently privileged daemon
remains necessary before host-user compromise is in scope.
