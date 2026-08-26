# Generic capability providers

Gensee's provider interface separates lifecycle security from protocol
semantics. The host broker owns the common state machine; a narrow provider
adapter understands one external protocol.

The common lifecycle is:

1. validate a typed, exact, non-wildcard scope;
2. durably record deny-only issuance intent;
3. prepare and activate authority with a stable idempotency key;
4. publish only an opaque handle or mediated endpoint;
5. bind the lease to operation identity, generation, and deadline;
6. record request-digested effects and telemetry coverage;
7. write `revoking` before teardown, reconcile after crashes, and deny new
   grants while provider state is indeterminate.

Schema v1 defines typed scopes for:

- credential use;
- HTTP/API calls;
- browser sessions;
- database transactions;
- message delivery;
- CI job invocation;
- secret reads;
- filesystem mutation;
- cloud control actions.

Each scope includes only handles and selectors, never secret bytes. It rejects
wildcards, empty action sets, duplicate targets, malformed digests, non-normal
filesystem roots, non-origin URLs, URL credentials, and unbounded transfer
budgets. The declared scope variant must match the broker resource kind.

An adapter registration states which resource kinds it enforces. The broker
passes the typed scope in its bounded JSON request and authenticates that exact
request throughout mint, status, effect collection, and revoke. Adapters must
return opaque provider handles, local mediator endpoints, and typed effect
records; unknown or secret-shaped response fields fail closed.

For a fresh capability cell, the exact typed scope must also appear in the
cell's preapproved `scope.broker_capabilities` list. Gensee checks that binding
before invoking the provider, and checks it again when the cell starts. A
caller cannot attach a broader provider lease merely by declaring a compatible
coarse capability or audience.

Protocol-specific adapters remain small trusted components. For example, an
HTTP mediator checks method, origin, path, and byte limits, while a database
mediator checks database, action, and transaction mode. Those components do
not define lease durability, operation attribution, revocation ordering, or
promotion eligibility; the Gensee host does.

Defining a schema does not make an unenforced capability usable. An operation
can receive one of these grants only when a registered adapter supports the
exact resource kind and the normal broker lifecycle successfully reaches
`active`. Otherwise admission fails closed.

## Executable provider runtime

`gensee boundary provider dispatch` is the common action host. It loads the
active lease from host-controlled broker state, requires an invocation whose
operation, lease, resource kind, and exact typed operation are a subset of that
lease, then launches the configured narrow adapter without a shell or ambient
environment. The adapter executable, working directory, arguments, resource
kind, digest, and deadline are root-controlled configuration. Output is
bounded and must repeat the exact invocation, target, action, effect kind, and
request digest; Gensee binds the accepted result, lease, and executable digest
into a host-signed dispatch receipt.

Provider dispatch currently requires Linux cgroup v2. Gensee creates a private
cgroup before the adapter starts, attaches the adapter before `exec`, and
recursively kills and verifies that complete execution subject empty on every
terminal path. A successful direct-child exit is not accepted until detached
or session-changing descendants have been killed and the owned cgroup has been
removed. Other platforms fail closed until they provide an equivalent
non-escapable execution-subject boundary.

Before launch, Gensee validates every executable and working-directory
ancestor as root-controlled, opens and copies the admitted executable into the
private invocation directory, verifies the copied bytes against the configured
digest, fsyncs it, and executes that snapshot. Replacing the configured path
between admission and launch cannot substitute different adapter code.

The same host supports all schema-v1 capability classes. Tests exercise a
valid invocation for every class and out-of-scope denial. This is the reusable
provider boundary; protocol implementations remain intentionally narrow. A
database adapter interprets the database operation, a browser adapter
interprets the browser action, and so on. They cannot change lifecycle,
identity, expiry, or the action envelope supplied by Gensee.

```console
gensee boundary provider dispatch \
  --config /etc/gensee/providers/database.json \
  --lease lease_123 \
  --request invocation.json \
  --output dispatch-receipt.json
```
