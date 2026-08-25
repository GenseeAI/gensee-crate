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

Protocol-specific adapters remain small trusted components. For example, an
HTTP mediator checks method, origin, path, and byte limits, while a database
mediator checks database, action, and transaction mode. Those components do
not define lease durability, operation attribution, revocation ordering, or
promotion eligibility; the Gensee host does.

Defining a schema does not make an unenforced capability usable. An operation
can receive one of these grants only when a registered adapter supports the
exact resource kind and the normal broker lifecycle successfully reaches
`active`. Otherwise admission fails closed.
