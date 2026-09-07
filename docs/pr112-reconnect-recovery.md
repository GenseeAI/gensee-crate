# Responsive sensor reconnect

The review of `0e7f9e2` found that manual reconnect only marked the transport for replacement. An unanswered XPC call prevented the polling loop from reaching that replacement, and a retry could not wake its backoff sleep.

The sensor now uses one polling coordinator for bounded XPC waits and interruptible delays:

- Both event-fetch and configuration requests have a five-second deadline. A timeout marks the transport for automatic replacement and uses the existing failure backoff.
- Reconnect cancels the current local XPC wait, resets failure backoff, and wakes the loop even when a replacement is already pending. An explicit retry is not counted as a transport outage.
- Each request has a unique completion identity. Timeout, cancellation, reply, and error can resolve it only once; late callbacks cannot resolve a successor or change its health.
- The existing single loop performs connection replacement and durable ingestion. A retry received during ingestion waits for that bounded persistence operation to complete before replacing the connection, preserving cursor ordering.
- Configuration rejection remains distinct from transport failure. Successful configuration pushes still preserve newer pending edits.

Validation: all 120 macOS harness tests passed, including five new tests for hung requests, late/duplicate replies, manual retry during a request, waking a 30-second backoff, and loop cancellation. The unsigned full macOS application build passed. These are deterministic callback tests; the installed signed sensor was not replaced for this change.
