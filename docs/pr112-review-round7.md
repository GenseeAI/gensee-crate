# PR #112 review 5127211552

This pass addresses the three inline findings on commit 844db2e.

## Passive extension discovery

App activation and the 15-second discovery timer now use a properties-only probe. It keeps the current title, busy state, and manual System Settings guidance while the request is in flight. An unchanged result does not publish another state transition; a failed probe leaves the existing presentation intact. Actual approval can still be discovered from either `notInstalled` or `awaitingApproval`.

Failure, restart-required, and busy states are not probed. Explicit installation, removal, and status refresh actions invalidate pending probes, so a delayed response cannot overwrite newer guidance. Probing does not initiate an extension upgrade; the existing explicit status/activation path retains that behavior.

## Sensor-owned connection recovery

The application delegate starts the sensor once. Transport interruption, invalidation, and XPC request failures mark the current connection for replacement by the polling loop. Recovery no longer depends on a subsequent app activation or the displayed `health.connected` value. The loop also survives a failed initial ingester launch.

Each replacement has a generation token. Callbacks from an old connection cannot invalidate a newer connection, and old replies cannot publish healthy status after interruption. The last complete configuration is resent after replacement. A configuration changed while its RPC is suspended remains pending and is applied before fetching another batch. Ingestion errors and rejected configurations do not themselves force transport replacement.

## Persistent event-loss history

Event loss has an independent stored banner beneath the current outage banner. After stable recovery, an undismissed loss becomes visible again, including across a sensor boot change. Dismissing an outage reveals the loss; dismissing the loss clears that history cue. A still-active, already-dismissed outage does not immediately reappear. Subsequent event-loss alarms can create a new cue, and undismissed loss counts accumulate.

## Validation

- All 112 macOS harness tests passed with no failures or skips.
- The unsigned full macOS app build passed.
- Regression coverage includes unchanged/failed probes, preserved approval fallback, terminal/busy states, late probe responses after activation failure, connection-generation handling, loss surviving outage recovery, and independent dismissal of outage and loss banners.

The tests exercise injected status observations and connection state transitions. They do not replace the installed signed system extension, simulate a real XPC service restart, or submit a real activation request to macOS. Interactive signed activation remains a separate validation step.
