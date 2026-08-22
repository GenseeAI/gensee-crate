# Operation supervisor

The operation supervisor is the durable runtime identity behind capability
decisions. It gives policy and enforcement a shared object that is narrower
than an agent session and longer-lived than one intercepted syscall.

For every managed local run, Gensee creates a random `operation_id`, passes it
to the child as `GENSEE_OPERATION_ID`, and stores an owner-only record at:

~~~text
GENSEE_HOME/operations/OPERATION_ID/record.json
~~~

The record contains:

- the source run and action class;
- lifecycle state, start/end time, and exit result;
- the root process and its Linux `(pid, start_time_ticks)` identity;
- the observed descendant process lineage;
- the cgroup path, attachment state, and cleanup result;
- the current capability envelope, active mediation boundaries, and leases;
- the number of recorded boundary effects, cumulative allowed/blocked network
  packets and bytes, and lifecycle violations.

Linux process identity includes `/proc/PID/stat` field 22, so a reused PID is
not silently treated as the original process. The supervisor polls the full
process tree while the child runs. On timeout it kills and waits for the root,
refreshes lineage, records the terminal state, and releases a cgroup it owns.
An adopted cgroup remains owned by the enforcement component that created it.

## Shared updates

The managed runner and a boundary supervisor may update the same operation.
Every update therefore takes an owner-only advisory lock, reloads the newest
record, validates its schema and identity, changes one portion, and atomically
replaces the JSON file without following symlinks. A stale process cannot
overwrite a newer lifecycle, envelope, lease, or effect count from another
component.

The C0 network supervisor joins this record. Its exact IP/protocol/port
envelope is copied into the generic envelope after each fail-closed nftables
generation, expired network leases are pruned, and every allow, lease, broker,
or deny effect increments the operation's effect count. Detailed network
evidence remains in `network-operations/OPERATION_ID/effects.jsonl`.

## Security boundary

This supervisor establishes durable identity and coordination; it does not by
itself make an unprivileged CLI a trusted reference monitor. A privileged
daemon still needs to own cgroups, nftables, lease expiry after client crashes,
authenticated effect evidence, and termination of every surviving descendant.
Fresh cells and live Tclone forks must also join this same lifecycle instead of
creating parallel, unrelated records.
