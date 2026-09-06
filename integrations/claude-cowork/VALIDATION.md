# Local Cowork regression validation

A signed, entitled development build was tested on macOS 15.1 (24B2083),
Claude Desktop 1.46388.4, with Cowork's local Linux VM. Tests used an isolated
Crate store, observe mode, and synthetic files in one connected folder.
The original app and sensor were restored after testing.

## Live cases

- Native `Read` → `Write` → `Edit` → `Read`: exact file contents verified on
  the Mac; four audit boundaries labeled `host-native`. Independent native
  create/write/rename evidence was retained with conservative `unattributed`
  OS origin, because automatic audit-to-sensor causal joining is not implemented.
- VM `mcp__workspace__bash`: Linux execution and exact output file verified;
  the audit boundary was `vm-mediated`. The existing launchd-owned Apple VM
  produced 16 retained file events for the test output, including create and
  write, all labeled `vm-mediated`.
- After both cases, the live health snapshot showed 36,276 ingested records,
  zero remaining backlog, zero reported drops, zero rejected events, and zero
  denied authorizations. The isolated database contained zero alerts. This
  exceeded the 20,000-record replay capacity without misreporting consumed
  history as lost evidence.
- Maximum sensor authorization duration was 414 µs against its 10,000 µs
  budget. This is an internal sensor statistic, not an end-to-end overhead
  benchmark. Background activity in the shared Claude process tree was present.

The preceding failing run produced no independent VM file evidence and more
than 41,000 high-severity gap alerts. The fixes associate launchd-owned VMs using
verified responsible-process generations, distinguish consumer gaps from
replay eviction, and drain queued batches without the idle polling delay.
The CLI also excludes idle input wait from batch-duration telemetry; that
additional timing correction was validated in the final build separately
from the live sensor snapshot above.

## Automated checks

- `scripts/test-cowork-endpoint-scope.sh`: actual Objective-C extension and
  bridge code with synthetic ES records. Covers valid and rejected VM
  association, responsible-PID reuse, opt-out revocation, canonical roots,
  helper identities, snapshot growth, circular-buffer ordering, consumed-history
  eviction, real unread gaps, fetch retries, and real kernel loss.
- `cargo build -p gensee-crate-cli` followed by
  `python3 scripts/test-endpoint-ingest-gaps.py`: the real CLI processes a gap
  burst across changing PIDs/paths and an ingester restart. A later incident
  and another boot remain visible while the initial burst creates one alert.
- Rust CLI, macOS adapter, and store suites; Clippy with warnings denied;
  formatting; signed Xcode app/extension build.

These results establish the two tested local execution surfaces for this
Claude/macOS build. They do not establish unlimited burst capacity, guest
syscall visibility, cold-start coverage before responsible-process evidence
exists, cloud execution, EDR interoperability, or an absence of vulnerabilities.
Repeat the live cases when Claude or macOS changes.
