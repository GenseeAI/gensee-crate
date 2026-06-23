# `gensee watch` — sidecar filesystem and system-event audit

`watch` runs as an independent sidecar and does **not** launch the agent. It
records filesystem effects in `$GENSEE_HOME/workspace-effects.jsonl` (default
`~/.gensee/workspace-effects.jsonl`) and, on macOS, starts `eslogger` by
default to record normalized system events in `$GENSEE_HOME/system-events.jsonl`.

```bash
cargo run -p gensee-crate-cli -- watch \
  --workspace . \
  --watch-root ~/Downloads \
  --duration-seconds 10
```

## Workspace vs. watch roots

- `--workspace` is the primary project/cwd used for attribution.
- `--watch-root <path>` (repeatable) adds directories whose
  create/modify/delete effects are observed.

By default, the sidecar watches the workspace **plus** existing sensitive
directories such as `~/.ssh`, `~/.aws`, and `~/.config/gcloud`. Use
`--no-sensitive-roots` for a narrow watch that only observes the workspace and
explicit `--watch-root` directories.

Effects under the session workspace are reported with **medium** confidence;
effects in extra watch roots are reported with **lower** confidence because
another local process may have caused them.

## Backends

On macOS, `watch` defaults to the FSEvents backend (`--backend auto`), which
receives file create/modify/delete/rename notifications without launching the
agent or requiring EndpointSecurity. Use `--backend snapshot` to force the
portable polling fallback.

Both backends observe filesystem **effects**, not pure reads. For read intent,
use agent hooks such as [Claude Code hooks](claude-code-hooks.md) or Codex
hooks; for enforced denial, use [`gensee run --sandbox mac`](run-and-sandbox.md).

## System events

On macOS, `gensee watch` starts `/usr/bin/eslogger` by default and ingests
normalized exec/open/create/write/rename/unlink events into the same
`GENSEE_HOME` store. The default comes from the policy document:

```bash
gensee policy set watch.system_events eslogger
```

Turn it off persistently with policy, or for one watch command:

```bash
gensee policy set watch.system_events none
gensee watch --workspace . --system-events none
```

`eslogger` may require elevated permissions. If the selected system-event
backend cannot start, the watch command reports that error instead of silently
dropping system events. The lower-level `gensee ingest eslogger` command remains
available for manual pipelines, but `gensee watch` is the default path for
sidecar capture.

EndpointSecurity/eslogger does not provide complete IP network
egress/ingress visibility. System-level network capture on macOS needs a
Network Extension, packet filter, or similar privileged network sensor, plus
process attribution to connect packets back to agent sessions. Today, Gensee
detects network egress for policy decisions from agent hook/tool events.

Keep explicit watch roots reasonably small when using `--backend snapshot`:
broad roots such as `~` or `~/Downloads` are recursively re-scanned each
interval by that fallback backend.

When using the snapshot backend, rapid create/modify/delete sequences can be
coalesced between polling intervals. To exercise all three event types under
snapshot mode, add a small delay between operations:

```bash
echo hello > /tmp/gensee-watch-test/demo.txt
sleep 1
echo again >> /tmp/gensee-watch-test/demo.txt
sleep 1
rm /tmp/gensee-watch-test/demo.txt
```

## Inspecting results

```bash
gensee timeline
```

See the [lineage graph](lineage-graph.md) guide for the underlying schema and
queries.
