# Omnigent Integration

Thin support for running
[Omnigent](https://github.com/omnigent-ai/omnigent) sessions under Gensee Crate.

This integration is intentionally shallow: it uses the existing `gensee watch`
sidecar and `gensee run` managed launcher around Omnigent. It does not yet add a
first-class Omnigent policy bridge or parse Omnigent's internal policy event
schema. Use it to get endpoint/runtime visibility, timeline records, staged
workspace review, and Gensee's host-level safety policy while we validate the
deeper integration path.

## What Works Today

- `gensee watch` can observe filesystem effects and macOS system events while
  Omnigent runs normally.
- `gensee run` can launch `omnigent` as a managed child, assign a Gensee run id,
  and record the root process.
- `gensee run --workspace-mode staged` can run Omnigent against a copied working
  tree so changes are reviewable before they touch the original workspace.
- The default policy treats `.omnigent` local state as control-plane material,
  so Gensee blocks agent writes to Omnigent bridge/config state when those
  mutations pass through a Gensee-enforced tool path.

## Sidecar Watch

Use this when you want Omnigent to keep its normal launch flow and native
harness setup:

```bash
export GENSEE_HOME="$HOME/.gensee-omnigent"
cargo build -p gensee-crate-cli

./target/debug/gensee watch \
  --workspace "$PWD" \
  --watch-root "$HOME/.omnigent" \
  --system-events none
```

In another terminal, start Omnigent as usual:

```bash
omnigent run path/to/agent.yaml
```

Then inspect the captured timeline:

```bash
./target/debug/gensee timeline --latest
```

Keep `GENSEE_HOME` outside the watched workspace. If it points inside
`--workspace`, the watcher records Gensee's own `sessions.jsonl` and
`workspace-effects.jsonl` writes. On macOS, `gensee watch` uses `eslogger`
system events by default when available. That requires Full Disk Access for the
terminal app and `sudo`; use `--system-events none` for a low-noise first run
or see [watch.md](../../docs/watch.md).

## Managed Launch

Use this when you want Gensee to own the Omnigent root process:

```bash
export GENSEE_HOME="$HOME/.gensee-omnigent"

./target/debug/gensee run \
  --workspace "$PWD" \
  -- omnigent run path/to/agent.yaml
```

For a safer first demo, run from a staged copy of the workspace:

```bash
./target/debug/gensee run \
  --workspace "$PWD" \
  --workspace-mode staged \
  -- omnigent
```

The bare `omnigent` CLI starts the interactive Omnigent flow under Gensee. Use
`omnigent run path/to/agent.yaml` when you want a specific agent spec instead.

On macOS, add Gensee's first-cut sandbox profile:

```bash
./target/debug/gensee run \
  --workspace "$PWD" \
  --sandbox mac \
  --profile cautious \
  --workspace-mode staged \
  -- omnigent run path/to/agent.yaml
```

Omnigent already applies its own native-harness sandboxing and policy hooks for
supported harnesses. Gensee's managed launch is an outer process/run boundary:
it records the run, can stage the workspace, can apply the current macOS
`sandbox-exec` profile, and can feed events into the Gensee timeline.

## Suggested Demo

1. Start `gensee watch` with `GENSEE_HOME` outside the repo, `--workspace
   "$PWD"`, `--watch-root "$HOME/.omnigent"`, and `--system-events none`.
2. Run a small Omnigent coding session that edits a file in the workspace.
3. Open `gensee timeline --latest` and confirm the run/session plus workspace
   effects appear.
4. Try to mutate an Omnigent control-plane path from a Gensee-enforced tool
   path, for example `.omnigent/...`, and confirm the policy reports
   `policy_control_plane_write`.

## Current Limits

- Gensee does not yet consume Omnigent's `PHASE_REQUEST`,
  `PHASE_TOOL_CALL`, or `PHASE_TOOL_RESULT` policy events directly.
- Omnigent's native Codex and Claude flows create private per-session homes and
  write their own command hooks. Running `gensee setup codex` globally is not
  the right integration point for those sessions.
- `gensee watch` filesystem events are observational. Active pre-tool
  enforcement still requires a Gensee hook or future Omnigent policy bridge.
- Omnigent and Gensee may both have policy decisions for the same action. The
  deeper integration should make precedence and user approval behavior explicit
  rather than stacking duplicate prompts.

## Deeper Integration Plan

The next step is an Omnigent policy adapter:

1. Add a Gensee entrypoint that accepts Omnigent policy evaluation events.
2. Map Omnigent `PHASE_*` events into Gensee policy subjects and timeline
   records.
3. Return Omnigent-compatible `POLICY_ACTION_ALLOW`, `POLICY_ACTION_DENY`, and
   `POLICY_ACTION_ASK` decisions.
4. Preserve Omnigent metadata such as conversation id, harness, model, parent
   session, and native bridge id.
5. Add e2e coverage for `claude-native`, `codex-native`, SDK harnesses, MCP
   tools, and sub-agent sessions.
