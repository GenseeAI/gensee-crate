# `gensee run` — managed launch and the macOS sandbox

`gensee run` launches an agent as a managed child, records a local run record in
`$GENSEE_HOME/sessions.jsonl`, captures the spawned agent root PID, and sets:

- `GENSEE_RUN_ID`
- `AGENT_SHIELD_SESSION_ID`
- `AGENT_SHIELD_START_TIME_MS`

`AGENT_SHIELD_SESSION_ID` is still set for compatibility, but the preferred name
for a Gensee-launched process root is now `GENSEE_RUN_ID`. Agent hook
`session_id` values remain the agent conversation/session IDs.

```bash
cargo run -p gensee-crate-cli -- run -- claude
cargo run -p gensee-crate-cli -- run -- omnigent run path/to/agent.yaml
cargo run -p gensee-crate-cli -- run list
cargo run -p gensee-crate-cli -- timeline
```

## Runtime governance

Managed runs can enforce a wall-clock maximum runtime:

```bash
gensee run --max-runtime-seconds 1800 -- claude
```

The same value can be supplied with `GENSEE_MAX_RUNTIME_SECONDS`. When the agent
exceeds the limit, Gensee terminates the child process, records the ended
session, and returns a timeout error.

If `GENSEE_EGRESS_PROXY_URL` is set, `gensee run` passes it to the child as
`HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY`. The `PreToolUse` policy also uses
that setting to enable egress-proxy governance; see
[policy.md#resource-governance](policy.md#resource-governance).

## Managed macOS sandbox mode

The v0.1 managed Mac path adds `sandbox-exec` confinement and a staged
workspace:

```bash
cargo run -p gensee-crate-cli -- run \
  --sandbox mac \
  --profile cautious \
  --workspace-mode staged \
  -- claude
```

This creates a staged workspace by recursively copying the visible working tree,
including uncommitted changes, while skipping heavyweight local directories such
as `.git`, `node_modules`, `target`, `.gensee`, and `.gensee-dev`. It then
launches the agent through `sandbox-exec` with an allow-default,
targeted-deny SBPL profile:

- deny common secret paths such as `~/.ssh`, `~/.aws`, and `~/.config/gcloud`
- deny writes to the original workspace when staged mode is active
- allow network for the launched agent itself, because cloud-model agents need
  outbound model/API access

`--deny-network`, CPU/memory quotas, deny-default profiles, and container mode
are intentionally not part of this first cut.

## Staged workspace review and discard

Staged workspaces are left on disk for review. The CLI prints the staged path
and a discard command after the run:

```bash
gensee run discard run_<pid>_<timestamp_ms>
```

Merge-back and automatic rollback flows are future work.

## Omnigent

`gensee run` can launch Omnigent as a managed child process:

```bash
gensee run --workspace "$PWD" -- omnigent run path/to/agent.yaml
```

For a first safety demo, prefer a staged workspace:

```bash
export GENSEE_HOME="$HOME/.gensee-omnigent"

gensee run \
  --workspace "$PWD" \
  --workspace-mode staged \
  -- omnigent
```

This is thin support: Gensee records the Omnigent root process and workspace
effects, and staged mode keeps generated edits out of the original working tree
until review. It does not yet consume Omnigent's internal policy events. See
[the Omnigent integration guide](../integrations/omnigent/README.md) for the
current workflow and deeper bridge plan.
