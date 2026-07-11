# `gensee run` — managed launch and host controls

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

## What `gensee run` Means

`gensee run -- <agent>` starts the agent as a child process of Gensee. That
lets Gensee assign a run id, track the root pid, load policy, choose workspace
mode, record lifecycle metadata, and install any launch-time controls that are
available for the selected platform.

Running without `sudo` is still meaningful. On both macOS and Linux, Gensee can
supervise the agent and apply controls that do not require elevated privilege.
On Linux, plain `gensee run -- <agent>` is a supervised launch, while
`gensee run --sandbox linux -- <agent>` requests Linux host controls and fails
closed unless seccomp or network enforcement is active. Seccomp can run without
root when the kernel supports seccomp filters. Root is needed when the requested
policy uses root-only host features, such as cgroup/nftables network policy or
fanotify permission-event probes.

## macOS vs. Linux

The macOS and Linux run paths intentionally use different OS primitives:

- macOS: `gensee run --sandbox mac` uses `sandbox-exec` and staged workspace
  review. `gensee watch` can use FSEvents and optional `eslogger` telemetry.
  Deeper file/process/network blocking is planned through a signed Apple
  EndpointSecurity client.
- Linux: `gensee run --sandbox linux` uses Linux host controls configured in
  policy. Seccomp can hard-deny dangerous syscalls without root. Network
  enforcement uses cgroup v2 plus nftables and currently needs root.
  `--linux-fanotify` starts a run-owned fanotify permission listener for
  supported sensitive-path file access and currently needs root. `sudo gensee
  watch --pid PID --linux-fanotify` attaches the same fanotify enforcement path
  to an already-running agent process tree.

## Managed Linux Sandbox Mode

On Linux, `gensee run --sandbox linux` can launch the agent through initial
host-enforcement layers configured in policy:

```bash
gensee policy setup

sudo gensee run \
  --sandbox linux \
  --linux-fanotify \
  -- codex
```

When launching npm/Node-based agents such as Codex or Claude Code with `sudo`,
preserve the user `PATH`; otherwise the agent shim may fail to find `node`:

```bash
sudo env "PATH=$PATH" gensee run \
  --sandbox linux \
  -- codex
```

For source-tree testing, the same rule applies to the debug binary:

```bash
sudo env "PATH=$PATH" ./target/debug/gensee run \
  --sandbox linux \
  -- codex
```

If the agent needs user auth or config files, you can also pass `"HOME=$HOME"`,
but root-launched agents may create root-owned files there. Use `sudo` for
cgroup/nftables network enforcement; seccomp-only launches can usually run as
the current user.

When `linux.seccomp.enabled` is true, Gensee installs the configured hard-deny
syscall profile before the agent binary executes. When `linux.network.mode` is
`allowlist`, `deny-all`, or has deny destinations, Gensee creates a per-run
cgroup, installs a cgroup-scoped nftables egress policy, starts the agent
through an internal exec wrapper, joins that cgroup, and then execs the real
agent.

A non-empty `linux.network.deny` with `linux.network.mode` left as `off` is
treated as deny-only monitor mode: only the listed destinations are rejected.
Destinations must currently be IP/CIDR values; hostname entries cause apply to
fail instead of being silently skipped.

Before cleanup, managed Linux runs read nftables reject counters and append
nonzero counters as `NetworkBlocked` system events. These appear in
`gensee timeline` with the blocked destination when known. The current event is
a run-level summary; exact child process attribution is planned with future nft
logging or eBPF telemetry.

`--linux-seccomp`, `--no-linux-seccomp`, `--linux-network`, `--allow-net`, and
`--deny-net` are per-run overrides for demos, tests, and emergency debugging.

Use `gensee status` to inspect host capabilities. Backend-specific probes such
as `gensee debug seccomp-profile` and `gensee debug network-plan` are available
for development/admin debugging. See [Linux host support](linux.md) for details
and current limitations.

## Tclone Runtime Mode

On prepared Linux tclone hosts, `gensee run --runtime tclone` launches an agent
inside cloneable Podman container storage:

```bash
export GENSEE_TCLONE_PODMAN=/home/yiying/os4agent/podman-tfork.sh
gensee run --runtime tclone -- codex
```

From another terminal, fork and inspect the running source container:

```bash
gensee run list
gensee fork <run_id> --copies 2
gensee run shell <run_id-or-container>
gensee run diff <run_id-or-container>
gensee run keep <run_id-or-container> --to /tmp/kept-workspace
gensee run discard <run_id-or-container>
```

This initial mode is separate from `--sandbox linux`: Gensee owns source/fork
container orchestration, while Linux seccomp, fanotify, and cgroup/nftables
controls are still applied by the direct Linux run path. See
[Tclone runtime integration](tclone.md) for setup and limitations.

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
[the Omnigent integration guide](https://github.com/GenseeAI/gensee-crate/tree/main/integrations/omnigent) for the
current workflow and deeper bridge plan.
