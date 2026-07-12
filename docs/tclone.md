# Tclone Runtime Integration

Gensee can launch agents in a
[GenseeAI/os4agent](https://github.com/GenseeAI/os4agent) tclone-backed Podman
container on Linux hosts. This mode is for whole-workspace fork, inspect,
merge, copy-out, and discard workflows. Tclone provides low-latency
full-workspace forking for AI agents.

```bash
gensee run --runtime tclone -- codex
```

The host-side Gensee process owns container orchestration. It creates a source
container, copies the workspace into cloneable container storage, copies
detected agent config such as `CODEX_HOME` or `CLAUDE_CONFIG_DIR`, copies
`GENSEE_HOME`, and starts the agent in the foreground with `podman exec -it`.

Use a second terminal to fork the running source container:

```bash
gensee run list
gensee fork <run_id> --copies 2
gensee run shell <run_id-or-container>
gensee run diff <run_id-or-container>
gensee run merge <fork-id> --into <source-id>          # default: --git
gensee run merge <fork-id> --into <source-id> --filesystem
gensee run merge <fork-id> --into <source-id> --paths /workspace /home/gensee/.codex
gensee run switch <fork-id>
gensee run keep <run_id-or-container> --to /tmp/kept-workspace
gensee run discard <run_id-or-container>
```

`gensee run merge` is the reconciliation command. The default `--git` scope
applies the fork's repo patch back into its source container, including staged
changes and commits made after the recorded fork point. Use `--dry-run` to check
whether the patch applies cleanly without modifying the source, or `--force` to
merge from a fork that is not recorded as a direct child of the target source.
If a fork was created before fork-point metadata existed, `--git` falls back to
`git diff HEAD`, which includes staged and unstaged working-tree changes but not
already committed fork work.

`--filesystem` merges persistent container filesystem changes from the fork into
the source container. `--paths` does the same for selected container paths. Both
use the fork's tclone overlay lowerdir as the merge base and upperdir as the
fork delta, then stop with a conflict report if the source and fork changed the
same path differently. These scopes do not merge live memory, running process
state, or pseudo filesystems such as `/proc`, `/sys`, `/dev`, `/run`, and `/tmp`.
Gensee passes tclone's `--tfork-overlay-btrfs` flag internally when creating
forks, so users do not need to set it. Older plain btrfs-snapshot forks must be
recreated before filesystem merge.

`gensee run switch` does not merge files. It marks the selected fork as the
active source container for future shells, forks, and merge targets, and marks
the previous source as switched away when Gensee knows the parent source.

## Requirements

- Linux tclone host.
- Podman with `container clone --live`.
- The tclone CRIU/crun stack configured for Podman.
- A container image with the agent runtime available, or a host Node/NVM mount
  that makes Node-based shims such as Codex available.

Environment overrides:

```bash
export GENSEE_TCLONE_PODMAN=/path/to/os4agent/podman-tfork.sh
export GENSEE_TCLONE_IMAGE=ghcr.io/wuklab/webtop:ubuntu-kde
export GENSEE_TCLONE_NODE_ROOT="$HOME/.nvm"
export GENSEE_TCLONE_NODE_BIN="$(dirname "$(command -v node)")"
```

## Control Split

The current integration is host-owned:

- host Gensee starts source containers and forks
- host Gensee records source/fork lineage in `$GENSEE_HOME/tclone-runs.jsonl`
- in-container hooks and policy config are copied in with the agent config
- forked containers can be inspected, copied out, or discarded from the host

This keeps fork/snapshot/rollback outside the agent trust boundary. Future work
should add a post-fork rebind handshake so in-container hooks can rotate from
the source `GENSEE_RUN_ID` to a fork-specific run id after live cloning.

## Current Limitations

- `--runtime tclone` is separate from `--sandbox linux` in this first version.
  Linux seccomp, fanotify, and cgroup/nftables controls are not yet applied to
  tclone containers by `gensee run`.
- Tclone mode is not yet a confinement boundary. Source containers currently run
  with unconfined seccomp/AppArmor settings required by the live-clone bring-up,
  and copied agent/Gensee config is duplicated into each fork.
- Hook telemetry inside an already-running fork may still identify as the
  source run until post-fork rebind is implemented.
- `gensee run merge` defaults to `--git`, which merges repo changes from the
  fork into the source container. `--filesystem` and `--paths` merge persistent
  container filesystem changes with conflict detection. None of the merge scopes
  merge process memory or external side effects.
- Merge into an active source container can race with writes from the running
  source agent. Prefer merging when the source agent is idle, stopped, or at a
  known checkpoint.
- `gensee run keep` copies a forked workspace out to a destination directory for
  inspection/debugging.
