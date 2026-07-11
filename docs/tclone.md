# Tclone Runtime Integration

Gensee can launch agents in a tclone-backed Podman container on Linux hosts.
This mode is for whole-workspace fork, inspect, keep, and discard workflows.

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
gensee run keep <run_id-or-container> --to /tmp/kept-workspace
gensee run discard <run_id-or-container>
```

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
- `gensee run keep` copies a forked workspace out to a destination directory; it
  does not merge changes back into the original workspace.
