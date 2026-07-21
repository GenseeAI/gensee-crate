# Tclone Runtime Integration

Gensee can launch agents in a
[GenseeAI/os4agent](https://github.com/GenseeAI/os4agent) tclone-backed Podman
container on Linux hosts. This mode is for whole-workspace fork, inspect,
merge, copy-out, and discard workflows. Tclone provides low-latency
full-workspace forking for AI agents.

```bash
export GENSEE_HOME="${GENSEE_HOME:-$HOME/.gensee}"
export GENSEE_TCLONE_PODMAN="$HOME/os4agent/podman-tfork.sh"
alias gensee-tclone='sudo env "PATH=$PATH" "HOME=$HOME" "TERM=$TERM" "TMUX=$TMUX" "GENSEE_HOME=$GENSEE_HOME" "GENSEE_TCLONE_PODMAN=$GENSEE_TCLONE_PODMAN" "GENSEE_TCLONE_IMAGE=$GENSEE_TCLONE_IMAGE" gensee'

gensee-tclone run --runtime tclone -- codex
```

The host-side Gensee process owns container orchestration. It prepares a source
container with the workspace, detected agent config such as `CODEX_HOME`,
`CLAUDE_CONFIG_DIR`, or Antigravity's `GEMINI_HOME`, and `GENSEE_HOME`, then
starts the agent as the container's main process. If the image has `tmux`,
Gensee runs the agent inside a named `gensee-agent` tmux session and
`gensee run attach` reconnects to that session. Treat `tmux` as required for
reliable attach to live/forked interactive agents; raw Podman attach is only a
fallback and may not survive tclone restore.
Add the exports and alias to `~/.bashrc`, `~/.zshrc`, or your shell profile if
you use this host regularly. If testing from a source checkout, replace the
alias target `gensee` with `./target/debug/gensee`.

Use a second terminal to fork the running source container:

```bash
gensee-tclone run list
gensee-tclone run list --json
gensee-tclone run fork <source-run-id> --copies 2
gensee-tclone run fork <source-run-id> --name try-upgrade --attach tmux:right --json
gensee-tclone run shell <run_id-or-container>
gensee-tclone run attach <run_id-or-container>
gensee-tclone run attach <run_id-or-container> --tmux right
gensee-tclone run send <run_id-or-container> -- 'Run npm test and fix failures'
gensee-tclone run exec <run_id-or-container> -- bash -lc 'cargo test'
gensee-tclone run diff <run_id-or-container> [--json]
gensee-tclone run summary <fork-id> --json
gensee-tclone run merge <fork-id> --into <source-id>          # default: --git
gensee-tclone run merge <fork-id> --into <source-id> --filesystem
gensee-tclone run merge <fork-id> --into <source-id> --paths /workspace/src /workspace/Cargo.toml
gensee-tclone run switch <fork-id>
gensee-tclone run keep <run_id-or-container> --to /tmp/kept-workspace
gensee-tclone run discard <run_id-or-container>
gensee-tclone run delete <run_id-or-container>   # remove container and hide from run list
gensee-tclone run delete --all                   # clean tracked runs and gensee-tclone-* orphans
```

When Codex starts work in a fork, these lifecycle commands are internal agent
controls. Codex polls `run list --json`, reads `run summary <fork-id> --json`,
and presents the changed files, tests, and keep-working/merge/discard choices in
chat. It must not merge, switch, or discard until the user approves that choice.
The host-control bridge checks that a later `UserPromptSubmit` hook recorded the
same choice and consumes that approval after the command succeeds. An agent
command without that state is denied. Direct commands entered at the host CLI
remain an explicit host-user authorization.

This is a workflow-integrity gate, not an isolation boundary against a malicious
same-user process inside the fork. Tclone currently trusts the fork agent and
does not prevent it from tampering with its own hook state; the gate prevents an
ordinary confused agent from skipping the user-choice turn.

The source id is the row with role `source` under the `Tclone containers`
section of `gensee run list`. The launcher also prints it directly:
`gensee: fork from another terminal with: gensee run fork run_...`.
When hooks see requests or commands that are good fork candidates, such as
dependency upgrades, migrations, broad refactors, lockfile changes, destructive
cleanup, or database resets, Gensee records a `policy_fork_suggested` alert with
suggested `gensee run fork --attach tmux:right --json` guidance. In Codex source
runs, matching user prompts add fork guidance before planning; matching source
commands are blocked as a backstop so Codex can ask for a fork and continue the
work there. The live-cloned Codex turn continues the original approved task
automatically; the source does not resend the prompt. Forked Codex runs are
allowed to execute the command.
Use the same `gensee-tclone` wrapper for `run list`, `run fork`, `run shell`,
`run attach`, `run send`, `run exec`, `run merge`, `run switch`, and cleanup;
otherwise Gensee may read the source record but look in a different Podman store
and report that the container is missing.
Before cloning a tmux-backed source, `gensee run fork` may briefly detach the
active `gensee-agent` client so tclone can checkpoint a stable process tree.
Gensee shows a short tmux status message and automatically reattaches the source
session as soon as the container is ready. If the host command runs inside tmux
and the sudo wrapper preserves `TMUX`, `gensee run fork --attach tmux:right`
opens the new fork in a right-side pane and reconnects to the cloned
in-container `gensee-agent` session. With `--copies 2`, additional forks are
opened below the first fork pane. `gensee run attach <id> --tmux right` can open
an existing run or fork in a new host pane.

Use `gensee run send <id> -- <prompt>` to paste a prompt into the fork's
in-container `gensee-agent` tmux session and press Enter. If that fork is
attached in a host tmux pane, the pane visibly shows the forked agent receiving
and executing the work:

```bash
FORK_ID=$(gensee-tclone run fork <source-run-id> --name try-upgrade --attach tmux:right --json \
  | jq -r '.forks[0].run_id')
gensee-tclone run send "$FORK_ID" -- 'Try the dependency upgrade, run tests, and summarize the result.'
```

When a fork is scheduled asynchronously from inside an agent, the JSON response
includes `status_command` and `retry_after_ms`. Poll immediately and keep
retrying that same status command while `status=running`. The active poll is
intentionally inherited by the live clone, allowing the forked Codex turn to
stop source orchestration and continue the task automatically. Async agent forks
ignore `GENSEE_TCLONE_WAIT_QUIET_FOR_FORK`; waiting for an idle source would
prevent the active turn from being handed off. Do not resend the original prompt.
If status is
`failed`, stop and inspect the included log summary. While running, status JSON
includes recent log lines so agents can explain quiet-wait or clone failures
instead of spinning blindly. During live-clone capability rotation, or when the
clone inherits an in-flight control response, a poll may temporarily return
`status=running`, `transient=true`, and `retry_after_ms`; retry the same status
command and never schedule a replacement fork. JSON status polls use a short
control-bridge timeout so the source cannot
wait on a response consumed by the clone. If the fork inherits the source's
status poll, Gensee tells the fork pane to stop source orchestration, continue
the original task, run its internal completion summary, and offer merge,
keep-working, or discard. After explicit approval, the fork can invoke only its
own lifecycle action against its direct source. Container-mediated `run send`
remains source-to-direct-child only and is used for later follow-up prompts.
Before follow-up tmux input is sent, Gensee marks the child task `queued`. Fork
creation reports success only after the child has received its authoritative
fork context.

Use `gensee run exec <id> -- <command>` for non-interactive work in a fork,
such as commands requested by an agent. The command runs inside the container
workspace without attaching to the live agent UI, and receives the container's
`GENSEE_RUN_ID`, `AGENT_SHIELD_SESSION_ID`, `GENSEE_HOME`, and
`GENSEE_WORKSPACE` context. Like `gensee run shell`, this is a host/container
control command and does not run the command through the agent PreToolUse hook;
use it only for commands you intend to execute in that fork. It runs alongside
any live in-container agent, so concurrent writes to the same workspace files can
race. For shell features or a series of commands, wrap them explicitly:

From the host, `run exec` may target any selected run. Through the in-container
host-control bridge, a run may execute only in itself. A source hands work to
direct child forks with `run send`, can inspect those children with scoped
`run list --json`, `run diff --json`, and `run summary --json`, and can resolve
them with merge, switch, or discard after user approval.

```bash
gensee-tclone run exec <fork-id> -- bash -lc 'npm install && npm test'
```

`gensee run merge` is the reconciliation command. The default `--git` scope
applies the fork's repo patch back into its source container, including staged
changes and commits made after the recorded fork point. Use `--dry-run` to check
whether the patch applies cleanly without modifying the source, or `--force` to
merge from a fork that is not recorded as a direct child of the target source.
If a fork was created before fork-point metadata existed, `--git` falls back to
`git diff HEAD`, which includes staged and unstaged working-tree changes but not
already committed fork work.

`--filesystem` merges persistent changes under the container workspace from the
fork into the source container. `--paths` does the same for selected paths under
that workspace; absolute paths outside the workspace and `..` escapes are
rejected. Both use the fork's tclone overlay lowerdir as the merge base and
upperdir as the fork delta, then stop with a conflict report if the source and
fork changed the same path differently. Eligible changes are copied into a
private staging tree and applied with rollback backups so a failed copy/apply
does not leave a delete-before-copy partial merge. These scopes do not merge
live memory, running process state, or pseudo filesystems such as `/proc`,
`/sys`, `/dev`, `/run`, and `/tmp`.
Gensee passes tclone's `--tfork-overlay-btrfs` flag internally when creating
forks, so users do not need to set it. Older plain btrfs-snapshot forks must be
recreated before filesystem merge.

`gensee run switch` does not merge files. It marks the selected fork as the
active source container for future shells, forks, and merge targets, and marks
the previous source as switched away when Gensee knows the parent source.

`gensee run discard <run_id-or-container>` removes the container and keeps a
`discarded` record for history. `gensee run delete <run_id-or-container>`
removes the container and removes that tclone record from `gensee run list`.
Use `gensee run delete --all` to clean tracked tclone containers, clear the
tclone section of the run list, and reap untracked `gensee-tclone-*` orphan
containers in the same Podman store.

## Requirements

- Linux tclone host.
- Podman with `container clone --live`.
- The tclone CRIU/crun stack configured for Podman.
- A container image with the agent runtime available, or a host Node/NVM mount
  that makes Node-based shims such as Codex available.
- `tmux` inside the image for `gensee run attach` with live/forked interactive
  agents. `gensee run shell` only opens a new shell and does not require tmux.

Environment overrides:

```bash
export GENSEE_TCLONE_PODMAN=/path/to/os4agent/podman-tfork.sh
export GENSEE_TCLONE_IMAGE=ghcr.io/wuklab/webtop:ubuntu-kde
export GENSEE_TCLONE_NODE_ROOT="$HOME/.nvm"
export GENSEE_TCLONE_NODE_BIN="$(dirname "$(command -v node)")"
export GENSEE_TCLONE_READY_TIMEOUT_SECS=120
```

## Control Split

The current integration is host-owned:

- host Gensee starts source containers and forks
- host Gensee records source/fork lineage in `$GENSEE_HOME/tclone-runs.jsonl`
- in-container hooks and policy config are copied in with the agent config
- forked containers can be inspected, copied out, or discarded from the host

Container-to-host control uses a per-run capability in the run context. Requests
are signed, short-lived, and replay-protected. A source capability may fork that
source, poll its own fork jobs, send prompts to direct child forks, inspect their
results, and resolve them after approval. JSON run listings are scoped to the
caller and its direct children. A fork cannot control its source or siblings;
`run attach`, `run shell`, and human-readable global run listings remain
host-only.

The capability authenticates the container, not an individual agent process:
any process that can read `/tmp/gensee-run-context.json` inside that container
inherits that run's limited authority. It does not gain another run's capability
or broader host command execution. Fork/snapshot/rollback mechanics and the run
registry remain host-owned. Future work should add a post-fork rebind handshake
so in-container hooks can rotate from the source `GENSEE_RUN_ID` to a
fork-specific run id after live cloning.

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
  workspace changes with conflict detection and transactional rollback. None
  of the merge scopes merge process memory or external side effects.
- Merge into an active source container can race with writes from the running
  source agent. Prefer merging when the source agent is idle, stopped, or at a
  known checkpoint.
- `gensee run keep` copies a forked workspace to a new, absolute destination
  directory for inspection/debugging; it refuses existing destinations.
