# Tclone Runtime Integration

Gensee can launch agents in a
[GenseeAI/os4agent](https://github.com/GenseeAI/os4agent) tclone-backed Podman
container on Linux hosts. This mode is for whole-workspace fork, inspect,
merge, copy-out, and discard workflows. Tclone provides low-latency
full-workspace forking for AI agents.

```bash
export GENSEE_HOME="${GENSEE_HOME:-$HOME/.gensee}"
export GENSEE_TCLONE_PODMAN="$HOME/os4agent/podman-tfork.sh"
export GENSEE_TCLONE_IMAGE="${GENSEE_TCLONE_IMAGE:-localhost/gensee-tclone-webtop:tmux}"
export GENSEE_TMP_ROOT="${GENSEE_TMP_ROOT:-/tmp}"
export TMPDIR="$GENSEE_TMP_ROOT"
# Optional: point at a dedicated rootful Podman store whose storage driver is btrfs.
# export CONTAINERS_STORAGE_CONF="$GENSEE_HOME/tclone-btrfs-storage.conf"
alias gensee-tclone='sudo env "PATH=$PATH" "HOME=$HOME" "TERM=$TERM" "TMUX=$TMUX" "TMPDIR=$TMPDIR" "GENSEE_TMP_ROOT=$GENSEE_TMP_ROOT" "CONTAINERS_STORAGE_CONF=$CONTAINERS_STORAGE_CONF" "GENSEE_HOME=$GENSEE_HOME" "GENSEE_TCLONE_PODMAN=$GENSEE_TCLONE_PODMAN" "GENSEE_TCLONE_IMAGE=$GENSEE_TCLONE_IMAGE" gensee'

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

Keep `GENSEE_TMP_ROOT` outside the workspace you pass to `gensee run`. If the
private `gensee-agent-guard` staging tree lands inside the workspace, a later
source launch can recursively copy that tree into itself and fail with
`File name too long`.

Tclone requires rootful Podman to use the `btrfs` storage driver. It is not
enough for an `overlay` Podman graphroot to live on a btrfs filesystem: the
running container root then appears as an overlay `merged` mount, and tclone's
btrfs snapshot step fails with `Not a Btrfs filesystem`. On hosts that already
have an overlay rootful store, create a separate storage config and pass it
through every Gensee wrapper command with `CONTAINERS_STORAGE_CONF`:

```toml
# $GENSEE_HOME/tclone-btrfs-storage.conf
[storage]
driver = "btrfs"
runroot = "/mnt/btrfs/gensee-podman-run"
graphroot = "/mnt/btrfs/gensee-podman-storage"
```

Images are scoped to the selected Podman store. After creating a btrfs store,
load or pull `GENSEE_TCLONE_IMAGE` into that same store before launching a
source:

```bash
sudo env "PATH=$PATH" "HOME=$HOME" "TMPDIR=$TMPDIR" \
  "$GENSEE_TCLONE_PODMAN" save "$GENSEE_TCLONE_IMAGE" \
  | sudo env "PATH=$PATH" "HOME=$HOME" "TMPDIR=$TMPDIR" \
      "CONTAINERS_STORAGE_CONF=$CONTAINERS_STORAGE_CONF" \
      "$GENSEE_TCLONE_PODMAN" load
```

Verify the store that Gensee will use:

```bash
sudo env "PATH=$PATH" "HOME=$HOME" "TMPDIR=$TMPDIR" \
  "CONTAINERS_STORAGE_CONF=$CONTAINERS_STORAGE_CONF" \
  "$GENSEE_TCLONE_PODMAN" info --format '{{.Store.GraphRoot}} {{.Store.GraphDriverName}}'
```

The driver must print `btrfs`.

Use a second terminal to fork the running source container:

```bash
gensee-tclone run list
gensee-tclone run list --json
gensee-tclone run fork <source-run-id> --copies 2 --name try-upgrade \
  --approach 'minimal compatible upgrade' \
  --approach 'aggressive latest-version upgrade' \
  --attach tmux:right --json
gensee-tclone run shell <run_id-or-container>
gensee-tclone run attach <run_id-or-container>
gensee-tclone run attach <run_id-or-container> --tmux right
gensee-tclone run send <run_id-or-container> -- 'Run npm test and fix failures'
gensee-tclone run exec <run_id-or-container> -- bash -lc 'cargo test'
gensee-tclone run diff <run_id-or-container> [--json]
gensee-tclone run summary <fork-id> --json
gensee-tclone run compare <parallel-fork-id> --json
gensee-tclone run choose <parallel-fork-id> <--merge|--promote|--discard-all>
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
and presents the changed files, tests, and merge/promote-to-main/discard choices
in chat. It must not merge, switch, or discard until the user approves that choice.
The host-control bridge checks that a later `UserPromptSubmit` hook recorded the
same choice and consumes that approval after the command succeeds. An agent
command without that state is denied. Direct commands entered at the host CLI
remain an explicit host-user authorization.

This is a workflow-integrity gate, not an isolation boundary against a malicious
same-user process inside the fork. Tclone currently trusts the fork agent and
does not prevent it from tampering with its own hook state; the gate prevents an
ordinary confused agent from skipping the user-choice turn.

For parallel work, Codex proposes distinct approaches before asking for one
approval. A named `--copies 2` group creates clean container names such as
`try-upgrade-0` and `try-upgrade-1` when those names are free. If an unresolved
older run still owns the clean names, Gensee automatically appends a timestamped
suffix to the new group's prefix so repeated smoke tests can fork without manual
cleanup. Repeated `--approach` values are assigned in index order and included
in each fork's task context as validated, bounded labels rather than trusted
instructions. The first fork no longer coordinates the
user-facing decision; every fork reports only its own completion. When all forks
finish, Gensee sends the source Codex a comparison prompt. The source runs
`run compare --json`, which reports each approach's changed files, tests,
readiness, and a smallest-passing-diff recommendation. That recommendation is
only a size-and-test-status heuristic, not a correctness judgment; Codex must
present it as a suggestion for the user's decision.
After the user selects an approach and lifecycle action in the source pane,
`run choose` merges or promotes that winner and schedules every other group
member for discard. `--discard-all` retires the whole group. These remain
agent-facing commands protected by the same later-user-approval gate as
single-fork lifecycle commands.

The source id is the row with role `source` under the `Tclone containers`
section of `gensee run list`. The launcher also prints it directly:
`gensee: fork from another terminal with: gensee run fork run_...`.
When hooks see requests or commands that are good fork candidates, such as
dependency upgrades, migrations, broad refactors, lockfile changes, destructive
cleanup, or database resets, Gensee records a
`policy_capability_delegation_required` alert with a provider-neutral capability
request. The request declares filesystem, network, identity, process, untrusted
code, and external-mutation needs; resource selectors whose empty value means
"not granted" rather than "allow all"; its effect scope; a maximum lease lifetime;
and whether execution requires an isolated cell or a brokered commit. This model
is intentionally operation-based rather than package-manager-specific. The
alert also includes suggested `gensee run fork --attach tmux:right --json`
guidance. In Codex source
runs, matching user prompts add fork guidance before planning; matching source
commands are blocked as a backstop so Codex can ask for a fork and continue the
work there. The live-cloned Codex turn continues the original approved task
automatically; the source does not resend the prompt. Forked Codex runs are
allowed to execute reversible local commands. Requests classified as external
mutations remain blocked inside forks because a workspace fork cannot roll back
an external effect; those require a brokered commit path.

Destructive commands against direct file-backed clients such as `sqlite3` and
`duckdb` are classified as irreversible local filesystem mutations and routed
to an isolated cell. Remote database clients and database commands executed
inside another container remain external mutations that require a brokered
commit path. Irreversible local requests fail closed with high severity for
every provider unless the command is already running in a disposable tclone
fork; this also applies to destructive workspace cleanup. An observe-only
policy can explicitly downgrade the stable capability-delegation rule when
enforcement is intentionally disabled.
The fork exemption is granted only by a role-consistent run-context marker at
Gensee's fixed runtime path. `GENSEE_TCLONE_CONTEXT_PATH` is a test-only
override, and an inherited `GENSEE_RUN_ID` may identify a source run but cannot
claim that execution is already isolated in a fork.

The alert's `capability_request` is a descriptive starting template, not a
ready-to-lease document. Its selectors are intentionally empty (empty means
"not granted"), so a trusted issuer must copy it and add exact path, network,
identity, or external-target selectors before `gensee run lease issue` will
accept it. Generated requests default to the cell runtime's 240-second maximum
lease lifetime.

The default external-mutation decision is a hard block. For a controlled
observe-only baseline, an operator can explicitly override the stable rule id
in the active policy; `warn` records the finding without denying the command:

```json
{
  "review_overrides": [
    {
      "rule_id": "policy_capability_delegation_required",
      "action": "warn"
    }
  ]
}
```

This override applies to every capability-delegation finding and should be
removed before enforcement testing.
Use the same `gensee-tclone` wrapper for `run list`, `run fork`, `run shell`,
`run attach`, `run send`, `run exec`, `run merge`, `run switch`, and cleanup;
otherwise Gensee may read the source record but look in a different Podman store
and report that the container is missing.

### Capability decision engine

Schema-v2 capability requests carry typed privilege deltas for file operations,
network destinations and protocols, secret handles and identities, cloud/IAM
resources and actions, syscalls and Linux capabilities, external
applications/APIs, database roles/actions, irreversible effects, and output
promotion. They do not contain an executor, source-execution toggle, or
inspect-before-commit toggle. Unknown fields are rejected, so an untrusted
producer cannot smuggle an old executor choice into the request. Empty
selectors always mean unresolved authority rather than a wildcard grant.

The provider-neutral policy engine returns a plan with independent dimensions:

- `executor`: `current_operation`, `trusted_mediator`, `fresh_cell`, or
  `live_fork`, selected only from trusted runtime facts;
- `lease_delta`: exact capability classes, required mediator attachments, and
  a bounded TTL. A capability listed as locally leaseable means its exact
  resource scope was already checked by a trusted backend;
- `approval`: `none`, `before_execution`, or `before_promotion`;
- `promotion`: `none`, `attest_before_return`, `transactional_promotion`, or
  `external_commit_receipt`;
- `decision`: `plan` or `deny`, with required and unavailable mediators plus
  stable reason codes.

An inseparable live-runtime effect requires a Tclone fork; untrusted or staged
effects otherwise select a fresh cell. External effects and effects classified
as completely brokerable by trusted context select a trusted mediator.
Bounded, fully revocable deltas may stay in the current operation. Unresolved
scopes, excessive leases, unavailable mediators
or executors, unbounded network grants, raw secret material, policy-denied
kernel authority, and unavailable required approval staging fail closed.

The orchestrator must declare mediators active for the specific operation;
installation on the host is not enough. Boundaries include process/cgroup,
filesystem, network, secret and workload-identity brokers, kernel controls,
cloud/API and browser gateways, database proxy, and transactional output
promotion. The fresh-cell lease path recomputes the decision immediately before
execution from its actually active boundaries. Filesystem, process/cgroup,
seccomp, AppArmor, and attached local broker gateways are supported; newly
modeled or unattached authority fails closed.

Typed filesystem operations are enforced by the fresh-cell path at this layer:
`read` and `execute` selectors become read-only mounts, while `create`, `write`,
`rename`, `delete`, and `metadata` selectors become writable mounts. This keeps
`destructive_filesystem` requests satisfiable without accepting unrelated typed
network, identity, or external selectors before their mediators exist.
The cell's disposable snapshot contains an `irreversible_local` effect, so it
does not require approval merely to execute there. The trusted decision still
returns `transactional_promotion` independently; promotion remains a separate
attest-and-commit action.

### Capability cells

The host-side mint/revoke protocol and secret-free adapter contract are
documented in [Capability broker](capability-broker.md).

Issuing a cell lease reserves an operation id, cell id, exact command, scope,
deadline, and trusted policy plan; it does not claim that future broker-backed
mediators are already active. At issue time the policy engine receives the
process/cgroup, filesystem, and kernel boundaries every fresh cell enforces and
the explicit set of attachable mediators. Immediately before execution,
Gensee derives the active set again from broker leases actually attached to
that cell, requires a `fresh_cell` plan, and requires every mediator delta to
be empty. Thus an unimplemented or unattached cloud, browser, database,
identity, secret, or network gateway cannot execute.

For a bounded authority-expanding operation, a trusted host operator can issue a
one-use lease bound to a source run, an exact command, scoped workspace paths,
and an expiry:

```console
gensee run lease issue run_... --request request.json -- /bin/sh -lc 'find . -maxdepth 2 -type f -print'
gensee run cell run_... --lease lease_... --json
gensee run cell inspect cell_... --json
gensee run cell promote cell_... --into run_... --path Cargo.lock --dry-run
gensee run cell promote cell_... --into run_... --path Cargo.lock
```

The cell is a fresh container rather than a live-memory clone. It does not
inherit the source agent home, credentials, memory, host-control capability, or
ambient network. Its root filesystem is read-only, Linux capabilities are
dropped, privilege gain is disabled, an explicit seccomp deny profile and
AppArmor profile are applied, resources are capped, and only explicitly
selected workspace paths are copied and mounted. A trusted, read-only copy of
the source container's Gensee binary supervises startup, requires Landlock,
grants read/execute access to the immutable image, and grants filesystem
mutation only to `/tmp`, `/run`, and the declared writable output mounts before
executing the leased command. Attached broker authority is
represented only by opaque ids and exact Unix-domain gateway socket mounts;
without a direct network lease the cell keeps `--network none`. Podman independently enforces the
remaining lease lifetime and automatic removal as a backstop if the Gensee
client exits. The exact command is fixed when the trusted host
issues the lease; the lease is consumed atomically before scoped input copying,
and its lifetime covers both snapshot preparation and command execution. This
prevents a caller from using an expired grant merely because staging was slow.
The container is destroyed on completion,
while its scoped workspace snapshot and execution record are retained for
inspection and replay planning. Gensee keeps an immutable input snapshot and a
separate writable output snapshot, hashes their actual contents, and writes a
typed `effect-manifest.json`. The manifest distinguishes requested capabilities
from observed use and records changed files, file reads, process lifecycles,
the exact-command digest, promotion proposals, violations, and explicit
telemetry coverage. Every Linux cell is held behind a startup gate while Gensee
places the container tree in its own cgroup and establishes mount-wide
fanotify permission marks over every declared effect mount: the immutable
container root, `/tmp`, `/run`, scoped workspace binds, the startup gate, the
trusted supervisor, and each private broker socket bind. A dedicated host
sensor thread services permission events so the orchestrator cannot block on
its own gate or evidence writes. The typed `filesystem_read_coverage` detail
records the container paths for all expected, covered, and uncovered effect
mounts.

Before opening the same startup gate, Gensee also subscribes to the Linux
process connector from the host's initial PID namespace and requires the
kernel's acknowledgement. Fork, exec, and exit events are filtered to the
container's inspected root PID and descendants. Process evidence records the
host PID, parent PID, `/proc` start-time ticks, executable, argument digest,
start/finish time, and decoded exit status; PID plus start-time ticks prevents
PID reuse from changing attribution. A process-connector receive overrun,
malformed message, identity race, subscription failure, fanotify queue
overflow, missing mount mark, or sensor failure produces explicit incomplete
coverage and a manifest violation. Evidence received before a failure is
retained, but it is never relabeled complete.

Promotion now requires complete filesystem-read telemetry when filesystem read
authority was requested and complete process-lifecycle telemetry when process,
privileged, or untrusted execution was requested. Thus a clean cell can be
promoted when both sensors prove coverage, while a host without either sensor
continues to fail closed. Capability cells therefore require Linux cgroup v2,
root fanotify support, and the Linux process connector (`CONFIG_CONNECTOR` and
`CONFIG_PROC_EVENTS`) available from the initial user and PID namespaces.

Install and load the shipped AppArmor profile before using cells:

```console
sudo install -m 0644 packaging/apparmor/gensee-capability-cell /etc/apparmor.d/gensee-capability-cell
sudo apparmor_parser -r /etc/apparmor.d/gensee-capability-cell
```

The default profile name is `gensee-capability-cell`; a missing profile causes
cell startup to fail closed. `gensee status` reports whether this default
capability-cell profile is loaded, so the prerequisite can be checked before a
cell is issued.

The immutable part of the manifest, the exact request and command, and both
snapshot tree digests are bound into an HMAC-authenticated
`forensics-evidence.json`. `gensee run cell inspect` verifies that signature and
all retained artifacts before displaying them. `replay-plan.json` contains the
exact original request, command, input digest, and required broker resource
kinds. `gensee run cell replay <cell-id> --source <source-id>` issues a new
one-use lease which will execute only if the new source produces the identical
input digest. Broker credentials and identities are deliberately not replayed;
fresh cell-bound broker leases must be attached to the new operation.

Before activating a cell, Gensee writes an owner-only cleanup journal naming
only its exact container, broker leases, expiry, and, when present, generated
nftables table and cgroup. Normal teardown marks the journal clean only after
network cleanup and lease revocation succeed. Subsequent lease, cell, and broker
operations reconcile expired active journals: they force-remove the exact
container, idempotently remove generated network state, and retry provider
revocation. Inspection remains available if reconciliation fails, preserving
the manifest and journal for forensics.

Nothing is promoted into the source automatically. Promotion is host-only and
requires explicit path selectors. Gensee re-hashes both snapshots, rejects a
changed manifest or output, requires a successful non-timeout execution with
zero violations, complete snapshot-diff coverage for writable outputs, and
complete telemetry for requested network, external-request, and secret effects,
verifies the signed forensic envelope, and verifies that each selected source
path still matches the immutable input. It then applies only the selected diff
through the existing rollback-on-failure filesystem transaction. Successful
promotions are appended to a separately HMAC-authenticated promotion ledger
(and mirrored in the manifest); a repeated or overlapping promotion is
rejected. Use `--dry-run` to perform all evidence and conflict checks without
changing the source.

An exact write scope may name a path that does not exist yet when its typed
file operation is `create`. Gensee preserves that absence in the immutable
input snapshot and materializes only the declared file or directory in the
isolated output layer, so the manifest records `created` and promotion can
perform the correct absence/conflict check. A declared file create is an exact
single-file bind mount; programs that publish through a sibling temporary file
and `rename(2)` must instead declare a writable parent directory. Symlink mount
targets are rejected.

Direct network leases are supported on Linux only when they pin IP/CIDR,
TCP/UDP, and exact ports. Gensee creates a private cell network namespace,
never the host network namespace, binds identical nftables forward and
host-input allowlists to its inspected
address, and attaches its process tree to a fresh cgroup before a trusted
startup gate releases the leased command. Covering both routing hooks prevents
an allowed origin from redirecting a cell to an unleased service on the Gensee
host. Gensee then records allowed counters and blocked attempts. Policy-denied
kernel authority and external mutations still fail closed. Repository/API,
identity, mTLS, browser, cloud, and database authority can run only through a
source/operation/cell-bound broker gateway.
The gateway must return complete typed effect telemetry at revocation or the
result cannot be promoted.

Before cloning a tmux-backed source, `gensee run fork` may briefly detach the
active `gensee-agent` client so tclone can checkpoint a stable process tree.
Gensee shows a short tmux status message and automatically reattaches the source
session as soon as the container is ready. If the host command runs inside tmux
and the sudo wrapper preserves `TMUX`, `gensee run fork --attach tmux:right`
opens the new fork in a right-side pane and reconnects to the cloned
in-container `gensee-agent` session. With `--copies 2`, additional forks are
opened below the previous fork pane, leaving the source on the left and one
stacked fork column on the right. `gensee run attach <id> --tmux right` can open
an existing run or fork in a new host pane.

When `--attach tmux:right` opens a pane, the pane re-enters
`gensee run attach <fork-id>`. That re-entry must inherit the same Podman store
and temporary-root environment as the source and fork commands, especially
`CONTAINERS_STORAGE_CONF`, `GENSEE_TMP_ROOT`, and `TMPDIR`. If a pane appears
and immediately disappears, check that the wrapper preserves those variables
and start a fresh source with the rebuilt `gensee` binary; already-running
sources keep the old host-control process in memory.

The os4agent tfork kernel helper modules must be built for the running kernel.
If `insmod` reports `Invalid module format`, compare `modinfo <module>.ko`
`vermagic` with `uname -r`, rebuild the modules against
`/lib/modules/$(uname -r)/build`, and load them again. Missing helpers surface
later as absent `/dev/vma_cherrypick`, `/dev/criu_capbypass`, `/dev/reparent`,
or `/dev/pkey_state` device nodes in CRIU/tfork logs.

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
promote-to-main-and-end-source, or discard. After explicit approval, the fork can invoke only its
own lifecycle action against its direct source. Container-mediated `run send`
remains source-to-direct-child only and is used for later follow-up prompts.
Before follow-up tmux input is sent, Gensee marks the child task `queued`. Fork
creation reports success only after the child has received its authoritative
fork context.

## Transaction History in the Dashboard

The native dashboard's **Transactions** page records the state-changing tclone
lifecycle: source start/end, fork, merge, switch, keep, discard, and delete.
Started, successful, failed, forced, and merge dry-run outcomes are retained in
the encrypted Gensee SQLite store. Multi-copy forks are grouped as one operation
with individually addressable child runs.

Use Dependencies for the default fork-and-merge relationship graph, or History
for a chronological, branch-aware view. Selecting a run opens Timeline filtered
to that source or fork. While the dashboard is running, new operations appear
live in Transactions and in Live Feed under **Transactional environment**.

Container deletion is resource cleanup only: it adds a terminal history event
and does not remove prior provenance. Interactive commands such as `attach`,
`shell`, `exec`, and `diff` are not lifecycle transactions and remain outside
this view.

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

`gensee run switch` does not merge files. It promotes the selected fork to the
main source environment for future work, rewrites its lifecycle context so it
can create and resolve new forks, transfers the host-control bridge to it, ends
the previous source container, and closes the previous source pane. The
user-facing choice is therefore “Promote this fork to the main environment and
end the old source,” rather than the ambiguous “Keep working.” Chained
promotions serialize ownership of the shared host-control endpoint so the new
source cannot rebind it while the previous server is still active.

`gensee run discard <run_id-or-container>` first records the fork as
`discarded` and returns the lifecycle response. A delayed cleanup then removes
the fork container, closes its attached pane, focuses the source pane, and
keeps the `discarded` record for history. Cleanup for container-proxied merge,
promotion, and discard waits for an authenticated acknowledgement emitted after
the lifecycle response has been printed and flushed; it does not depend on a
fixed sleep being long enough. Direct host-CLI resolutions retain a short grace
period because there is no container proxy to acknowledge delivery. Detached
cleanup and promotion diagnostics are written under
the private Gensee temporary root's `tclone-resolution/` directory (normally
`/tmp/gensee-agent-guard/tclone-resolution/`), and the lifecycle response
prints the exact log path. `gensee run delete <run_id-or-container>`
removes the container and removes that tclone record from `gensee run list`.
Use `gensee run delete --all` to clean tracked tclone containers, clear the
tclone section of the run list, and reap untracked `gensee-tclone-*` orphan
containers in the same Podman store. If a response acknowledgement is lost,
cleanup fails safe and leaves the environment running; either delete command
can reap that stranded environment. Lifecycle logs and acknowledgement markers
are retained for seven days and pruned opportunistically when another
lifecycle action runs.

### Host disk cleanup

Run the repository cleanup script from a separate host shell when old tclone
runs, `/tmp` state, or Cargo artifacts have filled the host disk. Do not run it
inside a Gensee source or fork container.

```bash
cd ~/gensee-crate
scripts/cleanup_tclone_host.sh --yes
```

The default cleanup deletes tracked tclone runs and `gensee-tclone-*` orphan
containers, removes the private `gensee-agent-guard` directory under `TMPDIR`
(normally `/tmp/gensee-agent-guard`), cleans Cargo artifacts, rebuilds `gensee`
in release mode, and reinstalls it at the current `gensee` path (or
`~/.cargo/bin/gensee`). It keeps unrelated containers and tagged images intact.
Custom absolute `TMPDIR` locations are canonicalized before the script removes
their exact `gensee-agent-guard` child.

On a dedicated tclone host where every Podman container is disposable, use the
stronger cleanup that also removes all containers and prunes unused volumes and
dangling image layers:

```bash
scripts/cleanup_tclone_host.sh --all-podman-data --yes
```

This deliberately does not run `podman system prune --all`: the configured
tagged tclone image is preserved, avoiding a subsequent short-name resolution
failure. Use `--dry-run` to review every destructive and rebuild command first,
or `--install-to /absolute/path/to/gensee` to select another install target.
The script resolves the existing `gensee`, Podman wrapper, and privileged host
utilities to absolute executable paths before invoking `sudo`; those binaries
and any tools called internally by a configured wrapper must belong to the
trusted host administrator. Failure to delete the selected private temporary
directory stops the script before rebuilding so a partial cleanup is not
reported as successful.

## Requirements

- Linux tclone host.
- Podman with `container clone --live`.
- The tclone CRIU/crun stack configured for Podman.
- A container image with the agent runtime available, or a host Node/NVM mount
  that makes Node-based shims such as Codex available.
- `tmux` inside the image for `gensee run attach` with live/forked interactive
  agents. `gensee run shell` only opens a new shell and does not require tmux.
- `setsid` from util-linux on the host for `gensee run switch`; promotion uses
  it to keep the host-control handoff alive while the old source is retired.

Environment overrides:

```bash
export GENSEE_TCLONE_PODMAN=/path/to/os4agent/podman-tfork.sh
export GENSEE_TCLONE_IMAGE=ghcr.io/wuklab/webtop:ubuntu-kde
export GENSEE_TCLONE_NODE_ROOT="$HOME/.nvm"
export GENSEE_TCLONE_NODE_BIN="$(dirname "$(command -v node)")"
export GENSEE_TCLONE_READY_TIMEOUT_SECS=120
```

The Node root is mounted read-only at `/opt/gensee-host-node` (with a separate
safe bin mount when needed), and absolute agent executables are remapped into
that tree. It is deliberately never mounted over `/usr/local`: doing so would
hide Gensee's trusted `gensee-tclone-init` and `gensee` launchers before the
container can establish its control and cleanup invariants.

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
registry remain host-owned. Before live cloning, Gensee revokes the source host
capability and preinstalls a distinct context and capability for every planned
fork. Hook ingestion treats that fork context as authoritative over the cloned
source process environment, so telemetry and host-control requests rebind to the
fork run immediately; the source receives a freshly rotated capability only
after clone completion.

Host hook observation uses a separate owner-only Unix socket that accepts only
authenticated `event_store_append_tclone_hook` messages. The general Gensee
daemon socket is never mounted into the container, so the observer cannot append
sessions or transactions and cannot ask the host policy engine for decisions.
This capability establishes run attribution, not containment: a process that can
read the run context can submit observations for that run. Set
`GENSEE_TCLONE_BIND_HOST_OBSERVER=0` before launch to omit the observer socket
entirely. The observer rejects requests over 2 MiB, applies a five-second total
read deadline, and admits at most 32 concurrent connections; excess clients are
closed before a worker thread is allocated.

## Current Limitations

- Long-lived `--runtime tclone` sources and live forks remain separate from
  `--sandbox linux`; Linux fanotify and general session cgroup/nftables controls
  are not yet applied to those containers by `gensee run`. Fresh capability
  cells do apply their operation-scoped cgroup/nftables policy.
- Fresh capability cells are a fail-closed confinement boundary. Long-lived
  Tclone sources and live forks are not: they currently run with unconfined
  seccomp/AppArmor settings required by live-clone bring-up, and copied
  agent/Gensee config is duplicated into each fork.
- A live fork intentionally inherits source process memory and is suitable only
  for same-authority speculative work. Authority-expanding cells always use the
  fresh-sandbox path, which inherits neither process memory nor agent
  credentials.
- `gensee run merge` defaults to `--git`, which merges repo changes from the
  fork into the source container. `--filesystem` and `--paths` merge persistent
  workspace changes with conflict detection and transactional rollback. None
  of the merge scopes merge process memory or external side effects.
- Merge into an active source container can race with writes from the running
  source agent. Prefer merging when the source agent is idle, stopped, or at a
  known checkpoint.
- `gensee run keep` copies a forked workspace to a new, absolute destination
  directory for inspection/debugging; it refuses existing destinations.
