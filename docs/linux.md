# Linux host support

Linux support is experimental and targets agents running directly on Linux
developer hosts or managed Linux workspaces. It is separate from container or
tclone runtime work: the first goal is to observe and enforce policy for a local
Claude Code, Codex, Omnigent, or similar agent process tree without requiring
the agent to run inside a container.

## What works now

- `gensee linux status` reports host capabilities such as fanotify, seccomp,
  cgroup v2, nftables, Landlock, BPF mounts, AppArmor, SELinux, and available
  speculation backends.
- `gensee linux plan` reports the Linux enforcement plan derived from the
  default Linux policy and the detected host capabilities.
- `gensee linux monitor --pid <pid>` performs `/proc` process-tree attribution
  for a root agent process and emits normalized exec events for the root and
  descendants.
- `gensee linux fanotify-plan` shows which sensitive-path policy rules can be
  installed as fanotify permission marks.
- `gensee linux fanotify-once` starts the Linux fanotify permission backend,
  installs marks for supported sensitive paths, polls once, evaluates observed
  permission events through `LinuxPolicy::evaluate_access`, and writes
  `FAN_ALLOW` or `FAN_DENY` back to the kernel.
- `gensee linux seccomp-profile` prints the default seccomp launcher profile.
- `gensee linux exec-seccomp -- <agent> [args...]` starts an agent under a
  seccomp filter that hard-denies dangerous syscall families such as `ptrace`,
  `bpf`, kernel module loading, mount changes, and namespace switching.
- `gensee linux network-plan` generates a cgroup v2 plus nftables egress plan.
- `gensee linux network-apply` creates/attaches the cgroup process tree and
  applies the generated nftables script.

The fanotify backend is the first contextual Linux system-level enforcement path
in Gensee Crate. It can deny file opens/accesses before the target process
continues. It requires Linux, root, and a kernel with fanotify permission events
enabled.

The seccomp launcher is a coarse hard-deny layer. It is less contextual than
fanotify, but it applies directly at the syscall boundary for processes launched
through the wrapper and does not require root.

The cgroup/nftables layer is a process-scoped network enforcement path. It
places the agent process tree into a cgroup v2 subtree and uses nftables
`socket cgroupv2` matching to allow listed IP/CIDR destinations or reject other
egress. It requires Linux, root, cgroup v2, and nftables.

## Commands

Inspect capabilities:

```bash
gensee linux status --json
```

Inspect the policy/capability plan:

```bash
gensee linux plan --json
```

Inspect the fanotify mark plan:

```bash
gensee linux fanotify-plan --json
```

Monitor a running agent process tree:

```bash
gensee linux monitor --pid <agent-root-pid> --json
```

Poll the fanotify backend once:

```bash
sudo gensee linux fanotify-once --json
```

`fanotify-once` is intentionally a low-level smoke path. A long-running Linux
daemon loop is still future work.

Inspect the seccomp launcher profile:

```bash
gensee linux seccomp-profile --json
```

Launch an agent under the default seccomp profile:

```bash
gensee linux exec-seccomp -- claude
gensee linux exec-seccomp -- codex
```

The launcher sets `no_new_privs` and installs the filter in the child process
immediately before `exec`.

Inspect a cgroup/nftables egress plan:

```bash
gensee linux network-plan \
  --session-id claude-1 \
  --pid <agent-root-pid> \
  --allow 10.0.0.0/8 \
  --allow 2001:db8::/32 \
  --json
```

Apply the cgroup/nftables plan:

```bash
sudo gensee linux network-apply \
  --session-id claude-1 \
  --pid <agent-root-pid> \
  --allow 10.0.0.0/8
```

If no `--allow` values are supplied, the network policy defaults to deny-all
for the attached cgroup. Use `--monitor` to generate a non-blocking nftables
table.

## Sensitive-path coverage

The current fanotify mark planner supports:

- exact paths such as `/path/to/file`
- prefix roots such as `/path/to/secret/**`
- home-relative prefix roots such as `~/.ssh/**`

It does not yet directly mark suffix glob patterns such as `**/.env` or
`**/.env.*`. Those rules are reported as warnings in `gensee linux
fanotify-plan` until recursive directory discovery or broader filesystem/mount
marking is added.

## Enforcement behavior

Linux policy keeps posture and action separate:

- `LinuxEnforcementMode` is the posture: `Monitor`, `Warn`, `Enforce`, or
  `Isolate`.
- `LinuxPolicyAction` is the per-rule outcome: `Observe`, `Warn`, `Ask`,
  `Deny`, or `Speculate`.
- `LinuxSpeculationBackend` records available runtime backends such as
  `FileStaging`, `OverlayFs`, `BtrfsSnapshot`, or `Tclone`.
- `LinuxEnforcementPlan` reports whether speculation was requested and whether
  a backend is available.

At the fanotify boundary, `Deny`, `Ask`, and `Speculate` currently fail closed
with `FAN_DENY`. `Ask` needs a prompt broker before it can safely block and wait
for a user decision. `Speculate` needs a transactional backend before the
operation can be allowed into a rollback-capable runtime.

At the seccomp boundary, the default profile allows ordinary syscalls and denies
configured dangerous syscall families with `EPERM`. The default profile blocks:

- `ptrace`, `process_vm_readv`, and `process_vm_writev`
- `bpf`
- `init_module`, `finit_module`, and `delete_module`
- `mount`, `umount2`, `pivot_root`, and the newer mount API calls
- `unshare` and `setns`

The profile intentionally does not block broad process creation syscalls such as
`clone`, because that would break ordinary developer tools and language
runtimes.

At the cgroup/nftables boundary, the current planner accepts IP and CIDR
destinations. Hostname allowlists are reported as warnings and skipped, because
safe hostname support needs DNS resolution plus policy reload logic.

## What is still future work

- A long-running Linux daemon that owns fanotify, process monitoring, event
  storage, and policy reloads.
- Recursive sensitive-path fanotify marks for patterns such as `**/.env`.
- eBPF telemetry for richer exec, file, and network attribution.
- More contextual seccomp policies that inspect syscall arguments where useful.
- DNS-aware network allowlists and live nftables policy reloads.
- Landlock/AppArmor profile generation where those systems are available.
- Integration with tclone or another transactional runtime for speculative
  execution and rollback.
