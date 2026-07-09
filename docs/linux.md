# Linux host support

Linux support is experimental and targets agents running directly on Linux
developer hosts or managed Linux workspaces. It is separate from container or
tclone runtime work: the first goal is to observe and enforce policy for a local
Claude Code, Codex, Omnigent, or similar agent process tree without requiring
the agent to run inside a container.

## What works now

- `gensee status` reports host capabilities such as fanotify, seccomp,
  cgroup v2, nftables, Landlock, BPF mounts, AppArmor, SELinux, and available
  speculation backends.
- `gensee watch --pid <pid>` performs `/proc` process-tree attribution for a
  root agent process and records normalized exec events for the root and
  descendants.
- `gensee run --sandbox linux -- <agent> [args...]` applies Linux host controls
  from policy. `--linux-seccomp`, `--no-linux-seccomp`, `--linux-fanotify`,
  `--linux-network`, and `--allow-net`/`--deny-net` remain per-run overrides for
  demos and debugging.
- `gensee run --sandbox linux` is the preferred workflow for network
  enforcement when policy enables it: it installs nftables for the run cgroup,
  starts the agent through a small internal exec wrapper, joins that cgroup, and
  then execs the real agent.
- `gensee debug ...` contains backend probes such as `plan`, `fanotify-plan`,
  `fanotify-once`, `seccomp-profile`, `network-plan`, and `network-apply`.
  These are for development/admin debugging, not the normal enforcement path.

The older `gensee linux ...` form is kept as a compatibility alias while Linux
support is experimental. New docs and scripts should use the top-level command
shape.

The fanotify backend is the first contextual Linux system-level file-enforcement
path in Gensee Crate. `gensee run --sandbox linux --linux-fanotify -- <agent>`
starts a parent-owned listener thread for the run, marks supported sensitive
paths, answers permission events, and appends file-access decisions to the
timeline. Fanotify requires Linux, root, and a kernel with fanotify permission
events enabled.

The seccomp launcher is a coarse hard-deny layer. It is less contextual than
fanotify, but it applies directly at the syscall boundary for processes launched
through the wrapper and does not require root.

The cgroup/nftables layer is a process-scoped network enforcement path. It
places the agent process tree into a cgroup v2 subtree and uses nftables
`socket cgroupv2` matching to allow listed IP/CIDR destinations or reject other
egress. It requires Linux, root, cgroup v2, and nftables.

## Privilege model

`gensee run` always means Gensee is the parent launcher for the agent process.
That gives Gensee a run id, a root pid, lifecycle accounting, policy loading,
workspace-mode handling, and a place to install launch-time controls before the
real agent executes.

Without `sudo`, `gensee run -- <agent>` is still useful as a supervised launch:
it can launch and attribute the agent, record the run, and use direct or staged
workspace mode. `gensee run --sandbox linux -- <agent>` means Linux host
controls are requested, so it fails closed unless seccomp or network enforcement
is active. Seccomp can run without root when policy enables it and the kernel
supports seccomp filters.

`sudo` is needed only for Linux features that modify kernel-owned global or
privileged state:

- cgroup/nftables network enforcement, because Gensee creates a cgroup subtree
  and installs nftables rules.
- fanotify permission-event enforcement, because permission-event marks require
  root or equivalent capability.
- future eBPF-based telemetry or enforcement, because loading BPF programs and
  reading privileged kernel data requires elevated privilege on normal hosts.

The macOS path has a different shape. macOS support is currently stable around
agent hooks, filesystem watching, staged workspaces, and `sandbox-exec`
profiles. `eslogger` can add EndpointSecurity-derived telemetry with Full Disk
Access and `sudo`, but it is not the same as owning a signed EndpointSecurity
client that can make production-grade blocking decisions. Linux gives Gensee
earlier access to host-level controls through seccomp, fanotify, cgroups,
nftables, and future eBPF work.

## Commands

Inspect capabilities:

```bash
gensee status --json
```

Watch a running agent process tree:

```bash
gensee watch --pid <agent-root-pid> --duration-seconds 60
```

Configure policy, then launch an agent with the configured Linux controls:

```bash
gensee policy setup
sudo gensee run --sandbox linux -- codex
```

For Node/npm-installed agent CLIs such as Codex or Claude Code, `sudo` may
replace the user `PATH` with a restricted `secure_path`. If the launch fails
with an error like `env: 'node': No such file or directory`, preserve `PATH`
when invoking Gensee:

```bash
sudo env "PATH=$PATH" gensee run --sandbox linux -- codex
```

From a source checkout, use the debug binary the same way:

```bash
sudo env "PATH=$PATH" ./target/debug/gensee run --sandbox linux -- codex
```

If the agent cannot find user auth or config files, add `"HOME=$HOME"` as well:

```bash
sudo env "PATH=$PATH" "HOME=$HOME" gensee run --sandbox linux -- codex
```

Preserving `HOME` can cause a root-launched process to create root-owned files
in the user's home directory, so use it only when needed. Seccomp-only launches
can usually run without `sudo`; cgroup/nftables network enforcement currently
requires root.

Setting `linux.network.deny` without changing `linux.network.mode` is treated
as deny-only monitor mode for `gensee run`: Gensee installs rejects for the
listed destinations while leaving other egress allowed.

Network policy destinations must currently be IP or CIDR strings. Hostnames are
still useful in higher-level hook policy, but cgroup/nftables enforcement
rejects hostname entries on apply because safe hostname support needs DNS
resolution plus live policy reloads.

For managed Linux runs, Gensee installs nftables counters on reject rules and
reads them before run cleanup. Nonzero counters are appended as
`NetworkBlocked` Layer 1 system events with packet and byte counts, so
`gensee timeline` can show blocked destinations. This is currently a run-end
summary; exact child PID and per-attempt timestamps require future nft log or
eBPF attribution.

Relevant policy keys:

```json
{
  "linux": {
    "seccomp": {
      "enabled": true,
      "deny_ptrace": true,
      "deny_bpf": true,
      "deny_kernel_modules": true,
      "deny_mount_namespace_changes": true
    },
    "network": {
      "mode": "allowlist",
      "allow": ["1.1.1.1"],
      "deny": ["169.254.169.254"]
    }
  }
}
```

The seccomp launcher sets `no_new_privs` and installs the filter in the child
process immediately before `exec`.

Inspect a cgroup/nftables egress plan for debugging:

```bash
gensee debug network-plan \
  --session-id claude-1 \
  --pid <agent-root-pid> \
  --allow 10.0.0.0/8 \
  --deny 169.254.169.254 \
  --allow 2001:db8::/32 \
  --json
```

Apply the cgroup/nftables plan to an existing process tree for debugging:

```bash
sudo gensee debug network-apply \
  --session-id claude-1 \
  --pid <agent-root-pid> \
  --allow 10.0.0.0/8 \
  --deny 169.254.169.254
```

If no `--allow`, `--deny`, `--deny-all`, or `--monitor` override is supplied,
the debug network commands use `linux.network` from policy. Use `--monitor` to
generate a non-default-blocking nftables table, optionally with explicit deny
destinations.

For real agent launches, prefer `gensee run` so the network policy follows the
agent you start:

```bash
sudo gensee run \
  --sandbox linux \
  -- codex
```

If `codex` or `claude` is installed through npm, prefer:

```bash
sudo env "PATH=$PATH" gensee run \
  --sandbox linux \
  --linux-fanotify \
  -- codex
```

## Sensitive-path coverage

The current fanotify mark planner supports:

- exact paths such as `/path/to/file`
- prefix roots such as `/path/to/secret/**`
- home-relative prefix roots such as `~/.ssh/**`

It does not yet directly mark suffix glob patterns such as `**/.env` or
`**/.env.*`. Those rules are reported as warnings in
`gensee debug fanotify-plan` until recursive directory discovery or broader
filesystem/mount marking is added.

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
with `FAN_DENY` in the run listener and debug enforcer. `Ask` needs a prompt
broker before it can safely block and wait for a user decision. `Speculate`
needs a transactional backend before the operation can be allowed into a
rollback-capable runtime.

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
