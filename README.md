<h1 align="center">
  <img src="dashboards/web/src/eye-only.png" alt="" width="48" />
  Gensee Crate
</h1>

<p align="center">
  <strong>Full-stack, long-horizon runtime safety for AI coding agents.</strong>
</p>

<p align="center">
  Gensee Crate watches system events, user requests, agent tool calls, skills and memory behind unmodified coding agents such as Claude Code, Codex, Antigravity, and <a href="https://github.com/omnigent-ai/omnigent" target="_blank">Omnigent</a>.
  It follows long-horizon agent behavior across requests and sessions and runs as a low-latency sidecar beside the agents on native hosts like macOS and, experimentally, Linux.
  Real-time enforcement happens within chat interface of the coding agents, with early Linux system-level syscall and network enforcement available through seccomp, cgroups, and nftables, plus fanotify planning/debug probes while continuous file enforcement is daemonized. Offline event tracking, lineage, and provenance can be viewed in a web dashboard and command line.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" /></a>
  <img alt="Status: alpha" src="https://img.shields.io/badge/status-alpha-orange.svg" />
  <img alt="Rust: stable" src="https://img.shields.io/badge/rust-stable-blue.svg" />
  <img alt="Platform: macOS first, Linux experimental" src="https://img.shields.io/badge/platform-macOS--first%20%7C%20Linux--experimental-lightgrey.svg" />
</p>

<p align="center">
  <a href="https://www.gensee.ai">gensee.ai</a>
  ·
  <a href="https://crate-docs.gensee.ai">Docs</a>
  ·
  <a href="https://www.gensee.ai/discord">Join Discord</a>
</p>

<p align="center">
  <img src="docs/gensee-crate-defense-in-depth.png" alt="Gensee Crate defense-in-depth architecture" />
</p>

<p align="center">
  Need company-enforced rules, credential and identity controls, and oversight
  across a distributed fleet of developer endpoints?
  <a href="https://www.gensee.ai/contact.html">Contact GenseeAI</a>.
</p>

---

## Why Gensee Crate?

Gensee Crate helps you:

- **Watch what your agent actually does.** Capture files read and written,
  commands run, network targets reached, hook intent, alerts, and timeline
  context in one local store.
- **Enforce policy before risky tools run.** Enforces a deterministic, configurable [policy](docs/policy.md) that can allow, ask, or
  deny secret reads, destructive ops, out-of-workspace writes, cloud-metadata
  access, control-plane writes, dangerous executable content, and more.
- **Trace provenance across sessions.** Lineage graphs link prompts,
  tool calls, filesystem effects, artifacts, alerts, and review verdicts so long-horizon safety issues such as memory poisoning and data exfiltration can be prevented in time and examined afterward.
- **Seamless integration with your current workflow.** Run `gensee watch` beside an
  agent or launch an agent in a sandbox with `gensee run` with additional safety.
  Manage policy with `gensee policy` and inspect activity in the local dashboard.

## Preliminary Benchmark Results

Preliminary AgentCanary benchmark results show Gensee Crate improving defense
rate across memory poisoning, long-horizon, and prompt-injection threat types
with low runtime overhead.

![Preliminary AgentCanary benchmark results](docs/images/preliminary-agentcanary-benchmark.png)

## Quick start

### 1. Install

One command installs Gensee Crate and checks or installs its command-line
prerequisites on macOS. At the end, the installer can configure supported agent
hooks for active safety policy enforcement, lets you choose `GENSEE_HOME`, and
lets you keep the bundled default policy or create an editable local policy:

```bash
curl -fsSL https://raw.githubusercontent.com/GenseeAI/gensee-crate/main/scripts/install_oss.sh | bash
```

For non-interactive installs that should configure Claude Code, Codex, and
Antigravity hooks:

```bash
curl -fsSL https://raw.githubusercontent.com/GenseeAI/gensee-crate/main/scripts/install_oss.sh | GENSEE_CONFIGURE_CLAUDE=1 GENSEE_CONFIGURE_CODEX=1 GENSEE_CONFIGURE_ANTIGRAVITY=1 bash
```

<details>
<summary>Prefer to install manually?</summary>

Install platform prerequisites first.

On macOS:

```bash
xcode-select --install

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

brew install jq
```

On Ubuntu/Debian Linux:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev jq nftables git

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

Build the CLI from source:

```bash
git clone https://github.com/GenseeAI/gensee-crate.git
cd gensee-crate
cargo build -p gensee-crate-cli
```

The binary is now at `target/debug/gensee`. For convenience, either add that
directory to your `PATH`, or install `gensee` globally:

```bash
cargo install --path crate/gensee-crate-cli   # puts `gensee` on PATH
```

Gensee stores its local state under `~/.gensee` by default. Set `GENSEE_HOME` to
override it, and use the **same** `GENSEE_HOME` for `watch`, hooks, `run`,
`timeline`, and the dashboard so the signals appear together. `GENSEE_HOME` is
the Gensee data store, not the agent project/workspace folder:

```bash
export GENSEE_HOME="$HOME/.gensee"
```

For hook-based agents, there are two paths to keep straight:

- `GENSEE_HOME`: where Gensee records hooks, alerts, timelines, policies, and
  dashboard data. Use the same value across Claude Code, Codex, Antigravity,
  Omnigent sidecars, `gensee watch`, `gensee timeline`, and the dashboard when
  you want one combined view.
- agent workspace/config path: where the agent looks for its hook settings.
  Claude Code uses `~/.claude/settings.json`, Codex uses `~/.codex/hooks.json`,
  and Antigravity defaults to global `~/.gemini/config/hooks.json`. Antigravity
  also supports workspace-local `.agents/hooks.json` when you pass `--hooks`.

Avoid pointing `GENSEE_HOME` at the project workspace root. A repo-local store
such as `$PWD/.gensee-dev` is convenient for development, while
`$HOME/.gensee-<agent>` is better for long-running sidecars such as Omnigent so
Gensee does not watch its own store writes.

The local store can include redacted prompts, commands, paths, policy alerts,
and lineage data. Fresh telemetry stores are encrypted at rest by default with a
local key in `$GENSEE_HOME/gensee.key`. Keep that key private and do not share
it with store snapshots; sharing the key and store together gives readers access
to the telemetry. Existing plaintext development stores remain readable rather
than breaking hooks; move or remove the old `GENSEE_HOME` to start a fresh
encrypted store. Set `GENSEE_STORE_ENCRYPTION=0` only for local debugging
stores.

</details>

<details>
<summary>Toolchain and prerequisites (if the installer reports a missing tool)</summary>

- macOS for the stable v0.1 path. Linux host support is experimental and
  currently focused on `/proc` process attribution, fanotify sensitive-path
  planning/debug probes, seccomp launcher profiles, and cgroup/nftables network
  controls.
- Claude Code, Codex, or Antigravity for hook-based enforcement. Other agents
  are planned.
- Rust toolchain (`cargo`) and `jq`.
- On Linux: build tools, `pkg-config`, OpenSSL headers, `nftables`, and `git`.

Install the required command-line tools on macOS:

```bash
xcode-select --install

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

brew install jq
```

Install the required command-line tools on Ubuntu/Debian Linux:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev jq nftables git

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

</details>

<details>
<summary>Configure agent hooks manually</summary>

To capture prompt/tool intent and enforce the [safety policy](docs/policy.md),
configure your agent's hooks to call the matching `gensee hook` endpoint. The
installer offers Claude Code, Codex, and Antigravity setup. To run the setup
step later for Claude Code:

```bash
gensee setup claude-code --gensee-home "$GENSEE_HOME"
```

If your team requires Claude Code traffic to pass through an inspecting LLM
gateway, configure that during the same setup step:

```bash
gensee setup claude-code \
  --gensee-home "$GENSEE_HOME" \
  --anthropic-base-url https://llm-gateway.example.com \
  --anthropic-auth-token "$GATEWAY_TOKEN"
```

For local screening/blocking, start the bundled gateway and point Claude Code at
it:

```bash
GENSEE_HOME="$GENSEE_HOME" \
GENSEE_BIN="$PWD/target/debug/gensee" \
GENSEE_GATEWAY_TOKEN="local-gateway-token" \
ANTHROPIC_UPSTREAM_API_KEY="$ANTHROPIC_API_KEY" \
node scripts/anthropic_gateway.mjs

./target/debug/gensee setup claude-code \
  --gensee-home "$GENSEE_HOME" \
  --anthropic-base-url http://127.0.0.1:8787 \
  --anthropic-auth-token local-gateway-token
```

Or for Codex:

```bash
gensee setup codex --gensee-home "$GENSEE_HOME"
```

Or for global Antigravity hooks:

```bash
gensee setup antigravity --gensee-home "$GENSEE_HOME"
```

For workspace-local Antigravity hooks instead, pass an explicit workspace hook
path:

```bash
gensee setup antigravity \
  --gensee-home "$GENSEE_HOME" \
  --hooks /path/to/workspace/.agents/hooks.json
```

If you are running from a source checkout instead of an installed binary:

```bash
./target/debug/gensee setup claude-code --gensee-home "$GENSEE_HOME"
./target/debug/gensee setup codex --gensee-home "$GENSEE_HOME"
./target/debug/gensee setup antigravity --gensee-home "$GENSEE_HOME"
```

The setup commands back up the previous hook settings, update
`~/.claude/settings.json`, `~/.codex/hooks.json`, or
`~/.gemini/config/hooks.json` by default, and use the absolute path to the
`gensee` binary you invoked. Fully restart Claude Code or Antigravity after
changing hook config. Open `/hooks` in Codex to review and trust the hook
command before testing enforcement. Full manual config and what gets recorded
(plus redaction details) are in
[`docs/claude-code-hooks.md`](docs/claude-code-hooks.md),
[`docs/codex-support.md`](docs/codex-support.md), and
[`docs/antigravity-support.md`](docs/antigravity-support.md).

</details>

<details>
<summary>Updating to a new release</summary>

Rerun the installer to update `gensee` in place:

```bash
curl -fsSL https://raw.githubusercontent.com/GenseeAI/gensee-crate/main/scripts/install_oss.sh | bash
```

If you installed from a source checkout, pull the latest changes and reinstall:

```bash
git pull --ff-only
cargo install --path crate/gensee-crate-cli --force
```

</details>

### 2. Run

Gensee has three protection levels you can combine:

- **Hooks only:** Agent requests and tool calling are checked and protected by the safety
  policy rules. Require agent hook installation (part of Step 1 above). No running commands needed.

- **`gensee watch`:** performs system-level event watching such as file system operations, macOS EndpointSecurityLogger events, etc. On macOS, `--system-events eslogger` needs Full Disk Access for the host app and `sudo` so it can create an EndpointSecurity client.

```bash
gensee watch # optional flags: --workspace --watch-root --duration-seconds --system-events
```

If you use `--system-events eslogger` on macOS, open Apple menu > System Settings > Privacy & Security > Full Disk Access, click `+`, add the app hosting `gensee` (for example Terminal, iTerm, or Visual Studio Code), then quit and reopen that app. Run the command with `sudo` as well.

- **`gensee run`:** starts the agent as a child of Gensee so the run can be
  attributed, recorded, and wrapped with launch-time controls. On macOS, this
  adds managed sandbox confinement and staged, reviewable workspace writes. On
  Linux, non-root runs can still supervise the agent and apply unprivileged
  controls such as seccomp when enabled; root is only needed for kernel features
  that require elevated privilege.

```bash
gensee run -- claude # or: gensee run -- codex
```

- **Experimental Linux host controls:** inspect Linux host capabilities, monitor
  a direct agent process tree through `/proc`, enforce supported fanotify
  sensitive-path permission decisions from `run` or `watch --pid`, launch an agent under a seccomp hard-deny
  syscall profile, and plan/apply cgroup-scoped nftables egress controls on Linux. The public CLI
  is capability-oriented; `gensee linux ...` remains only as a compatibility
  alias while this branch is experimental.

```bash
gensee status --json
gensee watch --pid <agent-root-pid>
sudo gensee watch --pid <agent-root-pid> --linux-fanotify
gensee policy setup
sudo gensee run --sandbox linux -- codex
```

`sudo` is needed for Linux controls that modify kernel-owned state, such as
cgroup/nftables egress enforcement and fanotify permission-event probes. It is
not required for basic `gensee run` supervision, staged workspace behavior, or
seccomp-only Linux launches.

When launching Node/npm-installed agents such as Codex or Claude Code with
`sudo`, preserve the user `PATH` so the agent shim can still find `node`:

```bash
sudo env "PATH=$PATH" gensee run --sandbox linux -- codex
```

If testing from a source build, use the same pattern with the debug binary:

```bash
sudo env "PATH=$PATH" ./target/debug/gensee run --sandbox linux -- codex
```

If the agent cannot find its auth or config files, also preserve `HOME`, but be
aware that a root-launched agent may create root-owned files in that directory.
Seccomp-only launches can usually run without `sudo`; cgroup/nftables network
enforcement currently requires it. `--sandbox linux` now fails closed if neither
seccomp nor network enforcement is active; use plain `gensee run -- <agent>` for
supervised-only launches.

The macOS and Linux paths are intentionally different. macOS uses agent hooks,
workspace watching, `sandbox-exec`, staged workspaces, and optional
`eslogger`-based telemetry; deeper blocking waits on Apple's EndpointSecurity
path. Linux can use lower-level primitives earlier: seccomp for syscall denies,
fanotify for sensitive file permission experiments, and cgroup/nftables for
process-scoped network policy. Network destinations must currently be IP/CIDR
values; hostname entries are rejected on apply rather than silently skipped.
Managed Linux runs record nftables counter summaries as `NetworkBlocked` Layer 1
system events after the agent exits, so `gensee timeline` shows blocked
destinations such as `169.254.169.254`. Exact per-attempt child PID attribution
is future eBPF/nft log work.
`--linux-fanotify` starts a run-owned fanotify permission listener for supported
sensitive-path file access and appends `FileAccess...` Layer 1 events.
`sudo gensee watch --pid <agent-root-pid> --linux-fanotify` uses the same
fanotify enforcement path as a sidecar attached to an already-running agent
process tree. Add harmless demo paths without replacing the built-in credential
rules:

```bash
gensee policy set linux.fanotify.paths '/tmp/gensee-demo-secret/**'
gensee debug fanotify-plan
```

For orchestration frameworks such as Omnigent, use the same primitives as a
thin outer safety layer:

```bash
gensee watch --workspace . --watch-root ~/.omnigent
gensee run --workspace-mode staged -- omnigent run path/to/agent.yaml
```

Inspect what happened at any time:

```bash
gensee run list   # list guarded run sessions and staged workspaces
gensee timeline   # show prompts, tool intent, file effects, and policy decisions
```

See [`docs/watch.md`](docs/watch.md),
[`docs/run-and-sandbox.md`](docs/run-and-sandbox.md), and
[`docs/linux.md`](docs/linux.md) for the full options.

### 3. Open the dashboard

The local dashboard reads the same `GENSEE_HOME` store as `watch`, hooks, and
`timeline`. It shows live agent activity, policy decisions, alerts, file and
request lineage, and the active policy document; users can record review
verdicts and edit validated policy settings from the browser.

Launch it from the repository checkout against your active store:

```bash
cd /path/to/agent-shield
GENSEE_HOME="$PWD/.gensee-dev" npm --prefix "$PWD/dashboards/web" run dev
# open http://localhost:5173
```

If you launch it from another directory, use absolute paths and the same
`GENSEE_HOME` that your hooks or `gensee watch` use:

```bash
REPO=/path/to/agent-shield
GENSEE_HOME="$REPO/.gensee-dev" npm --prefix "$REPO/dashboards/web" run dev
```

See [`dashboards/web/README.md`](dashboards/web/README.md) for requirements,
demo data, and policy editing notes.

The activity view brings policy decisions, timeline filtering, event details,
and command/tool context into one local browser surface.

![Gensee Crate dashboard activity timeline](docs/images/dashboard-activity.png)

The lineage view links derived artifacts and shows the facts behind each path,
including current risk state and the policy/query context used to inspect it.

![Gensee Crate artifact lineage dashboard](docs/images/dashboard-lineage.png)

The multi-turn view highlights long-horizon patterns across a session, including
read-to-exfiltration chains, memory-poison signals, repeated artifact targeting,
and policy decisions over time.

![Gensee Crate multi-turn provenance dashboard](docs/images/dashboard-multiturn.png)

### 4. Manage policy

`gensee policy` lets you inspect, initialize, validate, and edit the active
policy document without copying files by hand:

```bash
gensee policy path
gensee policy setup
gensee policy validate "$GENSEE_HOME/policy.json"
```

`gensee policy setup` walks through the same dashboard-style policy settings,
artifact definitions, and decision rules. Use it to tune resource limits,
network egress, runtime, enforcement, watch system events, allowlisted paths,
what counts as executable/memory/skill/control-plane artifacts, and whether
each safety rule denies, asks, or allows.

Use `gensee policy print-default` to inspect the bundled default policy. The
guided setup flow writes the user policy to `$GENSEE_HOME/policy.json`, which is
auto-loaded by the hook, CLI, and dashboard when `GENSEE_POLICY_FILE` is unset.
You can also point `GENSEE_POLICY_FILE` at a custom policy path; see
[`docs/policy.md`](docs/policy.md) for the full policy workflow.

### 5. Test

Run the unit/integration test suite:

```bash
cargo test --workspace
```

Prepare a populated dashboard store for UI testing:

```bash
cargo build --release -p gensee-crate-cli
dashboards/web/scripts/demo.sh
# open http://localhost:5173
```

Smoke-test the policy without launching an agent by feeding a sample
`PreToolUse` payload to a hook — a secret-path read should come back `deny`:

```bash
echo '{"session_id":"s1","hook_event_name":"PreToolUse","cwd":"'"$PWD"'","tool_name":"Bash","tool_use_id":"t1","tool_input":{"command":"cat ~/.ssh/config"}}' \
  | GENSEE_HOME="$PWD/.gensee-dev" ./target/debug/gensee hook claude-code
# => {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}
```

For Codex, use `./target/debug/gensee hook codex` with the same sample payload.

End-to-end: with hooks configured and the agent restarted or trusted, ask it to
read a sensitive file (e.g. `~/.ssh/config`); Gensee denies it, then the
decision and alert show up in the timeline:

```bash
GENSEE_HOME="$PWD/.gensee-dev" gensee timeline
```

## Roadmap

Gensee Crate is macOS-first today, with Claude Code, Codex, and Antigravity hook
support, local policy enforcement, staged workspace runs, local telemetry, and a
browser dashboard. Next directions include:

- **Linux system enforcement:** early `/proc` process attribution, fanotify
  sensitive-path enforcement, seccomp launcher profiles, and cgroup/nftables
  egress controls are available experimentally; eBPF, Landlock, and AppArmor
  work remains in progress.
- **Endpoint Security-based macOS defense:** deeper host-level file, process,
  and network visibility once the Apple Endpoint Security path is available.
- **Sandbox support:** stronger `gensee run` confinement, staged writes, and
  speculative or transactional execution for risky agent actions.
- **ML-based policy and rules:** learning from controlled traces, blocked
  actions, and bypass attempts to improve risk scoring and policy suggestions.
- **Integrations:** support for more agents and security tooling, including
  ChatGPT, Gemini, Cursor, GitHub Copilot, Omnigent, CrowdStrike, LLM gateways,
  MCP servers, and audit/security workflow exports.

See [`docs/roadmap.md`](docs/roadmap.md) for more detail.

## Documentation

Full docs live in [`docs/`](docs/README.md):

- [Architecture](docs/architecture.md) — the v0.1 wedge, workspace crates, and roadmap.
- [Roadmap](docs/roadmap.md) — planned Linux enforcement, macOS Endpoint Security, sandbox, ML policy, and integration work.
- [Linux host support](docs/linux.md) — experimental `/proc` monitoring,
  fanotify sensitive-path enforcement, seccomp launcher profiles,
  cgroup/nftables egress controls, and the Linux enforcement plan.
- [`gensee watch`](docs/watch.md) — sidecar filesystem and system-event audit, backends, and watch roots.
- [`gensee run` and the macOS sandbox](docs/run-and-sandbox.md) — managed launch and staged workspaces.
- [`gensee policy`](docs/gensee-policy.md) — inspect, initialize, validate, and edit local policy settings.
- [Claude Code hooks](docs/claude-code-hooks.md) — wiring Claude Code prompts and tool intent into Gensee.
- [Codex hooks](docs/codex-support.md) — wiring Codex prompts and tool intent into Gensee.
- [Antigravity support](docs/antigravity-support.md) — wiring Antigravity hooks and `.agents` customizations into Gensee.
- [Omnigent integration](integrations/omnigent/README.md) — thin sidecar/managed-run support and the deeper policy-bridge plan.
- [Safety policy](docs/policy.md) — the data-driven allow/ask/deny engine and `gensee policy` workflow.
- [SQLite lineage graph](docs/lineage-graph.md) — the provenance schema and example queries.
- [Endpoint Security spike](docs/endpoint-security.md) — `eslogger` system events and the future signed EndpointSecurity path.
