# Dashboard

The Gensee Crate dashboard is a local native desktop application for inspecting the same
`GENSEE_HOME` store used by `gensee watch`, agent hooks, `gensee run`, and
`gensee timeline`.

Use it when you want to see live agent activity, policy decisions, alerts, file
and request lineage, review verdicts, and the active policy document in one
place.

## Launch

Build the CLI first so the dashboard can validate policy edits:

```bash
cargo build --release -p gensee-crate-cli
```

Install the dashboard dependencies once (requires Node 18+):

```bash
npm install --prefix dashboards --legacy-peer-deps
```

Install the pinned native Tauri CLI once:

```bash
cargo install tauri-cli --version "^2" --locked
```

Then launch the Tauri desktop app:

```bash
cd dashboards
GENSEE_HOME="$HOME/.gensee" cargo tauri dev
```

This opens a native window backed by the Rust core — no TCP server is
started. All data access goes through Tauri IPC.

## Requirements

- Node 18 or newer.
- A built `gensee` binary for policy validation.
- Linux development requires WebKitGTK and GTK development packages; see
	[`dashboards/README.md`](https://github.com/GenseeAI/gensee-crate/blob/main/dashboards/README.md#linux-tauri-prerequisites).

The Tauri app binds no TCP port. All data access goes through Rust `#[tauri::command]`
handlers over the Tauri IPC bridge. Policy writes apply `0600` permissions and
require a `gensee` binary for validation before writing the file.

**Threat model**: single-user workstation. Processes running as the same OS user
are implicitly trusted (they can already read `$GENSEE_HOME` directly). There is
no network-accessible endpoint to attack.

## Demo Data

A fresh store is empty. Populate the Timeline, Lineage, and Policy views by
running an agent session with `gensee run -- <agent>`, or point `GENSEE_HOME`
at an existing store that already has data.

```bash
# Example: run a quick Claude session to generate events
GENSEE_HOME=~/.gensee gensee run -- claude

# Then open the dashboard
cd dashboards && GENSEE_HOME=~/.gensee cargo tauri dev
```

## Live Policy Editing

The Policy page reads and writes `$GENSEE_HOME/policy.json` through a native
Tauri IPC command. Saves are validated by the policy engine before the file is
written with owner-only permissions (`0600` on Unix). The Settings, Decision
Rules, and Artifact Definitions tabs provide structured editing; the Advanced
(JSON) tab gives full raw access.

## Development

Run the native app with frontend hot reload:

```bash
cd dashboards && cargo tauri dev
```

The Tauri dev runner starts Vite automatically (configured in
`src-tauri/tauri.conf.json → build.beforeDevCommand`).

Type-check and build the frontend bundle:

```bash
npm --prefix dashboards run build
```

## Rendering Safety

Prompts, commands, file paths, tool names, policy reasons, and artifact URIs are
attacker-influenced input. Keep dynamic rendering on safe text APIs such as
React's JSX text nodes or `textContent`. Do not pass live Gensee values through
`innerHTML`, even inside the security console itself.
