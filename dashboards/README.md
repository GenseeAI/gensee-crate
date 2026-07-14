# Gensee Crate UI

Native Tauri dashboard for the Gensee Crate security monitor. The React
frontend communicates with the Rust backend through process-local Tauri IPC;
the dashboard does not start an HTTP API server.

## Requirements

- Node 18 or newer
- Rust stable and the Tauri CLI (`cargo install tauri-cli --version '^2'`)
- A built `gensee` CLI binary (for policy validation)
- Linux: WebKitGTK development packages (see the Tauri prerequisites below)

## Quick start

```bash
# Install dependencies (once)
npm install

# Launch the native desktop application
GENSEE_HOME="$HOME/.gensee" cargo tauri dev
```

## Scripts

| Command | Description |
|---|---|
| `cargo tauri dev` | Native desktop app with Vite hot-module reload |
| `cargo tauri build` | Build native installable application bundles |
| `npm run dev` | Development asset server for the Tauri WebView only |
| `npm run build` | Production build into `dist/` |

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `GENSEE_HOME` | `~/.gensee` | Path to the Gensee data directory containing `gensee.db` |
| `GENSEE_DB_PATH` | `$GENSEE_HOME/gensee.db` | Override the SQLite database path directly |
| `GENSEE_BIN` | auto-detected | Path to the `gensee` binary for policy validation |

## Architecture

```
Tauri WebView                    Rust backend (same native process)
   React + TypeScript  ──IPC invoke()──▶  src-tauri/src/lib.rs
   src/                                  SQLite + policy filesystem access
   src/api/client.ts                     Tauri events for live activity
```

Vite uses `http://localhost:5174` only during `cargo tauri dev` to serve
hot-reload assets to the native WebView. It is not a dashboard API and normal
browsers cannot render the dashboard or invoke its IPC commands. Production
builds embed the static frontend; they do not open a localhost port.

## Linux Tauri prerequisites

On Ubuntu/Debian:

```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev \
   libayatana-appindicator3-dev librsvg2-dev build-essential pkg-config
```

## Policy editing

The Policy page loads `$GENSEE_HOME/policy.json` (or the bundled default if not
yet customised). Saving validates the document via the `gensee` binary then
writes `$GENSEE_HOME/policy.json` with owner-only permissions (`0600` on Unix).
The next hook or `gensee run` invocation picks up the change automatically.
