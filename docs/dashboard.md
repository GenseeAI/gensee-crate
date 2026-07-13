# Dashboard

The Gensee Crate dashboard is a local browser console for inspecting the same
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
npm install --prefix dashboards
```

Then start the dashboard against the store you want to inspect:

```bash
cd dashboards
GENSEE_HOME="$HOME/.gensee" npm run dev:full
# open http://localhost:5174
```

This starts both the Vite frontend (port 5174) and the Node API server (port 3001)
with a single command. Use the same `GENSEE_HOME` for hooks, `watch`, `run`,
`timeline`, and the dashboard when you want all signals to appear together.

## Requirements

- Node 18 or newer.
- A built `gensee` binary for policy validation.
- Optional: `sqlite3` on `PATH` for demo-store fallback reads.

The API server at port 3001 exposes versioned endpoints under `/api/v1/` such
as `GET /api/v1/sessions`, `GET /api/v1/alerts`, and `GET`/`POST /api/v1/policy`.
It binds to loopback only (`127.0.0.1`) and is proxied by Vite during development.

## Demo Data

A fresh store is empty. Seed a demo store to populate the Timeline, Lineage,
and Policy views by running agent sessions with `gensee-sudo run -- <agent>`,
or point `GENSEE_HOME` at an existing store that already has data.

```bash
# Example: run a quick Claude session to generate events
GENSEE_HOME=~/.gensee gensee-sudo run -- claude

# Then open the dashboard
cd dashboards && GENSEE_HOME=~/.gensee npm run dev:full
```

## Live Policy Editing

The Policy page reads and writes `$GENSEE_HOME/policy.json` through the local
`/api/v1/policy` endpoint. Saves are validated by the policy engine before the
file is written. The Settings, Decision Rules, and Artifact Definitions tabs
provide structured editing; the Advanced (JSON) tab gives full raw access.

## Development

Run frontend and API server together:

```bash
cd dashboards && GENSEE_HOME=~/.gensee npm run dev:full
```

Or start them separately:

```bash
# Terminal 1 — API server
cd dashboards && GENSEE_HOME=~/.gensee npm run dev:server

# Terminal 2 — Vite frontend
cd dashboards && npm run dev
```

Use a separate store while developing:

```bash
cd dashboards && GENSEE_HOME=/tmp/gensee-fixture npm run dev:full
```

Type-check the frontend:

```bash
npm --prefix dashboards run build   # full TypeScript + Vite build check
```

## Rendering Safety

Prompts, commands, file paths, tool names, policy reasons, and artifact URIs are
attacker-influenced input. Keep dynamic rendering on safe text APIs such as
React's JSX text nodes or `textContent`. Do not pass live Gensee values through
`innerHTML`, even inside the security console itself.
