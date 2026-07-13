# Gensee Crate UI

React + TypeScript dashboard for the Gensee Crate security monitor.

## Requirements

- Node 18 or newer
- A built `gensee` CLI binary (for policy validation)
- Optional: `sqlite3` on `PATH`

## Quick start

```bash
# Install dependencies (once)
npm install

# Start frontend (port 5174) + API server (port 3001) together
GENSEE_HOME="$HOME/.gensee" npm run dev:full

# Open http://localhost:5174
```

## Scripts

| Command | Description |
|---|---|
| `npm run dev` | Vite dev server only (port 5174) |
| `npm run dev:server` | Node API server only (port 3001) |
| `npm run dev:full` | Both together via `concurrently` |
| `npm run build` | Production build into `dist/` |
| `npm run preview` | Preview the production build |

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `GENSEE_HOME` | `~/.gensee` | Path to the Gensee data directory containing `gensee.db` |
| `GENSEE_DB_PATH` | `$GENSEE_HOME/gensee.db` | Override the SQLite database path directly |
| `GENSEE_BIN` | auto-detected | Path to the `gensee` binary for policy validation |
| `PORT` | `3001` | API server port |

## Architecture

```
Vite (port 5174)         Node API server (port 3001)
   React + TypeScript  ──proxy /api/v1/──▶  server/index.mjs
   src/                                      server/routes/v1/
   src/pages/                                  sessions.mjs
   src/components/                             events.mjs
   src/layouts/                                alerts.mjs
   src/api/client.ts                           artifacts.mjs
   src/hooks/                                  policy.mjs
                                               feedback.mjs
                                               stats.mjs
```

The API server binds to `127.0.0.1` only (loopback). The Vite proxy forwards
`/api` requests to port 3001 during development.

## Policy editing

The Policy page loads `$GENSEE_HOME/policy.json` (or the bundled default if not
yet customised). Saving validates the document via the `gensee` binary then
writes `$GENSEE_HOME/policy.json`. The next hook or `gensee run` invocation
picks up the change automatically.
