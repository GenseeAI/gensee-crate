# Gensee Crate dashboard

This package contains the Gensee Crate local security dashboard.

## Current status

The local dev server exposes `GET /api/state`, which reads the local Gensee
store from `GENSEE_HOME` or `~/.gensee` by default. It prefers
`gensee dashboard-state`, which can read encrypted local telemetry, and falls
back to raw `sqlite3`/JSONL reads for unencrypted demo or development stores.

The dashboard reads local telemetry and can edit the live policy document via
the dev server's `/api/policy` endpoint. Review decisions are persisted through
the local feedback API. Some legacy quick controls, such as rule toggles and
allowlist prefixes, remain cosmetic browser state until they are wired to the
policy document.

Prompts, commands, file paths, tool names, policy reasons, and artifact URIs
are attacker-influenced input. Keep dynamic rendering on safe text APIs such as
`textContent` or framework escaping. Do not pass live shield values through
`innerHTML`, even in the security console itself.

## Local development

```bash
npm run dev
```

The dev server is a tiny dependency-free Node server at
`scripts/dev-server.mjs`. It serves `src/` on port `5173` by default.

## Requirements

- **Node 18+** (the dashboard's data comes from the dev server's `/api/state`
  and `/api/policy` endpoints — there is no Node-free path to a working UI).
- A built `gensee` binary (`cargo build --release`) for encrypted telemetry,
  live policy view/edit, and policy validation.
- Optional: `sqlite3` on `PATH` (or `/usr/bin/sqlite3`) for unencrypted demo
  store fallback reads.

## Demo data

A fresh store is empty. To populate every view (Live / Timeline / Lineage /
Policy) with example data:

```bash
# seed only:
dashboards/web/scripts/seed-demo.sh

# seed + serve in one command:
dashboards/web/scripts/demo.sh
# then open http://localhost:5173
```

Both default to `GENSEE_HOME=~/.gensee-demo`; override `GENSEE_HOME` / `GENSEE_BIN`
to point elsewhere. The dashboard must be launched against the **same**
`GENSEE_HOME` that was seeded.

`seed-demo.sh` wipes `GENSEE_HOME` before seeding. To avoid clobbering a real
store, it refuses to delete a directory it didn't create (it marks demo stores
with a `.gensee-demo-seed` file). Pass `--force` to overwrite anyway:

```bash
dashboards/web/scripts/demo.sh --force
```

## Live policy view/edit

The **Policy document** panel reads and writes the live policy
(`$GENSEE_HOME/policy.json`) via `GET`/`POST /api/policy`; saves require a custom
`X-Gensee-Dashboard` header (CSRF) and are fully validated by the engine before
writing. The legacy rule toggles and allowlist-prefix controls are still
`localStorage`-only (cosmetic) and not yet wired to the document.

```bash
PORT=4173 npm run dev
```

Use a separate store while developing:

```bash
GENSEE_HOME=/tmp/gensee-dashboard-fixture PORT=4173 npm run dev
```

## Checks

```bash
npm run check
```

The check script validates JavaScript syntax for the static UI controller and
the local dev server.
