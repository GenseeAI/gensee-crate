# Dashboard

The Gensee Crate dashboard is a local browser console for inspecting the same
`GENSEE_HOME` store used by `gensee watch`, agent hooks, `gensee run`, and
`gensee timeline`.

Use it when you want to see live agent activity, policy decisions, alerts, file
and request lineage, review verdicts, and the active policy document in one
place.

## Launch

Build the CLI first so the dashboard can read encrypted telemetry, validate
policy edits, and use the local dashboard-state command:

```bash
cargo build --release -p gensee-crate-cli
```

Then start the dashboard against the store you want to inspect:

```bash
GENSEE_HOME="$PWD/.gensee-dev" npm --prefix dashboards/web run dev
# open http://localhost:5173
```

Use the same `GENSEE_HOME` for hooks, `watch`, `run`, `timeline`, and the
dashboard when you want all signals to appear together.

## Requirements

- Node 18 or newer.
- A built `gensee` binary for encrypted telemetry, live policy view/edit, and
  policy validation.
- Optional: `sqlite3` on `PATH` for unencrypted demo-store fallback reads.

The dashboard dev server exposes local API endpoints such as `GET /api/state`
and `GET`/`POST /api/policy`. It prefers `gensee dashboard-state`, which can
read encrypted local telemetry, and falls back to raw `sqlite3`/JSONL reads for
unencrypted demo or development stores.

## Demo Data

A fresh store is empty. Seed a demo store to populate the Live, Timeline,
Lineage, and Policy views:

```bash
# seed only:
dashboards/web/scripts/seed-demo.sh

# seed + serve:
dashboards/web/scripts/demo.sh
# then open http://localhost:5173
```

Both commands default to `GENSEE_HOME=~/.gensee-demo`. Override `GENSEE_HOME` or
`GENSEE_BIN` to point at a different store or binary.

`seed-demo.sh` wipes the target `GENSEE_HOME` before seeding. To avoid deleting
a real store by accident, it refuses to delete a directory it did not create.
It marks demo stores with `.gensee-demo-seed`; pass `--force` only when you
intend to overwrite the target:

```bash
dashboards/web/scripts/demo.sh --force
```

## Live Policy Editing

The Policy document panel reads and writes `$GENSEE_HOME/policy.json` through
the local `/api/policy` endpoint. Saves require the dashboard's CSRF header and
are validated by the policy engine before the file is written.

Legacy quick controls, such as rule toggles and allowlist prefixes, remain
cosmetic browser state until they are wired to the policy document. Use the
Policy document panel or [`gensee policy`](gensee-policy.md) for changes that
must affect enforcement.

## Development

Run the dashboard package directly when working on the UI:

```bash
npm --prefix dashboards/web run dev
```

Use a separate store while developing:

```bash
GENSEE_HOME=/tmp/gensee-dashboard-fixture PORT=4173 npm --prefix dashboards/web run dev
```

Validate the dashboard JavaScript and local dev server:

```bash
npm --prefix dashboards/web run check
```

## Rendering Safety

Prompts, commands, file paths, tool names, policy reasons, and artifact URIs are
attacker-influenced input. Keep dynamic rendering on safe text APIs such as
`textContent` or framework escaping. Do not pass live Gensee values through
`innerHTML`, even inside the security console itself.
