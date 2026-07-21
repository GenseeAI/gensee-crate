# Gensee Crate UI

Native Tauri dashboard for the Gensee Crate security monitor. The React
frontend communicates with the Rust backend through process-local Tauri IPC;
the dashboard does not start an HTTP API server.

## Requirements

- Node 18 or newer
- Rust stable and the Tauri CLI (`cargo install tauri-cli --version "^2" --locked`)
- A built `gensee` CLI binary (for policy validation)
- Linux: WebKitGTK development packages (see the Tauri prerequisites below)

## Installer setup

The one-line Gensee installer can provision this dashboard source checkout and
its Tauri/frontend dependencies. In an interactive install, accept the native
dashboard prompt; for unattended installs use:

```bash
curl -fsSL https://raw.githubusercontent.com/GenseeAI/gensee-crate/main/scripts/install_oss.sh \
   | GENSEE_CONFIGURE_DASHBOARD=1 bash
```

Set `GENSEE_DASHBOARD_SOURCE_DIR` to choose the local source checkout location.
The installer requires Node.js 18+ and prints the resulting `cargo tauri dev`
launch command after setup.

## Quick start

```bash
# Install dependencies (once)
npm install

# Launch the native desktop application
GENSEE_HOME="$HOME/.gensee" cargo tauri dev
```

## Transactions showcase data

Create a dedicated plaintext development database with two real-world workflows:

- A checkout reliability incident forks retry-guard, load-shedding, and
  queue-redesign approaches, then exercises validated and conflicting merges,
  discard, switch, keep, and delete.
- A Stripe SDK upgrade follows PR #23's visible-fork workflow: policy guidance,
  approval, one async host-owned fork, status polling, duplicate prevention,
  right-hand tmux attachment, prompt handoff, preserved tooling, recursive-fork
  suppression, and structured `exec --json` follow-up. After that fork merges,
  the updated source fans out into webhook security, a conflicting ledger
  backfill, and a reconciliation redesign that becomes active.

```bash
GENSEE_SHOWCASE_HOME="$(cd .. && pwd)/.gensee-dev"
mkdir -p "$GENSEE_SHOWCASE_HOME"
sqlite3 "$GENSEE_SHOWCASE_HOME/gensee.db" < ../db/schema.sql
sqlite3 "$GENSEE_SHOWCASE_HOME/gensee.db" < showcase/transactions.sql
sqlite3 "$GENSEE_SHOWCASE_HOME/gensee.db" < showcase/visible-fork-workflow.sql
GENSEE_HOME="$GENSEE_SHOWCASE_HOME" cargo tauri dev
```

The fixtures use reserved `checkout-*` / `txn-checkout-*` and `billing-*` /
`txn-billing-*` identifiers. They are safe to rerun and replace only
their own rows. Both create matching Timeline sessions and tool events so run
links in Transactions have drill-down content. The database is deliberately
project-local and ignored by Git. Settings will identify it as plaintext because
it is synthetic development data, not production telemetry.

The visible-fork fixture also inserts five synthetic policy decisions for the
Alerts view: the initial fork suggestion, the source-command backstop, the
approved schedule, a prevented duplicate schedule, and a blocked source-to-child
`exec` redirected to `send`. They are unchained fixture rows; production alerts
are appended through the tamper-evident store path.

Use an absolute `GENSEE_HOME` as above: the Tauri development process may use a
different working directory from the shell that launched it, so a relative path
such as `../.gensee-dev` is not reliable at runtime.

## README screenshot showcase

For screenshots of the rest of the product, create a separate database and load
the non-transactional product tour by itself:

```bash
GENSEE_README_HOME="$(cd .. && pwd)/.gensee-dev/readme"
mkdir -p "$GENSEE_README_HOME"
sqlite3 "$GENSEE_README_HOME/gensee.db" < ../db/schema.sql
sqlite3 "$GENSEE_README_HOME/gensee.db" < showcase/product-tour.sql
GENSEE_HOME="$GENSEE_README_HOME" cargo tauri dev
```

This fixture tells connected, realistic stories rather than presenting random
sample rows:

- **Dashboard:** activity is distributed across the last 24 hours and all seven
  days, with a complete alert-severity donut and recent policy decisions.
- **Timeline:** a duplicate-payment incident, OAuth security hardening, and
  release readiness include sequential and parallel tools, durations, policy
  outcomes, blocked actions, and filesystem effects.
- **Today's Highlight:** current sessions cover file reads and edits, web
  research, test commands, and every policy action.
- **Lineage Graph:** six artifacts connect incident evidence and operational
  guidance to the payment fix, replay tests, release workflow, and protected
  production manifest.
- **Alerts, Sessions, and Feedback:** the same stories provide filterable risk
  decisions, flagged sessions, approvals, overrides, and a false negative.

The fixture never inserts transaction history and uses only reserved
`showcase-*` sessions and IDs from 9501 upward. It is safe to rerun. To capture
the **Live Feed**, open that page first and replay a short burst from another
terminal (the replay intentionally appends new rows each time):

```bash
sqlite3 "$GENSEE_README_HOME/gensee.db" < showcase/live-feed-replay.sql
```

To open the WebView developer tools while debugging the frontend, opt in
explicitly:

```bash
GENSEE_OPEN_DEVTOOLS=1 GENSEE_HOME="$HOME/.gensee" cargo tauri dev
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

Production builds enforce a restrictive Content Security Policy: bundled assets
and the Tauri IPC bridge are permitted, while arbitrary network connections,
external scripts, and JavaScript `eval` are not. The separate development CSP
permits Vite localhost/HMR assets only during `cargo tauri dev`.

Tauri's automatic CSP nonce injection is disabled only for `style-src` because
Ant Design and the chart library generate styles at runtime. The production CSP
therefore explicitly allows inline styles, while retaining strict script and
network restrictions.

## Local telemetry privacy

`$GENSEE_HOME/gensee.db` is sensitive local security telemetry. It can contain
agent prompts, file paths, tool names, policy findings, and bounded metadata for
WebSearch, WebFetch, and ToolSearch calls. Treat the Gensee home directory as
private user data and do not share the database without review.

The **Transactions** page reads append-only transactional environment events
from the same encrypted database. Its History view groups state-changing tclone
operations chronologically, while Dependencies shows which runs were forked and
which successful merges contributed changes to another run. Run identifiers
link to a session-filtered Timeline. New operations update Transactions live and
also appear under the **Transactional environment** category in Live Feed.

Discarding or deleting a tclone container does not erase its transaction
history. Stored failure details are bounded: Gensee records structured operation
metadata and short diagnostic messages, but not full patches, environment
variables, or unrestricted command output.

The store does not generically copy arbitrary non-file tool-input objects. Each
persisted tool-input JSON record is capped at 16 KiB; oversized inputs are
replaced by truncation metadata rather than partial content.

## Encrypted-store smoke test

Encryption at rest is enabled by default. The Tauri backend uses bundled
SQLCipher and reads `$GENSEE_HOME/gensee.key` before opening an encrypted
`gensee.db`; it does not silently fall back to an empty database when the key is
missing or invalid.

After generating at least one event with the default store, verify the native
dashboard against that same encrypted store:

```bash
# This should open real sessions, alerts, and Timeline data from the default
# encrypted store. Do not copy or print $GENSEE_HOME/gensee.key.
GENSEE_HOME="$HOME/.gensee" cargo tauri dev
```

If the key is unavailable or mismatched, startup fails with an explicit store
error rather than rendering empty panels.

The Settings page displays whether the active store is encrypted. Plaintext
stores show an action-required warning. Gensee intentionally does not attempt
an in-place SQLCipher conversion from the dashboard; use a tested migration to
a newly initialized encrypted `GENSEE_HOME` before replacing an active store.

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
The validated content is synced to a same-directory temporary file and atomically
renamed into place, so an interrupted save leaves the previous policy intact.
The next hook or `gensee run` invocation picks up the change automatically.
