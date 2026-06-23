#!/usr/bin/env bash
#
# One command: seed a demo store, then serve the dashboard against it.
# Requires Node 18+ and a built gensee binary (cargo build --release).
#
#   dashboards/web/scripts/demo.sh
#   dashboards/web/scripts/demo.sh --force
#   open http://localhost:5173
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export GENSEE_HOME="${GENSEE_HOME:-$HOME/.gensee-demo}"

seed_args=()
for arg in "$@"; do
  case "$arg" in
    --force)
      seed_args+=("$arg")
      ;;
    -h|--help)
      echo "Usage: [GENSEE_HOME=...] [GENSEE_BIN=...] $0 [--force]" >&2
      echo "  --force  overwrite GENSEE_HOME even if it is not a prior demo store" >&2
      exit 0
      ;;
    *)
      echo "error: unknown argument '$arg' (try --help)" >&2
      exit 2
      ;;
  esac
done

"$here/seed-demo.sh" "${seed_args[@]}"

echo "Starting dashboard (Ctrl-C to stop)…"
exec node "$here/dev-server.mjs"
