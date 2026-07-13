/**
 * db.mjs — SQLite access layer for the gensee-ui API server.
 *
 * Uses the `sqlite3` CLI (same as the existing dev-server) so there are no
 * additional npm dependencies.  Set SQLITE3_BIN to override the binary path.
 *
 * For production-grade use, swap the execFile approach for `better-sqlite3`
 * (synchronous, parameterised queries, zero sub-process overhead).
 */

import { execFile }    from 'node:child_process';
import { promisify }   from 'node:util';
import { access }      from 'node:fs/promises';
import { homedir }     from 'node:os';
import { join, resolve } from 'node:path';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

export const genseeHome = resolve(
  process.env.GENSEE_HOME ?? join(homedir(), '.gensee'),
);

export const dbPath = resolve(
  process.env.GENSEE_DB_PATH ?? join(genseeHome, 'gensee.db'),
);

// ---------------------------------------------------------------------------
// Binary resolution
// ---------------------------------------------------------------------------

const CANDIDATES = [
  process.env.SQLITE3_BIN,
  'sqlite3',
  '/usr/bin/sqlite3',
  '/usr/local/bin/sqlite3',
  '/opt/homebrew/bin/sqlite3',
].filter(Boolean);

let resolvedBin = null;

async function getSqlite3() {
  if (resolvedBin) return resolvedBin;
  for (const candidate of CANDIDATES) {
    try {
      await execFileAsync(candidate, ['--version'], { timeout: 2_000 });
      resolvedBin = candidate;
      return resolvedBin;
    } catch {
      // try next
    }
  }
  throw new Error(
    'sqlite3 CLI not found. Install it (brew install sqlite3 / apt install sqlite3) ' +
    'or set SQLITE3_BIN to its path.',
  );
}

// ---------------------------------------------------------------------------
// Query helpers
// ---------------------------------------------------------------------------

/**
 * Run a read-only SQL query and return the rows as plain JS objects.
 * Uses sqlite3 -json mode; returns [] for empty result sets.
 */
export async function query(sql) {
  const bin = await getSqlite3();

  try {
    await access(dbPath);
  } catch {
    throw new Error(
      `Database not found at ${dbPath}. ` +
      'Set GENSEE_HOME or GENSEE_DB_PATH to the directory/file that contains gensee.db.',
    );
  }

  try {
    const { stdout } = await execFileAsync(
      bin,
      [dbPath, '-json', sql.trim()],
      { maxBuffer: 8 * 1024 * 1024 },
    );
    const trimmed = stdout.trim();
    return trimmed ? JSON.parse(trimmed) : [];
  } catch (err) {
    // execFile rejects with a non-zero exit when the query fails.
    const msg = err.stderr?.trim() || err.message;
    throw new Error(`SQL error: ${msg}`);
  }
}

/** Return the first row of a query, or null. */
export async function queryOne(sql) {
  const rows = await query(sql);
  return rows[0] ?? null;
}

// ---------------------------------------------------------------------------
// Safe escape helpers (no parameterised queries via CLI)
// ---------------------------------------------------------------------------

/** Escape a string value for use in a SQL literal. */
export function escStr(value) {
  return String(value).replace(/'/g, "''");
}

/** Parse and validate an integer query parameter. */
export function escInt(value, fallback) {
  const n = parseInt(value, 10);
  if (Number.isNaN(n)) {
    if (fallback !== undefined) return fallback;
    throw new Error(`Expected integer, got: ${value}`);
  }
  return n;
}

/** Clamp a LIMIT value between 1 and max. */
export function clampLimit(value, max = 500) {
  return Math.min(Math.max(escInt(value, 50), 1), max);
}
