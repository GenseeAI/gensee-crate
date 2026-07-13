/**
 * Gensee UI — versioned API server  (Node 18+, zero npm dependencies)
 *
 * All routes are under /api/v1/.
 * Bind address is loopback-only (127.0.0.1) — the dashboard exposes local
 * security telemetry that must not be reachable from the LAN.
 *
 * Usage:
 *   node server/index.mjs
 *   GENSEE_HOME=~/.local PORT=3001 node server/index.mjs
 */

import { createServer }  from 'node:http';
import { homedir }       from 'node:os';
import { join, resolve } from 'node:path';

import { handleState }       from './state.mjs';
import { handleSessions }    from './sessions.mjs';
import { handleAgentEvents, handleEventStream, handleSessionEvents } from './events.mjs';
import { handleAlerts }      from './alerts.mjs';
import { handleMetricsToday } from './metrics.mjs';
import { handleStats }       from './stats.mjs';
import { handleArtifacts }   from './artifacts.mjs';
import { handlePolicy }      from './policy.mjs';
import { handleFeedback }    from './feedback.mjs';
import { dbPath, genseeHome } from './db.mjs';

const PORT      = parseInt(process.env.PORT      ?? '3001', 10);
const BIND_HOST = '127.0.0.1';   // loopback only — never 0.0.0.0

// Allow the Vite dev server origin during development.
const ALLOWED_ORIGINS = new Set([
  `http://localhost:5174`,
  `http://127.0.0.1:5174`,
  `http://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`,
  // Tauri WebView origin (varies by platform / version).
  'tauri://localhost',
  'https://tauri.localhost',
]);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : null;
  return allowed ? {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Headers': 'Content-Type, X-Gensee-Dashboard',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  } : {};
}

function jsonResponse(res, data, status = 200, origin = '') {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    ...corsHeaders(origin),
  });
  res.end(JSON.stringify(data));
}

function errorResponse(res, message, status = 500, origin = '') {
  jsonResponse(res, { error: message }, status, origin);
}

async function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      try {
        resolve(raw ? JSON.parse(raw) : null);
      } catch {
        reject(new Error('Request body is not valid JSON.'));
      }
    });
    req.on('error', reject);
  });
}

/** Require the CSRF guard header on all non-GET, non-preflight requests. */
function csrfAllowed(req) {
  return Boolean(req.headers['x-gensee-dashboard']);
}

// ---------------------------------------------------------------------------
// Request handler
// ---------------------------------------------------------------------------

const server = createServer(async (req, res) => {
  const origin = req.headers.origin ?? '';
  const url    = new URL(req.url, `http://${req.headers.host ?? BIND_HOST}`);
  const path   = url.pathname;
  const method = req.method ?? 'GET';
  const params = Object.fromEntries(url.searchParams.entries());

  // CORS preflight.
  if (method === 'OPTIONS') {
    res.writeHead(204, corsHeaders(origin));
    res.end();
    return;
  }

  // CSRF guard for state-changing requests.
  if (method !== 'GET' && !csrfAllowed(req)) {
    errorResponse(res, 'Missing X-Gensee-Dashboard header.', 403, origin);
    return;
  }

  try {
    // ── GET /api/v1/state ──────────────────────────────────────────────────
    if (path === '/api/v1/state' && method === 'GET') {
      return jsonResponse(res, await handleState(), 200, origin);
    }

    // ── GET /api/v1/sessions ───────────────────────────────────────────────
    if (path === '/api/v1/sessions' && method === 'GET') {
      return jsonResponse(res, await handleSessions(params), 200, origin);
    }

    // ── GET /api/v1/sessions/:id ───────────────────────────────────────────
    const sessionMatch = path.match(/^\/api\/v1\/sessions\/([^/]+)$/);
    if (sessionMatch && method === 'GET') {
      const row = await handleSessions(params, decodeURIComponent(sessionMatch[1]));
      return row
        ? jsonResponse(res, row, 200, origin)
        : errorResponse(res, 'Session not found.', 404, origin);
    }

    // ── GET /api/v1/sessions/:id/requests ─────────────────────────────────
    const sessionReqMatch = path.match(/^\/api\/v1\/sessions\/([^/]+)\/requests$/);
    if (sessionReqMatch && method === 'GET') {
      return jsonResponse(
        res,
        await handleSessions(params, decodeURIComponent(sessionReqMatch[1]), 'requests'),
        200,
        origin,
      );
    }

    // ── GET /api/v1/sessions/:id/events ───────────────────────────────────
    const sessionEventsMatch = path.match(/^\/api\/v1\/sessions\/([^/]+)\/events$/);
    if (sessionEventsMatch && method === 'GET') {
      return jsonResponse(
        res,
        await handleSessionEvents(decodeURIComponent(sessionEventsMatch[1])),
        200,
        origin,
      );
    }

    // ── GET /api/v1/events/agent ───────────────────────────────────────────
    if (path === '/api/v1/events/agent' && method === 'GET') {
      return jsonResponse(res, await handleAgentEvents(params), 200, origin);
    }

    // ── GET /api/v1/events/stream  (SSE) ──────────────────────────────────
    if (path === '/api/v1/events/stream' && method === 'GET') {
      // SSE manages its own response lifecycle.
      handleEventStream(req, res);
      return;
    }

    // ── GET /api/v1/alerts ─────────────────────────────────────────────────
if (path === '/api/v1/alerts' && method === 'GET') {
      return jsonResponse(res, await handleAlerts(params), 200, origin);
    }
    // ── GET /api/v1/metrics/today ───────────────────────────────────────────
if (path === '/api/v1/metrics/today' && method === 'GET') {
      return jsonResponse(res, await handleMetricsToday(params), 200, origin);
    }
    // ── GET /api/v1/stats/activity  &  /api/v1/stats/severity ──────────
    const statsMatch = path.match(/^\/api\/v1\/stats\/([a-z]+)$/);
    if (statsMatch && method === 'GET') {
      const result = await handleStats(statsMatch[1], params);
      if (result !== null) return jsonResponse(res, result, 200, origin);
    }
    // ── GET /api/v1/artifacts ──────────────────────────────────────────────
    if (path === '/api/v1/artifacts' && method === 'GET') {
      return jsonResponse(res, await handleArtifacts(params), 200, origin);
    }

    // ── GET /api/v1/artifacts/graph ───────────────────────────────────────
    if (path === '/api/v1/artifacts/graph' && method === 'GET') {
      return jsonResponse(res, await handleArtifacts(params, 'graph'), 200, origin);
    }

    // ── GET /api/v1/artifacts/:id/lineage ─────────────────────────────────
    const lineageMatch = path.match(/^\/api\/v1\/artifacts\/(\d+)\/lineage$/);
    if (lineageMatch && method === 'GET') {
      return jsonResponse(
        res,
        await handleArtifacts(params, Number(lineageMatch[1])),
        200,
        origin,
      );
    }

    // ── GET|POST /api/v1/policy ────────────────────────────────────────────
    if (path === '/api/v1/policy') {
      if (method === 'GET') {
        return jsonResponse(res, await handlePolicy('get'), 200, origin);
      }
      if (method === 'POST') {
        const body = await readJsonBody(req);
        return jsonResponse(res, await handlePolicy('set', body), 200, origin);
      }
    }

    // ── GET|POST /api/v1/feedback ──────────────────────────────────────────
    if (path === '/api/v1/feedback') {
      if (method === 'GET') {
        return jsonResponse(res, await handleFeedback(params), 200, origin);
      }
      if (method === 'POST') {
        const body = await readJsonBody(req);
        return jsonResponse(res, await handleFeedback(params, body), 200, origin);
      }
    }

    errorResponse(res, `Not found: ${method} ${path}`, 404, origin);
  } catch (err) {
    console.error(`[api] ${method} ${path} —`, err.message);
    errorResponse(res, err.message ?? 'Internal server error.', 500, origin);
  }
});

server.listen(PORT, BIND_HOST, () => {
  console.log(`[gensee-api] v1 listening on http://${BIND_HOST}:${PORT}`);
  console.log(`[gensee-api] GENSEE_HOME : ${genseeHome}`);
  console.log(`[gensee-api] database    : ${dbPath}`);
});
