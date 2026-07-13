import { query, escStr, escInt, clampLimit } from '../../db.mjs';

/** * GET /api/v1/sessions/:id/events
 *
 * Returns system_events for a session (joined through requests), sorted by ts.
 * Used by the Timeline page for sidecar-watch and system-monitor sessions that
 * have file-change effects but no agent-prompt requests.
 */
export async function handleSessionEvents(sessionId) {
  const sid = escStr(sessionId);
  // Extract the file path from the nested eslogger JSON (args) using SQLite
  // json_extract. Each event type stores its path under a different key.
  // cwd is populated for workspace-effect events; args.event.*.path for eslogger.
  return query(`
    SELECT
      se.event_id,
      se.pid,
      se.request_id,
      se.ts,
      se.source,
      se.type,
      se.cwd,
      COALESCE(
        CASE WHEN se.cwd != '' THEN se.cwd END,
        json_extract(se.args, '$.event.write.target.path'),
        json_extract(se.args, '$.event.create.destination.path'),
        json_extract(se.args, '$.event.rename.destination.path'),
        json_extract(se.args, '$.event.unlink.target.path'),
        json_extract(se.args, '$.event.exec.target.path'),
        json_extract(se.args, '$.event.open.file.path')
      ) AS path,
      json_extract(se.args, '$.process.executable.path') AS process
      FROM system_events se
      JOIN requests r ON se.request_id = r.request_id
     WHERE r.session_id = '${sid}'
     ORDER BY se.ts DESC
     LIMIT 200
  `);
}

/** * GET  /api/v1/events/agent   — paginated agent_events
 * GET  /api/v1/events/stream  — SSE live stream (handled separately in index.mjs)
 */
export async function handleAgentEvents(params) {
  const limit  = clampLimit(params.limit, 500);
  const offset = Math.max(parseInt(params.offset ?? '0', 10) || 0, 0);

  let where = '';
  if (params.request_id) {
    where = `WHERE request_id = ${escInt(params.request_id)}`;
  }

  return query(`
    SELECT * FROM agent_events
    ${where}
    ORDER BY ts DESC
    LIMIT ${limit} OFFSET ${offset}
  `);
}

/**
 * Start an SSE response that polls agent_events for new rows every second.
 * The client (useRealtime hook) receives newline-delimited "data: {...}\n\n"
 * frames compatible with the EventSource API.
 *
 * NOTE: This is a polling-based approximation. For true push, replace with
 * a SQLite update_hook via better-sqlite3 or a message-queue approach.
 */
export function handleEventStream(req, res) {
  res.writeHead(200, {
    'Content-Type':  'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection':    'keep-alive',
    // Restrict to same loopback origin — CORS handled by the main server.
  });

  let lastId = 0;
  let closed = false;

  async function poll() {
    if (closed) return;
    try {
      const rows = await query(`
        SELECT * FROM agent_events
         WHERE event_id > ${lastId}
         ORDER BY event_id ASC
         LIMIT 50
      `);
      for (const row of rows) {
        if (closed) break;
        res.write(`data: ${JSON.stringify(row)}\n\n`);
        if (row.event_id > lastId) lastId = row.event_id;
      }
    } catch {
      // DB may not exist yet during startup — silently skip this tick.
    }
    if (!closed) setTimeout(poll, 1_000);
  }

  req.on('close', () => { closed = true; });
  poll();
}
