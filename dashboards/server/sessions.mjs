import { query, escStr, clampLimit } from './db.mjs';

/**
 * GET /api/v1/sessions
 * GET /api/v1/sessions/:id
 * GET /api/v1/sessions/:id/requests
 */
export async function handleSessions(params, sessionId = null, sub = null) {
  if (sessionId && sub === 'requests') {
    const limit = clampLimit(params.limit, 200);
    return query(`
      SELECT * FROM requests
       WHERE session_id = '${escStr(sessionId)}'
       ORDER BY request_id DESC
       LIMIT ${limit}
    `);
  }

  if (sessionId) {
    return query(`
      SELECT * FROM sessions
       WHERE session_id = '${escStr(sessionId)}'
       LIMIT 1
    `).then(rows => rows[0] ?? null);
  }

  const limit      = clampLimit(params.limit, 500);
  const offset     = Math.max(parseInt(params.offset ?? '0', 10) || 0, 0);
  const hideEmpty  = params.hide_empty === 'true' || params.hide_empty === '1';

  // When hide_empty is set, exclude sessions that have no requests AND no agent events.
  // Use inline subqueries in WHERE (SQLite doesn't allow HAVING aliases without GROUP BY).
  const whereClause = hideEmpty
    ? `WHERE (
        SELECT COUNT(*) FROM requests r WHERE r.session_id = s.session_id
      ) > 0
      OR (
        SELECT COUNT(*) FROM agent_events ae
          JOIN requests r ON ae.request_id = r.request_id
         WHERE r.session_id = s.session_id
      ) > 0`
    : '';

  return query(`
    SELECT s.*,
      (SELECT COUNT(*) FROM requests r WHERE r.session_id = s.session_id) AS req_count,
      (SELECT COUNT(*) FROM agent_events ae
         JOIN requests r ON ae.request_id = r.request_id
        WHERE r.session_id = s.session_id) AS event_count
    FROM sessions s
    ${whereClause}
     ORDER BY first_event_at DESC
     LIMIT ${limit} OFFSET ${offset}
  `);
}
