import { query, queryOne } from '../../db.mjs';

const TODAY_AE      = "date(ae.ts/1000,'unixepoch','localtime') = date('now','localtime')";
const TODAY_SESS    = "date(first_event_at/1000,'unixepoch','localtime') = date('now','localtime')";
const TODAY_ALERTS  = "date(created_at/1000,'unixepoch','localtime')    = date('now','localtime')";

/**
 * GET /api/v1/metrics/today
 * All counts are scoped to the specified calendar day (local time).
 * Accepts optional ?date=YYYY-MM-DD param; defaults to today.
 */
export async function handleMetricsToday(params = {}) {
  // Validate date param — must be YYYY-MM-DD or absent
  const rawDate   = typeof params.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(params.date)
    ? params.date
    : null;
  const dateLiteral = rawDate ? `'${rawDate}'` : `date('now','localtime')`;

  const TODAY_AE_F    = `date(ae.ts/1000,'unixepoch','localtime') = ${dateLiteral}`;
  const TODAY_SESS_F  = `date(first_event_at/1000,'unixepoch','localtime') = ${dateLiteral}`;
  const TODAY_ALERT_F = `date(created_at/1000,'unixepoch','localtime') = ${dateLiteral}`;
  const [    toolCounts,
    sessionsRow,
    requestsRow,
    writtenRow,
    readRow,
    alertsByAction,
    alertsBySeverity,
  ] = await Promise.all([
    // Tool call counts by tool_name (PreToolUse only — no double-counting with Post)
    query(`
      SELECT ae.tool_name, COUNT(*) AS count
        FROM agent_events ae
       WHERE ae.type = 'PreToolUse' AND ${TODAY_AE_F}
         AND ae.tool_name IS NOT NULL
       GROUP BY ae.tool_name
       ORDER BY count DESC
       LIMIT 20
    `),

    // Sessions started on this day (exclude system-monitor pseudo-sessions)
    queryOne(`
      SELECT COUNT(*) AS count FROM sessions
       WHERE ${TODAY_SESS_F} AND agent_id != 'system-monitor'
    `),

    // Distinct request_ids touched on this day
    queryOne(`
      SELECT COUNT(DISTINCT ae.request_id) AS count
        FROM agent_events ae
       WHERE ${TODAY_AE_F}
    `),

    // Unique file paths written/edited
    queryOne(`
      SELECT COUNT(DISTINCT json_extract(ae.tool_input,'$.path')) AS count
        FROM agent_events ae
       WHERE ae.type = 'PreToolUse'
         AND ae.tool_name IN ('Write','Edit','MultiEdit','apply_patch')
         AND ${TODAY_AE_F}
         AND json_extract(ae.tool_input,'$.path') IS NOT NULL
    `),

    // Unique file paths read
    queryOne(`
      SELECT COUNT(DISTINCT json_extract(ae.tool_input,'$.path')) AS count
        FROM agent_events ae
       WHERE ae.type = 'PreToolUse'
         AND ae.tool_name = 'Read'
         AND ${TODAY_AE_F}
         AND json_extract(ae.tool_input,'$.path') IS NOT NULL
    `),

    // Alerts by action
    query(`
      SELECT action, COUNT(*) AS count FROM alerts
       WHERE ${TODAY_ALERT_F}
       GROUP BY action
    `),

    // Alerts by severity
    query(`
      SELECT severity, COUNT(*) AS count FROM alerts
       WHERE ${TODAY_ALERT_F}
       GROUP BY severity
    `),
  ]);

  const byAction   = Object.fromEntries(alertsByAction.map(r  => [r.action,   r.count]));
  const bySeverity = Object.fromEntries(alertsBySeverity.map(r => [r.severity, r.count]));

  return {
    sessions:       sessionsRow?.count  ?? 0,
    requests:       requestsRow?.count  ?? 0,
    tool_calls:     toolCounts.reduce((s, r) => s + r.count, 0),
    files_written:  writtenRow?.count   ?? 0,
    files_read:     readRow?.count      ?? 0,
    web_searches:   toolCounts.find(r => r.tool_name === 'WebSearch')?.count  ?? 0,
    web_fetches:    toolCounts.find(r => r.tool_name === 'WebFetch')?.count   ?? 0,
    bash_commands:  toolCounts.find(r => r.tool_name === 'Bash')?.count       ?? 0,
    alerts_by_action:   byAction,
    alerts_by_severity: bySeverity,
    top_tools:      toolCounts,
  };
}
