import { query } from '../../db.mjs';

/**
 * GET /api/v1/stats/activity?range=24h|7d
 * Returns bucketed counts for sessions, agent_events, and alerts.
 *
 * GET /api/v1/stats/severity
 * Returns alert counts grouped by severity.
 */
export async function handleStats(sub, params) {
  if (sub === 'activity') return handleActivity(params);
  if (sub === 'severity') return handleSeverity();
  return null;
}

async function handleActivity(params) {
  const is7d     = params.range === '7d';
  const bucketMs = is7d ? 86_400_000 : 3_600_000;   // day : hour
  const rangeMs  = is7d ? 7 * 86_400_000 : 86_400_000;
  const fromMs   = Date.now() - rangeMs;

  const bucket = `(CAST(ts_col / ${bucketMs} AS INTEGER)) * ${bucketMs}`;

  // Run all three metric queries in parallel.
  const [sessions, agentEvents, alerts] = await Promise.all([
    query(`
      SELECT (CAST(first_event_at / ${bucketMs} AS INTEGER)) * ${bucketMs} AS bucket,
             COUNT(*) AS count
        FROM sessions
       WHERE first_event_at >= ${fromMs}
       GROUP BY bucket
       ORDER BY bucket
    `),
    query(`
      SELECT (CAST(ts / ${bucketMs} AS INTEGER)) * ${bucketMs} AS bucket,
             COUNT(*) AS count
        FROM agent_events
       WHERE ts >= ${fromMs}
       GROUP BY bucket
       ORDER BY bucket
    `),
    query(`
      SELECT (CAST(created_at / ${bucketMs} AS INTEGER)) * ${bucketMs} AS bucket,
             COUNT(*) AS count
        FROM alerts
       WHERE created_at >= ${fromMs}
       GROUP BY bucket
       ORDER BY bucket
    `),
  ]);

  return { range: is7d ? '7d' : '24h', bucketMs, sessions, agentEvents, alerts };
}

async function handleSeverity() {
  return query(`
    SELECT severity, COUNT(*) AS count
      FROM alerts
     GROUP BY severity
     ORDER BY CASE severity
       WHEN 'critical' THEN 5 WHEN 'high' THEN 4
       WHEN 'medium' THEN 3   WHEN 'low'  THEN 2
       ELSE 1
     END DESC
  `);
}
