import { query } from '../../db.mjs';

/**
 * GET /api/v1/state
 *
 * Returns aggregate counts for the dashboard stat cards.
 * All counts are computed in a single SQL statement to minimise round-trips.
 */
export async function handleState() {
  // unix_millis() is a user-defined function in newer SQLite builds, but
  // strftime is universally available.
  const rows = await query(`
    SELECT
      (SELECT count(*) FROM sessions)                                          AS sessions_count,
      (SELECT count(*) FROM requests)                                          AS requests_count,
      (SELECT count(*) FROM agent_events)                                      AS agent_events_count,
      (SELECT count(*) FROM system_events)                                     AS system_events_count,
      (SELECT count(*) FROM alerts)                                            AS alerts_count,
      (SELECT count(*) FROM alerts
        WHERE severity IN ('high', 'critical')
          AND created_at > (CAST(strftime('%s', 'now') AS INTEGER) * 1000 - 86400000)
      )                                                                        AS recent_high_alerts,
      (SELECT count(*) FROM artifacts)                                         AS artifacts_count
  `);

  return rows[0] ?? {
    sessions_count:      0,
    requests_count:      0,
    agent_events_count:  0,
    system_events_count: 0,
    alerts_count:        0,
    recent_high_alerts:  0,
    artifacts_count:     0,
  };
}
