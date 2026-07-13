import { query, escStr, clampLimit } from './db.mjs';

const VALID_SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);
const VALID_ACTIONS    = new Set(['allow', 'warn', 'ask', 'block']);

/**
 * GET /api/v1/alerts
 */
export async function handleAlerts(params) {
  const limit  = clampLimit(params.limit, 500);
  const offset = Math.max(parseInt(params.offset ?? '0', 10) || 0, 0);

  const conditions = [];
  if (params.severity && VALID_SEVERITIES.has(params.severity)) {
    conditions.push(`severity = '${params.severity}'`);
  }
  if (params.action && VALID_ACTIONS.has(params.action)) {
    conditions.push(`action = '${params.action}'`);
  }
  if (params.request_id) {
    const rid = parseInt(params.request_id, 10);
    if (Number.isFinite(rid)) conditions.push(`request_id = ${rid}`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  return query(`
    SELECT alert_id, request_id, entity_kind, entity_id, severity, action,
           rule_id, message, path, created_at,
           json_extract(evidence, '$.tool_use_id') AS tool_use_id
    FROM alerts
    ${where}
    ORDER BY created_at DESC
    LIMIT ${limit} OFFSET ${offset}
  `);
}
