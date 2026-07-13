import { query, escStr, clampLimit } from '../../db.mjs';

const VALID_VERDICTS = new Set(['agree', 'allow', 'deny']);

/**
 * GET  /api/v1/feedback         — list feedback rows
 * POST /api/v1/feedback         — insert a new feedback row
 */
export async function handleFeedback(params, body = null) {
  if (body !== null) {
    return insertFeedback(body);
  }

  const limit  = clampLimit(params.limit, 500);
  const offset = Math.max(parseInt(params.offset ?? '0', 10) || 0, 0);

  return query(`
    SELECT * FROM human_feedback
     ORDER BY created_at DESC
     LIMIT ${limit} OFFSET ${offset}
  `);
}

async function insertFeedback(body) {
  const verdict = String(body.human_verdict ?? '');
  if (!VALID_VERDICTS.has(verdict)) {
    throw new Error(`human_verdict must be one of: ${[...VALID_VERDICTS].join(', ')}`);
  }

  // Derive label if not provided — same logic as the CLI.
  const genseeAction = body.gensee_action ?? null;
  let label = body.label ?? null;
  if (!label) {
    if (verdict === 'agree') {
      label = 'confirmed';
    } else if (verdict === 'allow' && ['deny', 'block', 'ask', 'warn'].includes(genseeAction)) {
      label = 'false_positive';
    } else if (verdict === 'deny' && ['allow', 'watch'].includes(genseeAction)) {
      label = 'false_negative';
    } else {
      label = 'override';
    }
  }

  const now = Date.now();

  const cols = {
    human_verdict: `'${escStr(verdict)}'`,
    label:         label ? `'${escStr(label)}'` : 'NULL',
    gensee_action: genseeAction ? `'${escStr(genseeAction)}'` : 'NULL',
    event_key:     body.event_key   ? `'${escStr(body.event_key)}'`   : 'NULL',
    tool_use_id:   body.tool_use_id ? `'${escStr(body.tool_use_id)}'` : 'NULL',
    session_id:    body.session_id  ? `'${escStr(body.session_id)}'`  : 'NULL',
    rule_id:       body.rule_id     ? `'${escStr(body.rule_id)}'`     : 'NULL',
    path:          body.path        ? `'${escStr(body.path)}'`        : 'NULL',
    note:          body.note        ? `'${escStr(body.note)}'`        : 'NULL',
    created_at:    now,
  };

  const keys   = Object.keys(cols).join(', ');
  const values = Object.values(cols).join(', ');

  // Use RETURNING so the ID comes from the same sqlite3 process that ran the INSERT.
  // last_insert_rowid() on a separate connection always returns 0.
  const rows = await query(`
    INSERT INTO human_feedback (${keys}) VALUES (${values})
    RETURNING feedback_id
  `);
  return { feedback_id: rows[0]?.feedback_id ?? null };
}
