-- Reproducible Transactions dashboard showcase.
-- Safe to run repeatedly: only rows with the reserved showcase identifiers below
-- are replaced. Load db/schema.sql before this fixture in a new database.

PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

DELETE FROM agent_events
WHERE event_id BETWEEN 91001 AND 91012;

DELETE FROM requests
WHERE request_id BETWEEN 9001 AND 9004;

DELETE FROM sessions
WHERE session_id IN (
  'checkout-reliability',
  'checkout-retry-guard',
  'checkout-load-shedding',
  'checkout-queue-redesign'
);

DELETE FROM transaction_events
WHERE operation_id LIKE 'txn-checkout-%';

INSERT INTO sessions (
  session_id, agent_id, first_event_at, last_event_at, flagged
) VALUES
  ('checkout-reliability', 'codex · checkout reliability source',
    (unixepoch('now', '-30 minutes') * 1000), NULL, 0),
  ('checkout-retry-guard', 'codex · retry guard fork',
    (unixepoch('now', '-25 minutes') * 1000), (unixepoch('now', '-14 minutes') * 1000), 0),
  ('checkout-load-shedding', 'codex · load shedding fork',
    (unixepoch('now', '-25 minutes') * 1000), (unixepoch('now', '-3 minutes') * 1000), 1),
  ('checkout-queue-redesign', 'codex · active queue redesign source',
    (unixepoch('now', '-25 minutes') * 1000), NULL, 0);

INSERT INTO requests (
  request_id, session_id, original_user_prompt, final_response, events,
  file_accessed_rate, network_rate
) VALUES
  (9001, 'checkout-reliability',
    'Reduce duplicate checkout charges without disrupting the incident workspace.',
    'Created isolated paths for a retry guard, load shedding, and a queue redesign.', '[]', 1.5, 0.0),
  (9002, 'checkout-retry-guard',
    'Add an idempotency guard around payment retries and validate the focused patch.',
    'Validated and merged the retry guard into the checkout reliability source.', '[]', 2.0, 0.0),
  (9003, 'checkout-load-shedding',
    'Prototype load shedding for payment-provider timeouts.',
    'The approach conflicted with the retry changes and was discarded.', '[]', 2.5, 0.0),
  (9004, 'checkout-queue-redesign',
    'Move payment retries behind a durable queue while preserving the original workspace.',
    'The queue redesign became the active transactional source.', '[]', 3.0, 0.0);

INSERT INTO agent_events (
  event_id, pid, request_id, ts, source, type, cwd, permission_mode,
  tool_name, tool_input, tool_response, tool_use_id
) VALUES
  (91001, 4100, 9001, (unixepoch('now', '-29 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/checkout-service', 'default', 'Read',
    '{"operation":"read","path":"src/payments/retry.rs"}', NULL, 'checkout-source-read'),
  (91002, 4100, 9001, (unixepoch('now', '-28 minutes') * 1000),
    'codex', 'PostToolUse', '/workspace/checkout-service', 'default', 'Read',
    '{"operation":"read","path":"src/payments/retry.rs"}',
    '{"duration_ms":42}', 'checkout-source-read'),
  (91003, 4201, 9002, (unixepoch('now', '-23 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/checkout-service', 'default', 'Bash',
    '{"command":"cargo test payment_idempotency"}', NULL, 'checkout-retry-test'),
  (91004, 4201, 9002, (unixepoch('now', '-22 minutes') * 1000),
    'codex', 'PostToolUse', '/workspace/checkout-service', 'default', 'Bash',
    '{"command":"cargo test payment_idempotency"}', '{"duration_ms":310}', 'checkout-retry-test'),
  (91005, 4202, 9003, (unixepoch('now', '-21 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/checkout-service', 'default', 'Bash',
    '{"command":"cargo test load_shedding"}', NULL, 'checkout-load-test'),
  (91006, 4202, 9003, (unixepoch('now', '-19 minutes') * 1000),
    'codex', 'PostToolUse', '/workspace/checkout-service', 'default', 'Bash',
    '{"command":"cargo test load_shedding"}',
    '{"duration_ms":120000,"stderr":"2 payment timeout cases failed"}', 'checkout-load-test'),
  (91007, 4203, 9004, (unixepoch('now', '-20 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/checkout-service', 'default', 'Edit',
    '{"operation":"edit","path":"src/payments/queue.rs"}', NULL, 'checkout-queue-edit'),
  (91008, 4203, 9004, (unixepoch('now', '-18 minutes') * 1000),
    'codex', 'PostToolUse', '/workspace/checkout-service', 'default', 'Edit',
    '{"operation":"edit","path":"src/payments/queue.rs"}',
    '{"duration_ms":84000}', 'checkout-queue-edit'),
  (91009, 4203, 9004, (unixepoch('now', '-12 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/checkout-service', 'default', 'Bash',
    '{"command":"cargo test --workspace"}', NULL, 'checkout-queue-tests'),
  (91010, 4203, 9004, (unixepoch('now', '-9 minutes') * 1000),
    'codex', 'PostToolUse', '/workspace/checkout-service', 'default', 'Bash',
    '{"command":"cargo test --workspace"}',
    '{"duration_ms":180000}', 'checkout-queue-tests');

INSERT INTO transaction_events (
  operation_id, environment_kind, operation, phase,
  source_run_id, target_run_id, parent_run_id, workspace,
  summary, error_kind, error_message, metadata, occurred_at
) VALUES
  ('txn-checkout-source', 'tclone', 'source', 'started',
    'checkout-reliability', NULL, NULL, '/workspace/checkout-service',
    'Preparing checkout reliability workspace', NULL, NULL,
    '{"status":"preparing","container_name":"gensee-checkout-reliability"}',
    (unixepoch('now', '-30 minutes') * 1000)),
  ('txn-checkout-source', 'tclone', 'source', 'succeeded',
    'checkout-reliability', NULL, NULL, '/workspace/checkout-service',
    'Checkout reliability source is ready', NULL, NULL,
    '{"status":"running","container_name":"gensee-checkout-reliability"}',
    (unixepoch('now', '-29 minutes', '-55 seconds') * 1000)),

  ('txn-checkout-forks', 'tclone', 'fork', 'started',
    'checkout-reliability', NULL, NULL, '/workspace/checkout-service',
    'Creating 3 isolated approaches for the checkout incident', NULL, NULL,
    '{"copies":3,"requested_name":"checkout-reliability-options"}',
    (unixepoch('now', '-25 minutes') * 1000)),
  ('txn-checkout-forks', 'tclone', 'fork', 'succeeded',
    'checkout-reliability', 'checkout-retry-guard', 'checkout-reliability', '/workspace/checkout-service',
    'Forked retry guard approach from checkout reliability', NULL, NULL,
    '{"copies":3,"copy_index":0,"container_name":"gensee-checkout-retry-guard"}',
    (unixepoch('now', '-24 minutes', '-58 seconds') * 1000)),
  ('txn-checkout-forks', 'tclone', 'fork', 'succeeded',
    'checkout-reliability', 'checkout-load-shedding', 'checkout-reliability', '/workspace/checkout-service',
    'Forked load shedding approach from checkout reliability', NULL, NULL,
    '{"copies":3,"copy_index":1,"container_name":"gensee-checkout-load-shedding"}',
    (unixepoch('now', '-24 minutes', '-57 seconds') * 1000)),
  ('txn-checkout-forks', 'tclone', 'fork', 'succeeded',
    'checkout-reliability', 'checkout-queue-redesign', 'checkout-reliability', '/workspace/checkout-service',
    'Forked queue redesign approach from checkout reliability', NULL, NULL,
    '{"copies":3,"copy_index":2,"container_name":"gensee-checkout-queue-redesign"}',
    (unixepoch('now', '-24 minutes', '-56 seconds') * 1000)),

  ('txn-checkout-retry-validation', 'tclone', 'merge', 'started',
    'checkout-retry-guard', 'checkout-reliability', 'checkout-reliability', '/workspace/checkout-service',
    'Validating retry guard merge into checkout reliability', NULL, NULL,
    '{"scope":"git","paths":[],"dry_run":true,"force":false}',
    (unixepoch('now', '-16 minutes') * 1000)),
  ('txn-checkout-retry-validation', 'tclone', 'merge', 'succeeded',
    'checkout-retry-guard', 'checkout-reliability', 'checkout-reliability', '/workspace/checkout-service',
    'Validated retry guard merge into checkout reliability', NULL, NULL,
    '{"scope":"git","paths":[],"dry_run":true,"force":false,"changed":4,"upserted":4,"deleted":0}',
    (unixepoch('now', '-15 minutes', '-58 seconds') * 1000)),

  ('txn-checkout-retry-merge', 'tclone', 'merge', 'started',
    'checkout-retry-guard', 'checkout-reliability', 'checkout-reliability', '/workspace/checkout-service',
    'Merging retry guard into checkout reliability', NULL, NULL,
    '{"scope":"git","paths":[],"dry_run":false,"force":false}',
    (unixepoch('now', '-15 minutes') * 1000)),
  ('txn-checkout-retry-merge', 'tclone', 'merge', 'succeeded',
    'checkout-retry-guard', 'checkout-reliability', 'checkout-reliability', '/workspace/checkout-service',
    'Merged retry guard into checkout reliability', NULL, NULL,
    '{"scope":"git","paths":[],"dry_run":false,"force":false,"changed":4,"upserted":4,"deleted":0}',
    (unixepoch('now', '-14 minutes', '-57 seconds') * 1000)),

  ('txn-checkout-load-shedding-merge', 'tclone', 'merge', 'started',
    'checkout-load-shedding', 'checkout-reliability', 'checkout-reliability', '/workspace/checkout-service',
    'Merging load shedding into checkout reliability', NULL, NULL,
    '{"scope":"filesystem","paths":[],"dry_run":false,"force":false}',
    (unixepoch('now', '-13 minutes') * 1000)),
  ('txn-checkout-load-shedding-merge', 'tclone', 'merge', 'failed',
    'checkout-load-shedding', 'checkout-reliability', 'checkout-reliability', '/workspace/checkout-service',
    'Load shedding merge into checkout reliability failed', 'invaliddata',
    'Filesystem merge has 2 conflicts: src/payments/retry.rs and Cargo.lock',
    '{"scope":"filesystem","paths":[],"dry_run":false,"force":false,"conflicts":2}',
    (unixepoch('now', '-12 minutes', '-58 seconds') * 1000)),

  ('txn-checkout-load-shedding-discard', 'tclone', 'discard', 'started',
    'checkout-load-shedding', NULL, 'checkout-reliability', '/workspace/checkout-service',
    'Discarding the conflicting load shedding approach', NULL, NULL, NULL,
    (unixepoch('now', '-11 minutes') * 1000)),
  ('txn-checkout-load-shedding-discard', 'tclone', 'discard', 'succeeded',
    'checkout-load-shedding', NULL, 'checkout-reliability', '/workspace/checkout-service',
    'Discarded the conflicting load shedding approach', NULL, NULL, NULL,
    (unixepoch('now', '-10 minutes', '-59 seconds') * 1000)),

  ('txn-checkout-queue-switch', 'tclone', 'switch', 'started',
    'checkout-queue-redesign', 'checkout-queue-redesign', 'checkout-reliability', '/workspace/checkout-service',
    'Switching active source to the queue redesign', NULL, NULL, NULL,
    (unixepoch('now', '-9 minutes') * 1000)),
  ('txn-checkout-queue-switch', 'tclone', 'switch', 'succeeded',
    'checkout-queue-redesign', 'checkout-queue-redesign', 'checkout-reliability', '/workspace/checkout-service',
    'Queue redesign became the active source', NULL, NULL, NULL,
    (unixepoch('now', '-8 minutes', '-59 seconds') * 1000)),

  ('txn-checkout-queue-keep', 'tclone', 'keep', 'started',
    'checkout-queue-redesign', NULL, 'checkout-reliability', '/workspace/checkout-service',
    'Exporting the queue redesign workspace for review', NULL, NULL,
    '{"destination":"/tmp/checkout-queue-review"}',
    (unixepoch('now', '-6 minutes') * 1000)),
  ('txn-checkout-queue-keep', 'tclone', 'keep', 'succeeded',
    'checkout-queue-redesign', NULL, 'checkout-reliability', '/workspace/checkout-service',
    'Exported the queue redesign workspace for review', NULL, NULL,
    '{"destination":"/tmp/checkout-queue-review"}',
    (unixepoch('now', '-5 minutes', '-58 seconds') * 1000)),

  ('txn-checkout-load-shedding-delete', 'tclone', 'delete', 'started',
    'checkout-load-shedding', NULL, 'checkout-reliability', '/workspace/checkout-service',
    'Deleting the discarded load shedding environment', NULL, NULL, NULL,
    (unixepoch('now', '-4 minutes') * 1000)),
  ('txn-checkout-load-shedding-delete', 'tclone', 'delete', 'succeeded',
    'checkout-load-shedding', NULL, 'checkout-reliability', '/workspace/checkout-service',
    'Deleted load shedding environment; transaction history retained', NULL, NULL,
    '{"container":"removed","history_retained":true}',
    (unixepoch('now', '-3 minutes', '-59 seconds') * 1000));

COMMIT;
