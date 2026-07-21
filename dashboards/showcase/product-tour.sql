-- Non-transactional product tour for README screenshots.
--
-- The dataset follows three current engineering stories (a payment webhook
-- incident, OAuth hardening, and release readiness), plus a small amount of
-- prior-week activity so both Dashboard ranges have useful shapes. It does
-- not insert transaction_events or refer to transactional environments.
--
-- Load db/schema.sql first. This fixture is safe to run repeatedly and only
-- replaces rows in its reserved showcase ID ranges and showcase-* sessions.

PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

DELETE FROM artifact_risk_tags WHERE tag_id BETWEEN 99701 AND 99720;
DELETE FROM artifact_observations WHERE observation_id BETWEEN 99601 AND 99620;
DELETE FROM artifact_facts
WHERE current_artifact_id BETWEEN 98001 AND 98020
   OR uri IN (
     'file:///workspace/commerce-platform/docs/operations/payment-webhooks.md',
     'file:///workspace/commerce-platform/fixtures/stripe/replayed-events.json',
     'file:///workspace/commerce-platform/services/payments/src/webhook.rs',
     'file:///workspace/commerce-platform/services/payments/tests/webhook_replay_test.rs',
     'file:///workspace/commerce-platform/.github/workflows/release.yml',
     'file:///workspace/commerce-platform/deploy/production.yaml'
   );
DELETE FROM relations WHERE relation_id BETWEEN 99001 AND 99020;
DELETE FROM artifacts WHERE artifact_id BETWEEN 98001 AND 98020;
DELETE FROM human_feedback WHERE feedback_id BETWEEN 97501 AND 97520;
DELETE FROM alerts WHERE alert_id BETWEEN 97001 AND 97030;
DELETE FROM system_events WHERE event_id BETWEEN 96001 AND 96020;
DELETE FROM agent_events WHERE request_id BETWEEN 9501 AND 9520;
DELETE FROM agent_events WHERE event_id BETWEEN 95001 AND 95120;
DELETE FROM requests WHERE request_id BETWEEN 9501 AND 9520;
DELETE FROM sessions WHERE session_id LIKE 'showcase-%';

-- Current work appears first in Timeline; older sessions give the 7-day
-- activity chart a deliberate, non-random cadence.
INSERT INTO sessions (
  session_id, agent_id, first_event_at, last_event_at, flagged
) VALUES
  ('showcase-release-readiness', 'codex',
    (unixepoch('now', '-55 minutes') * 1000), (unixepoch('now', '-12 minutes') * 1000), 1),
  ('showcase-file-watch', 'sidecar-watch',
    (unixepoch('now', '-2 hours') * 1000), (unixepoch('now', '-1 hour', '-42 minutes') * 1000), 1),
  ('showcase-webhook-incident', 'claude-code',
    (unixepoch('now', '-3 hours') * 1000), (unixepoch('now', '-1 hour') * 1000), 1),
  ('showcase-oauth-hardening', 'codex',
    (unixepoch('now', '-7 hours') * 1000), (unixepoch('now', '-5 hours', '-35 minutes') * 1000), 0),
  ('showcase-query-optimization', 'claude-code',
    (unixepoch('now', '-1 day', '-3 hours') * 1000), (unixepoch('now', '-1 day', '-2 hours') * 1000), 0),
  ('showcase-accessibility-audit', 'codex',
    (unixepoch('now', '-2 days', '-4 hours') * 1000), (unixepoch('now', '-2 days', '-3 hours') * 1000), 0),
  ('showcase-dependency-review', 'claude-code',
    (unixepoch('now', '-3 days', '-2 hours') * 1000), (unixepoch('now', '-3 days', '-1 hour') * 1000), 1),
  ('showcase-docs-migration', 'codex',
    (unixepoch('now', '-4 days', '-5 hours') * 1000), (unixepoch('now', '-4 days', '-4 hours') * 1000), 0),
  ('showcase-flaky-test-investigation', 'claude-code',
    (unixepoch('now', '-5 days', '-3 hours') * 1000), (unixepoch('now', '-5 days', '-2 hours') * 1000), 0),
  ('showcase-audit-retention', 'codex',
    (unixepoch('now', '-6 days', '-4 hours') * 1000), (unixepoch('now', '-6 days', '-3 hours') * 1000), 0);

INSERT INTO requests (
  request_id, session_id, original_user_prompt, final_response, events,
  file_accessed_rate, network_rate
) VALUES
  (9501, 'showcase-webhook-incident',
    'Investigate the duplicate Stripe charges reported after this morning''s deploy. Correlate webhook delivery IDs with payment attempts and identify the safest fix.',
    'The retries reused delivery IDs but bypassed the in-memory deduplication window. I traced the failure to webhook.rs and proposed durable idempotency keyed by account and delivery ID.',
    '[]', 4.8, 1.7),
  (9502, 'showcase-webhook-incident',
    'Implement durable webhook idempotency, add a replay regression test, and run the billing suite.',
    'Added the durable claim before charge creation, covered concurrent replays, and passed 86 billing tests. The production secret remained protected throughout the investigation.',
    '[]', 6.1, 0.0),
  (9503, 'showcase-release-readiness',
    'Prepare commerce-platform v2.4.0 for release: review the diff, run focused and full test suites, update release notes, and verify the deployment workflow without publishing.',
    'Release candidate v2.4.0 is ready for human approval: 412 tests passed, release notes cover the webhook fix and OAuth hardening, and the deployment workflow was inspected but not executed.',
    '[]', 5.2, 0.4),
  (9504, 'showcase-oauth-hardening',
    'Audit the OAuth callback for state validation and PKCE downgrade risks, implement fixes, and cite the relevant standards in the security notes.',
    'Enforced exact state matching, rejected plain-code challenges, rotated callback nonces after use, and added seven security regression tests.',
    '[]', 5.6, 2.3),
  (9505, 'showcase-file-watch',
    'Observe filesystem effects while the payment incident remediation runs.',
    'Recorded four correlated writes and one unmatched attempt against the production environment file.',
    '[]', 2.0, 0.0),
  (9506, 'showcase-query-optimization',
    'Reduce checkout history endpoint latency without changing response semantics.',
    'Added a covering index and removed an N+1 query; p95 fell from 840 ms to 118 ms in the benchmark.',
    '[]', 3.2, 0.0),
  (9507, 'showcase-accessibility-audit',
    'Audit the checkout dialog for keyboard navigation and screen-reader regressions.',
    'Fixed focus restoration, labelled the payment error region, and added keyboard navigation tests.',
    '[]', 2.7, 0.8),
  (9508, 'showcase-dependency-review',
    'Review the proposed JWT dependency update for security and compatibility risks.',
    'Flagged a transitive crypto downgrade and recommended holding the update pending the patched release.',
    '[]', 2.4, 1.1),
  (9509, 'showcase-docs-migration',
    'Migrate the incident runbook to the new operations documentation structure.',
    'Moved the runbook, repaired internal links, and verified the generated documentation site.',
    '[]', 3.0, 0.0),
  (9510, 'showcase-flaky-test-investigation',
    'Find why the webhook concurrency test fails intermittently in CI.',
    'Replaced wall-clock sleeps with a barrier and reproduced 1,000 clean runs.',
    '[]', 3.8, 0.0),
  (9511, 'showcase-audit-retention',
    'Validate that security audit exports obey the 30-day retention policy.',
    'Confirmed lifecycle expiration and added a regression test for legal-hold exclusions.',
    '[]', 2.1, 0.3);

-- Payment incident: investigation calls overlap where independent evidence was
-- gathered in parallel. A blocked read intentionally has no PostToolUse row.
INSERT INTO agent_events (
  event_id, pid, request_id, ts, source, type, cwd, permission_mode,
  tool_name, tool_input, tool_response, tool_use_id
) VALUES
  (95001, 6101, 9501, (unixepoch('now', '-2 hours', '-58 minutes') * 1000),
    'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'WebSearch',
    '{"query":"Stripe webhook duplicate delivery id retry semantics"}', NULL, 'incident-search'),
  (95002, 6101, 9501, (unixepoch('now', '-2 hours', '-57 minutes', '-54 seconds') * 1000),
    'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'default', 'WebSearch',
    '{"query":"Stripe webhook duplicate delivery id retry semantics"}', '{"duration_ms":6120,"results":6}', 'incident-search'),
  (95003, 6101, 9501, (unixepoch('now', '-2 hours', '-57 minutes') * 1000),
    'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'WebFetch',
    '{"url":"https://docs.stripe.com/webhooks#handle-duplicate-events"}', NULL, 'incident-docs'),
  (95004, 6101, 9501, (unixepoch('now', '-2 hours', '-56 minutes', '-52 seconds') * 1000),
    'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'default', 'WebFetch',
    '{"url":"https://docs.stripe.com/webhooks#handle-duplicate-events"}', '{"duration_ms":8350,"status":200}', 'incident-docs'),
  (95005, 6101, 9501, (unixepoch('now', '-2 hours', '-54 minutes') * 1000),
    'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"services/payments/src/webhook.rs"}', NULL, 'incident-read-webhook'),
  (95006, 6101, 9501, (unixepoch('now', '-2 hours', '-53 minutes', '-55 seconds') * 1000),
    'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"services/payments/src/webhook.rs"}', '{"duration_ms":5210,"lines":284}', 'incident-read-webhook'),
  (95007, 6101, 9501, (unixepoch('now', '-2 hours', '-54 minutes') * 1000 + 900),
    'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"fixtures/stripe/replayed-events.json"}', NULL, 'incident-read-fixture'),
  (95008, 6101, 9501, (unixepoch('now', '-2 hours', '-53 minutes', '-54 seconds') * 1000),
    'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"fixtures/stripe/replayed-events.json"}', '{"duration_ms":6400,"records":18}', 'incident-read-fixture'),
  (95009, 6101, 9501, (unixepoch('now', '-2 hours', '-51 minutes') * 1000),
    'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"rg \"delivery_id|idempotency\" services/payments tests"}', NULL, 'incident-rg'),
  (95010, 6101, 9501, (unixepoch('now', '-2 hours', '-50 minutes', '-59 seconds') * 1000),
    'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"rg \"delivery_id|idempotency\" services/payments tests"}', '{"duration_ms":780,"matches":23}', 'incident-rg'),
  (95011, 6101, 9501, (unixepoch('now', '-2 hours', '-49 minutes') * 1000),
    'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":".env.production"}', '{"permissionDecision":"deny","reason":"Production credentials are not required for log correlation."}', 'incident-prod-env'),
  (95012, 6101, 9501, (unixepoch('now', '-2 hours', '-45 minutes') * 1000),
    'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"sqlite3 telemetry.db \"select delivery_id,count(*) from webhook_receipts group by 1 having count(*) > 1\""}', NULL, 'incident-query'),
  (95013, 6101, 9501, (unixepoch('now', '-2 hours', '-44 minutes', '-56 seconds') * 1000),
    'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"sqlite3 telemetry.db \"select delivery_id,count(*) from webhook_receipts group by 1 having count(*) > 1\""}', '{"duration_ms":4210,"rows":37}', 'incident-query'),

  (95014, 6102, 9502, (unixepoch('now', '-2 hours', '-5 minutes') * 1000),
    'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"services/payments/src/webhook.rs"}', NULL, 'remediation-read'),
  (95015, 6102, 9502, (unixepoch('now', '-2 hours', '-4 minutes', '-58 seconds') * 1000),
    'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"services/payments/src/webhook.rs"}', '{"duration_ms":2330,"lines":284}', 'remediation-read'),
  (95016, 6102, 9502, (unixepoch('now', '-2 hours', '-1 minute') * 1000),
    'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'acceptEdits', 'Edit',
    '{"path":"services/payments/src/webhook.rs","change":"Claim each account and delivery ID before charge creation"}', NULL, 'remediation-edit'),
  (95017, 6102, 9502, (unixepoch('now', '-1 hour', '-59 minutes', '-51 seconds') * 1000),
    'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'acceptEdits', 'Edit',
    '{"path":"services/payments/src/webhook.rs","change":"Claim each account and delivery ID before charge creation"}', '{"duration_ms":69400,"files_changed":1}', 'remediation-edit'),
  (95018, 6102, 9502, (unixepoch('now', '-1 hour', '-57 minutes') * 1000),
    'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'acceptEdits', 'Write',
    '{"path":"services/payments/tests/webhook_replay_test.rs"}', NULL, 'remediation-test-write'),
  (95019, 6102, 9502, (unixepoch('now', '-1 hour', '-55 minutes', '-48 seconds') * 1000),
    'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'acceptEdits', 'Write',
    '{"path":"services/payments/tests/webhook_replay_test.rs"}', '{"duration_ms":72100,"bytes":4912}', 'remediation-test-write'),
  (95020, 6102, 9502, (unixepoch('now', '-1 hour', '-52 minutes') * 1000),
    'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"cargo test -p payments webhook_replay -- --nocapture"}', NULL, 'remediation-focused-tests'),
  (95021, 6102, 9502, (unixepoch('now', '-1 hour', '-48 minutes') * 1000),
    'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"cargo test -p payments webhook_replay -- --nocapture"}', '{"duration_ms":240000,"stdout":"12 passed; 0 failed"}', 'remediation-focused-tests'),
  (95022, 6102, 9502, (unixepoch('now', '-1 hour', '-44 minutes') * 1000),
    'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"cargo test -p payments"}', NULL, 'remediation-suite'),
  (95023, 6102, 9502, (unixepoch('now', '-1 hour', '-37 minutes') * 1000),
    'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"cargo test -p payments"}', '{"duration_ms":420000,"stdout":"86 passed; 0 failed"}', 'remediation-suite'),

  -- Release readiness: parallel test commands make the request graph visually rich.
  (95024, 6201, 9503, (unixepoch('now', '-53 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"CHANGELOG.md"}', NULL, 'release-read-changelog'),
  (95025, 6201, 9503, (unixepoch('now', '-52 minutes', '-58 seconds') * 1000),
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"CHANGELOG.md"}', '{"duration_ms":2100,"lines":416}', 'release-read-changelog'),
  (95026, 6201, 9503, (unixepoch('now', '-50 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"git diff --stat v2.3.1...HEAD"}', NULL, 'release-diff'),
  (95027, 6201, 9503, (unixepoch('now', '-49 minutes', '-59 seconds') * 1000),
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"git diff --stat v2.3.1...HEAD"}', '{"duration_ms":920,"files":18,"insertions":624,"deletions":117}', 'release-diff'),
  (95028, 6201, 9503, (unixepoch('now', '-47 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"cargo test -p payments"}', NULL, 'release-payments-tests'),
  (95029, 6201, 9503, (unixepoch('now', '-47 minutes') * 1000 + 700),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"npm test --workspace apps/checkout"}', NULL, 'release-checkout-tests'),
  (95030, 6201, 9503, (unixepoch('now', '-42 minutes') * 1000),
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"npm test --workspace apps/checkout"}', '{"duration_ms":300000,"stdout":"214 passed; 0 failed"}', 'release-checkout-tests'),
  (95031, 6201, 9503, (unixepoch('now', '-40 minutes') * 1000),
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"cargo test -p payments"}', '{"duration_ms":420000,"stdout":"198 passed; 0 failed"}', 'release-payments-tests'),
  (95032, 6201, 9503, (unixepoch('now', '-35 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'acceptEdits', 'Edit',
    '{"path":"CHANGELOG.md","change":"Document webhook idempotency and OAuth callback hardening"}', NULL, 'release-notes'),
  (95033, 6201, 9503, (unixepoch('now', '-33 minutes', '-48 seconds') * 1000),
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'acceptEdits', 'Edit',
    '{"path":"CHANGELOG.md","change":"Document webhook idempotency and OAuth callback hardening"}', '{"duration_ms":72400,"files_changed":1}', 'release-notes'),
  (95034, 6201, 9503, (unixepoch('now', '-29 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":".github/workflows/release.yml"}', NULL, 'release-read-workflow'),
  (95035, 6201, 9503, (unixepoch('now', '-28 minutes', '-57 seconds') * 1000),
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":".github/workflows/release.yml"}', '{"duration_ms":3010,"lines":122}', 'release-read-workflow'),
  (95036, 6201, 9503, (unixepoch('now', '-22 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"gh workflow run release.yml -f version=v2.4.0"}',
    '{"permissionDecision":"deny","reason":"Publishing requires explicit human approval."}', 'release-publish'),

  -- OAuth security audit.
  (95037, 6301, 9504, (unixepoch('now', '-6 hours', '-58 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"services/identity/src/oauth/callback.rs"}', NULL, 'oauth-read-callback'),
  (95038, 6301, 9504, (unixepoch('now', '-6 hours', '-57 minutes', '-55 seconds') * 1000),
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"services/identity/src/oauth/callback.rs"}', '{"duration_ms":5040,"lines":318}', 'oauth-read-callback'),
  (95039, 6301, 9504, (unixepoch('now', '-6 hours', '-58 minutes') * 1000 + 800),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"services/identity/tests/oauth_callback_test.rs"}', NULL, 'oauth-read-tests'),
  (95040, 6301, 9504, (unixepoch('now', '-6 hours', '-57 minutes', '-53 seconds') * 1000),
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"services/identity/tests/oauth_callback_test.rs"}', '{"duration_ms":7100,"lines":205}', 'oauth-read-tests'),
  (95041, 6301, 9504, (unixepoch('now', '-6 hours', '-52 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'WebSearch',
    '{"query":"OAuth 2.1 PKCE downgrade state validation best practices"}', NULL, 'oauth-search'),
  (95042, 6301, 9504, (unixepoch('now', '-6 hours', '-51 minutes', '-54 seconds') * 1000),
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'WebSearch',
    '{"query":"OAuth 2.1 PKCE downgrade state validation best practices"}', '{"duration_ms":6200,"results":8}', 'oauth-search'),
  (95043, 6301, 9504, (unixepoch('now', '-6 hours', '-49 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'WebFetch',
    '{"url":"https://www.rfc-editor.org/rfc/rfc9700.html"}', NULL, 'oauth-rfc'),
  (95044, 6301, 9504, (unixepoch('now', '-6 hours', '-48 minutes', '-52 seconds') * 1000),
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'WebFetch',
    '{"url":"https://www.rfc-editor.org/rfc/rfc9700.html"}', '{"duration_ms":8400,"status":200}', 'oauth-rfc'),
  (95045, 6301, 9504, (unixepoch('now', '-6 hours', '-42 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'acceptEdits', 'MultiEdit',
    '{"path":"services/identity/src/oauth/callback.rs","change":"Require S256 PKCE and one-time callback state"}', NULL, 'oauth-fix'),
  (95046, 6301, 9504, (unixepoch('now', '-6 hours', '-38 minutes') * 1000),
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'acceptEdits', 'MultiEdit',
    '{"path":"services/identity/src/oauth/callback.rs","change":"Require S256 PKCE and one-time callback state"}', '{"duration_ms":240000,"files_changed":3}', 'oauth-fix'),
  (95047, 6301, 9504, (unixepoch('now', '-6 hours', '-32 minutes') * 1000),
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"cargo test -p identity oauth_callback"}', NULL, 'oauth-tests'),
  (95048, 6301, 9504, (unixepoch('now', '-6 hours', '-26 minutes') * 1000),
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"cargo test -p identity oauth_callback"}', '{"duration_ms":360000,"stdout":"7 passed; 0 failed"}', 'oauth-tests'),

  -- One compact request per prior day supplies readable 7-day chart points.
  (95049, 6401, 9506, (unixepoch('now', '-1 day', '-2 hours', '-58 minutes') * 1000), 'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash', '{"command":"cargo bench -p orders checkout_history"}', NULL, 'history-bench'),
  (95050, 6401, 9506, (unixepoch('now', '-1 day', '-2 hours', '-52 minutes') * 1000), 'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash', '{"command":"cargo bench -p orders checkout_history"}', '{"duration_ms":360000,"p95_ms":118}', 'history-bench'),
  (95051, 6402, 9507, (unixepoch('now', '-2 days', '-3 hours', '-58 minutes') * 1000), 'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash', '{"command":"npm run test:a11y --workspace apps/checkout"}', NULL, 'a11y-tests'),
  (95052, 6402, 9507, (unixepoch('now', '-2 days', '-3 hours', '-52 minutes') * 1000), 'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash', '{"command":"npm run test:a11y --workspace apps/checkout"}', '{"duration_ms":360000,"violations":0}', 'a11y-tests'),
  (95053, 6403, 9508, (unixepoch('now', '-3 days', '-1 hour', '-58 minutes') * 1000), 'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash', '{"command":"cargo tree -i vulnerable-jwt"}', NULL, 'dependency-tree'),
  (95054, 6403, 9508, (unixepoch('now', '-3 days', '-1 hour', '-57 minutes') * 1000), 'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash', '{"command":"cargo tree -i vulnerable-jwt"}', '{"duration_ms":5800,"affected_crates":4}', 'dependency-tree'),
  (95055, 6404, 9509, (unixepoch('now', '-4 days', '-4 hours', '-58 minutes') * 1000), 'codex', 'PreToolUse', '/workspace/commerce-platform', 'acceptEdits', 'MultiEdit', '{"path":"docs/operations/payment-webhooks.md"}', NULL, 'docs-move'),
  (95056, 6404, 9509, (unixepoch('now', '-4 days', '-4 hours', '-55 minutes') * 1000), 'codex', 'PostToolUse', '/workspace/commerce-platform', 'acceptEdits', 'MultiEdit', '{"path":"docs/operations/payment-webhooks.md"}', '{"duration_ms":180000,"links_repaired":14}', 'docs-move'),
  (95057, 6405, 9510, (unixepoch('now', '-5 days', '-2 hours', '-58 minutes') * 1000), 'claude-code', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash', '{"command":"cargo test -p payments webhook_concurrent -- --test-threads=1"}', NULL, 'flaky-tests'),
  (95058, 6405, 9510, (unixepoch('now', '-5 days', '-2 hours', '-42 minutes') * 1000), 'claude-code', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash', '{"command":"cargo test -p payments webhook_concurrent -- --test-threads=1"}', '{"duration_ms":960000,"runs":1000,"failures":0}', 'flaky-tests'),
  (95059, 6406, 9511, (unixepoch('now', '-6 days', '-3 hours', '-58 minutes') * 1000), 'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash', '{"command":"cargo test -p audit retention_policy"}', NULL, 'retention-tests'),
  (95060, 6406, 9511, (unixepoch('now', '-6 days', '-3 hours', '-52 minutes') * 1000), 'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash', '{"command":"cargo test -p audit retention_policy"}', '{"duration_ms":360000,"tests":24,"failures":0}', 'retention-tests');

INSERT INTO system_events (
  event_id, pid, request_id, ts, source, type, cwd, args
) VALUES
  (96001, 7210, 9505, (unixepoch('now', '-1 hour', '-58 minutes') * 1000), 'sidecar-watch', 'open', '/workspace/commerce-platform',
    '{"event":{"open":{"file":{"path":"/workspace/commerce-platform/services/payments/src/webhook.rs"}}},"process":{"executable":{"path":"/usr/bin/codex"}}}'),
  (96002, 7210, 9505, (unixepoch('now', '-1 hour', '-56 minutes') * 1000), 'sidecar-watch', 'write', '/workspace/commerce-platform',
    '{"event":{"write":{"target":{"path":"/workspace/commerce-platform/services/payments/src/webhook.rs"}}},"process":{"executable":{"path":"/usr/bin/codex"}}}'),
  (96003, 7210, 9505, (unixepoch('now', '-1 hour', '-53 minutes') * 1000), 'sidecar-watch', 'create', '/workspace/commerce-platform',
    '{"event":{"create":{"destination":{"path":"/workspace/commerce-platform/services/payments/tests/webhook_replay_test.rs"}}},"process":{"executable":{"path":"/usr/bin/codex"}}}'),
  (96004, 7255, 9505, (unixepoch('now', '-1 hour', '-47 minutes') * 1000), 'sidecar-watch', 'write', '/workspace/commerce-platform',
    '{"event":{"write":{"target":{"path":"/workspace/commerce-platform/target/test-results/payments.xml"}}},"process":{"executable":{"path":"/usr/bin/cargo"}}}'),
  (96005, 7299, 9505, (unixepoch('now', '-1 hour', '-43 minutes') * 1000), 'sidecar-watch', 'open', '/workspace/commerce-platform',
    '{"event":{"open":{"file":{"path":"/workspace/commerce-platform/.env.production"}}},"process":{"executable":{"path":"/usr/bin/python3"}}}');

-- Synthetic policy decisions are intentionally unchained fixture rows. A
-- running store appends real alerts through the tamper-evident hash chain.
INSERT INTO alerts (
  alert_id, request_id, entity_kind, entity_id, severity, action,
  rule_id, message, path, evidence, created_at
) VALUES
  (97001, 9503, 'agent_event', 95036, 'high', 'block', 'release_requires_human_approval',
    'Blocked an attempt to start the production release workflow without explicit approval', '.github/workflows/release.yml', '{"tool_use_id":"release-publish","reason":"production deployment"}', (unixepoch('now', '-22 minutes') * 1000)),
  (97002, 9503, 'agent_event', 95034, 'low', 'allow', 'control_plane_read_observed',
    'Deployment workflow was inspected in read-only mode', '.github/workflows/release.yml', '{"tool_use_id":"release-read-workflow"}', (unixepoch('now', '-29 minutes') * 1000)),
  (97003, 9503, 'agent_event', 95032, 'info', 'allow', 'release_notes_expected_write',
    'Release notes update stayed within the approved documentation scope', 'CHANGELOG.md', '{"tool_use_id":"release-notes"}', (unixepoch('now', '-35 minutes') * 1000)),
  (97004, 9505, 'system_event', 96005, 'critical', 'block', 'production_secret_path_protected',
    'Prevented an unmatched process from opening the production environment file', '/workspace/commerce-platform/.env.production', '{"process":"/usr/bin/python3"}', (unixepoch('now', '-1 hour', '-43 minutes') * 1000)),
  (97005, 9502, 'agent_event', 95016, 'high', 'ask', 'payment_execution_path_change',
    'Asked for approval before changing code on the payment execution path', 'services/payments/src/webhook.rs', '{"tool_use_id":"remediation-edit","approved":true}', (unixepoch('now', '-2 hours', '-1 minute') * 1000)),
  (97006, 9502, 'agent_event', 95022, 'info', 'allow', 'test_command_allowed',
    'Allowed the repository-scoped payment test suite', NULL, '{"tool_use_id":"remediation-suite"}', (unixepoch('now', '-1 hour', '-44 minutes') * 1000)),
  (97007, 9501, 'agent_event', 95011, 'critical', 'block', 'production_secret_path_protected',
    'Blocked direct access to production credentials during incident triage', '.env.production', '{"tool_use_id":"incident-prod-env"}', (unixepoch('now', '-2 hours', '-49 minutes') * 1000)),
  (97008, 9501, 'agent_event', 95003, 'medium', 'warn', 'external_content_untrusted',
    'External documentation may inform analysis but cannot authorize tool actions', 'https://docs.stripe.com/webhooks', '{"tool_use_id":"incident-docs"}', (unixepoch('now', '-2 hours', '-57 minutes') * 1000)),
  (97009, 9501, 'agent_event', 95012, 'medium', 'ask', 'telemetry_query_review',
    'Asked before querying the incident telemetry database', 'telemetry.db', '{"tool_use_id":"incident-query","approved":true}', (unixepoch('now', '-2 hours', '-45 minutes') * 1000)),
  (97010, 9504, 'agent_event', 95045, 'high', 'ask', 'authentication_boundary_change',
    'Asked for approval before modifying OAuth callback validation', 'services/identity/src/oauth/callback.rs', '{"tool_use_id":"oauth-fix","approved":true}', (unixepoch('now', '-6 hours', '-42 minutes') * 1000)),
  (97011, 9504, 'agent_event', 95043, 'medium', 'warn', 'external_content_untrusted',
    'Fetched a public security standard as untrusted reference material', 'https://www.rfc-editor.org/rfc/rfc9700.html', '{"tool_use_id":"oauth-rfc"}', (unixepoch('now', '-6 hours', '-49 minutes') * 1000)),
  (97012, 9508, 'agent_event', 95053, 'high', 'warn', 'dependency_security_regression',
    'JWT update would introduce a transitive cryptography downgrade', 'Cargo.lock', '{"tool_use_id":"dependency-tree","advisory":"GHSA-example"}', (unixepoch('now', '-3 days', '-1 hour', '-58 minutes') * 1000)),
  (97013, 9507, 'agent_event', 95051, 'low', 'allow', 'accessibility_test_expected',
    'Accessibility suite ran inside the repository test scope', 'apps/checkout', '{"tool_use_id":"a11y-tests"}', (unixepoch('now', '-2 days', '-3 hours', '-58 minutes') * 1000)),
  (97014, 9511, 'agent_event', 95059, 'info', 'allow', 'audit_validation_expected',
    'Retention-policy validation used only synthetic audit fixtures', 'crates/audit/tests', '{"tool_use_id":"retention-tests"}', (unixepoch('now', '-6 days', '-3 hours', '-58 minutes') * 1000));

-- Six related artifacts fill the complete lineage canvas. Their facts are
-- ordered to keep the principal flow readable from source evidence to deploy.
INSERT INTO artifacts (
  artifact_id, kind, uri, digest, created_at, updated_at, metadata
) VALUES
  (98001, 'file', 'file:///workspace/commerce-platform/docs/operations/payment-webhooks.md', 'sha256:runbook-v4', (unixepoch('now', '-4 days') * 1000), (unixepoch('now', '-8 minutes') * 1000), '{"language":"markdown","owner":"payments"}'),
  (98002, 'file', 'file:///workspace/commerce-platform/fixtures/stripe/replayed-events.json', 'sha256:stripe-fixture-v2', (unixepoch('now', '-14 days') * 1000), (unixepoch('now', '-7 minutes') * 1000), '{"records":18,"synthetic":true}'),
  (98003, 'file', 'file:///workspace/commerce-platform/services/payments/src/webhook.rs', 'sha256:webhook-idempotent-v1', (unixepoch('now', '-2 years') * 1000), (unixepoch('now', '-6 minutes') * 1000), '{"language":"rust","owner":"payments"}'),
  (98004, 'file', 'file:///workspace/commerce-platform/services/payments/tests/webhook_replay_test.rs', 'sha256:replay-tests-v1', (unixepoch('now', '-2 hours') * 1000), (unixepoch('now', '-5 minutes') * 1000), '{"language":"rust","tests":12}'),
  (98005, 'file', 'file:///workspace/commerce-platform/.github/workflows/release.yml', 'sha256:release-workflow-v12', (unixepoch('now', '-18 months') * 1000), (unixepoch('now', '-4 minutes') * 1000), '{"language":"yaml","control_plane":true}'),
  (98006, 'file', 'file:///workspace/commerce-platform/deploy/production.yaml', 'sha256:production-manifest-v24', (unixepoch('now', '-11 months') * 1000), (unixepoch('now', '-3 minutes') * 1000), '{"language":"yaml","environment":"production"}');

INSERT INTO artifact_facts (
  kind, uri, current_artifact_id, current_digest, last_seen_at,
  last_modified_at, last_modified_source, last_modified_request_id,
  last_modified_session_id, last_system_event_id, last_agent_event_id,
  recent_unmatched_effect_count, recent_cross_session_write_count,
  is_agent_authored, is_unmatched_modified, is_memory_artifact,
  is_persistent_target, is_control_plane, risk_level, risk_rule_id,
  risk_digest, risk_updated_at, metadata
) VALUES
  ('file', 'file:///workspace/commerce-platform/docs/operations/payment-webhooks.md', 98001, 'sha256:runbook-v4', (unixepoch('now', '-3 minutes') * 1000), (unixepoch('now', '-4 days') * 1000), 'codex', 9509, 'showcase-docs-migration', NULL, 95056, 0, 0, 1, 0, 0, 0, 0, NULL, NULL, NULL, NULL, '{"role":"operational guidance"}'),
  ('file', 'file:///workspace/commerce-platform/fixtures/stripe/replayed-events.json', 98002, 'sha256:stripe-fixture-v2', (unixepoch('now', '-4 minutes') * 1000), (unixepoch('now', '-14 days') * 1000), 'maintainer', NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, '{"role":"synthetic evidence"}'),
  ('file', 'file:///workspace/commerce-platform/services/payments/src/webhook.rs', 98003, 'sha256:webhook-idempotent-v1', (unixepoch('now', '-5 minutes') * 1000), (unixepoch('now', '-1 hour', '-59 minutes') * 1000), 'claude-code', 9502, 'showcase-webhook-incident', 96002, 95017, 0, 0, 1, 0, 0, 0, 0, 'high', 'payment_execution_path_change', 'sha256:webhook-idempotent-v1', (unixepoch('now', '-2 hours') * 1000), '{"review":"approved"}'),
  ('file', 'file:///workspace/commerce-platform/services/payments/tests/webhook_replay_test.rs', 98004, 'sha256:replay-tests-v1', (unixepoch('now', '-8 minutes') * 1000), (unixepoch('now', '-1 hour', '-55 minutes') * 1000), 'claude-code', 9502, 'showcase-webhook-incident', 96003, 95019, 0, 0, 1, 0, 0, 0, 0, NULL, NULL, NULL, NULL, '{"coverage":"concurrent replay"}'),
  ('file', 'file:///workspace/commerce-platform/.github/workflows/release.yml', 98005, 'sha256:release-workflow-v12', (unixepoch('now', '-6 minutes') * 1000), (unixepoch('now', '-21 days') * 1000), 'maintainer', NULL, NULL, NULL, 95035, 0, 0, 0, 0, 0, 1, 1, 'high', 'release_requires_human_approval', 'sha256:release-workflow-v12', (unixepoch('now', '-22 minutes') * 1000), '{"review":"read only"}'),
  ('file', 'file:///workspace/commerce-platform/deploy/production.yaml', 98006, 'sha256:production-manifest-v24', (unixepoch('now', '-7 minutes') * 1000), (unixepoch('now', '-30 days') * 1000), 'release-bot', NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, 1, 1, 'critical', 'production_deployment_target', 'sha256:production-manifest-v24', (unixepoch('now', '-22 minutes') * 1000), '{"environment":"production"}');

INSERT INTO relations (
  relation_id, src_kind, src_id, dst_kind, dst_id, relation_type,
  confidence, evidence, created_at
) VALUES
  (99001, 'artifact', 98001, 'artifact', 98003, 'informed', 0.95, '{"reason":"runbook retry guidance"}', (unixepoch('now', '-1 hour') * 1000)),
  (99002, 'artifact', 98002, 'artifact', 98003, 'reproduced', 1.0, '{"reason":"duplicate delivery fixture"}', (unixepoch('now', '-1 hour') * 1000)),
  (99003, 'artifact', 98003, 'artifact', 98004, 'verified_by', 1.0, '{"tests":12}', (unixepoch('now', '-45 minutes') * 1000)),
  (99004, 'artifact', 98003, 'artifact', 98006, 'packaged_into', 0.98, '{"release":"v2.4.0"}', (unixepoch('now', '-20 minutes') * 1000)),
  (99005, 'artifact', 98005, 'artifact', 98006, 'promotes', 1.0, '{"gate":"human approval required"}', (unixepoch('now', '-18 minutes') * 1000));

INSERT INTO artifact_observations (
  observation_id, artifact_id, request_id, agent_event_id, session_id,
  digest, size_bytes, content_prefix, content_truncated, observed_at, evidence
) VALUES
  (99601, 98003, 9502, 95017, 'showcase-webhook-incident', 'sha256:webhook-idempotent-v1', 18442, 'use crate::idempotency::DurableClaim;', 1, (unixepoch('now', '-1 hour', '-59 minutes') * 1000), '{"source":"PostToolUse"}'),
  (99602, 98004, 9502, 95019, 'showcase-webhook-incident', 'sha256:replay-tests-v1', 4912, '#[tokio::test] async fn concurrent_replay', 1, (unixepoch('now', '-1 hour', '-55 minutes') * 1000), '{"source":"PostToolUse"}'),
  (99603, 98005, 9503, 95035, 'showcase-release-readiness', 'sha256:release-workflow-v12', 3280, 'name: Release', 1, (unixepoch('now', '-28 minutes') * 1000), '{"source":"PostToolUse","mode":"read"}');

INSERT INTO artifact_risk_tags (
  tag_id, artifact_id, digest, rule_id, severity, action, message, path,
  confidence, source_request_id, source_event_id, source_session_id,
  observed_at, evidence
) VALUES
  (99701, 98003, 'sha256:webhook-idempotent-v1', 'payment_execution_path_change', 'high', 'ask', 'Payment execution changes require review', 'services/payments/src/webhook.rs', 1.0, 9502, 95016, 'showcase-webhook-incident', (unixepoch('now', '-2 hours') * 1000), '{"approved":true}'),
  (99702, 98005, 'sha256:release-workflow-v12', 'release_requires_human_approval', 'high', 'block', 'Production release requires human approval', '.github/workflows/release.yml', 1.0, 9503, 95036, 'showcase-release-readiness', (unixepoch('now', '-22 minutes') * 1000), '{"approved":false}'),
  (99703, 98006, 'sha256:production-manifest-v24', 'production_deployment_target', 'critical', 'block', 'Production manifest is a protected persistent target', 'deploy/production.yaml', 1.0, 9503, 95036, 'showcase-release-readiness', (unixepoch('now', '-22 minutes') * 1000), '{"environment":"production"}');

INSERT INTO human_feedback (
  feedback_id, event_key, tool_use_id, session_id, gensee_action,
  human_verdict, label, rule_id, path, note, created_at
) VALUES
  (97501, 'alert:97001', 'release-publish', 'showcase-release-readiness', 'block', 'agree', 'confirmed', 'release_requires_human_approval', '.github/workflows/release.yml', 'Correct gate: release manager approval was still pending.', (unixepoch('now', '-16 minutes') * 1000)),
  (97502, 'alert:97005', 'remediation-edit', 'showcase-webhook-incident', 'ask', 'agree', 'confirmed', 'payment_execution_path_change', 'services/payments/src/webhook.rs', 'Approval was appropriate for a charge-path change.', (unixepoch('now', '-1 hour', '-12 minutes') * 1000)),
  (97503, 'alert:97008', 'incident-docs', 'showcase-webhook-incident', 'warn', 'allow', 'override', 'external_content_untrusted', 'https://docs.stripe.com/webhooks', 'Official vendor documentation was acceptable as reference material.', (unixepoch('now', '-1 hour', '-8 minutes') * 1000)),
  (97504, 'alert:97007', 'incident-prod-env', 'showcase-webhook-incident', 'block', 'agree', 'confirmed', 'production_secret_path_protected', '.env.production', 'Production credentials were unnecessary for the investigation.', (unixepoch('now', '-1 hour', '-5 minutes') * 1000)),
  (97505, 'alert:97012', 'dependency-tree', 'showcase-dependency-review', 'warn', 'deny', 'false_negative', 'dependency_security_regression', 'Cargo.lock', 'This dependency regression should block, not merely warn.', (unixepoch('now', '-45 minutes') * 1000));

COMMIT;
