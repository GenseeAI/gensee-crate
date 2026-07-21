-- Append a short burst of non-transactional activity to an already-open
-- dashboard so the Live Feed can be captured for documentation.
--
-- Load product-tour.sql first, open Live Feed, then run this file from another
-- terminal. Unlike the base fixture, each replay intentionally appends events.

PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

CREATE TEMP TABLE showcase_replay_nonce (value TEXT NOT NULL);
INSERT INTO showcase_replay_nonce VALUES (lower(hex(randomblob(6))));

INSERT INTO agent_events (
  pid, request_id, ts, source, type, cwd, permission_mode,
  tool_name, tool_input, tool_response, tool_use_id
) VALUES
  (6201, 9503, (unixepoch('now') * 1000) - 5200,
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"CHANGELOG.md"}', NULL, 'live-showcase-release-notes-' || (SELECT value FROM showcase_replay_nonce)),
  (6201, 9503, (unixepoch('now') * 1000) - 4100,
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":"CHANGELOG.md"}', '{"duration_ms":1100,"lines":416}', 'live-showcase-release-notes-' || (SELECT value FROM showcase_replay_nonce)),
  (6201, 9503, (unixepoch('now') * 1000) - 3000,
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"cargo test -p payments webhook_replay"}', NULL, 'live-showcase-release-check-' || (SELECT value FROM showcase_replay_nonce)),
  (6201, 9503, (unixepoch('now') * 1000) - 1800,
    'codex', 'PostToolUse', '/workspace/commerce-platform', 'default', 'Bash',
    '{"command":"cargo test -p payments webhook_replay"}', '{"duration_ms":1200,"stdout":"12 passed; 0 failed"}', 'live-showcase-release-check-' || (SELECT value FROM showcase_replay_nonce)),
  (6201, 9503, (unixepoch('now') * 1000) - 700,
    'codex', 'PreToolUse', '/workspace/commerce-platform', 'default', 'Read',
    '{"path":".github/workflows/release.yml"}', NULL, 'live-showcase-release-workflow-' || (SELECT value FROM showcase_replay_nonce));

COMMIT;
