CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    root_pid INTEGER NOT NULL DEFAULT 0,
    first_event_at INTEGER NOT NULL,
    last_event_at INTEGER,
    flagged INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS requests (
    request_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    original_user_prompt TEXT,
    final_response TEXT,
    events TEXT,
    file_accessed_rate FLOAT DEFAULT 0.0,
    network_rate FLOAT DEFAULT 0.0,
    created_at INTEGER,
    completed_at INTEGER,
    total_tokens INTEGER,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    CHECK (events IS NULL OR json_valid(events))
);

CREATE TRIGGER IF NOT EXISTS requests_set_created_at
AFTER INSERT ON requests
WHEN NEW.created_at IS NULL
BEGIN
    UPDATE requests SET created_at = unixepoch() * 1000 WHERE request_id = NEW.request_id;
END;

-- Last cumulative transcript counter observed for each agent session. Keeping
-- this baseline separate prevents the first captured turn in an older session
-- from absorbing all tokens used before Gensee token capture was enabled.
CREATE TABLE IF NOT EXISTS session_token_usage (
    session_id TEXT PRIMARY KEY,
    last_cumulative_tokens INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

-- Incremental transcript parsing state. This survives one-shot hook processes
-- and is removed when its agent session ends.
CREATE TABLE IF NOT EXISTS transcript_token_state (
    session_id TEXT NOT NULL,
    transcript_path TEXT NOT NULL,
    state_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (session_id, transcript_path),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    CHECK (json_valid(state_json))
);

CREATE TABLE IF NOT EXISTS agent_events (
  event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  pid             INTEGER NOT NULL,
  request_id      INTEGER NOT NULL,
  ts              INTEGER NOT NULL,
  source          TEXT NOT NULL,
  type            TEXT NOT NULL,
  cwd             TEXT NOT NULL,
  permission_mode TEXT,
  tool_name       TEXT,
  tool_input      TEXT,
  tool_response   TEXT,
  -- Claude Code's per-tool-call id. Lets a PostToolUse row (tool actually ran)
  -- be joined back to the PreToolUse alert that decided it — used to derive the
  -- outcome of an `ask` (PostToolUse present => user approved; absent => denied).
  tool_use_id     TEXT,
  FOREIGN KEY (request_id) REFERENCES requests(request_id),
  CHECK (tool_input    IS NULL OR json_valid(tool_input)),
  CHECK (tool_response IS NULL OR json_valid(tool_response))
);

CREATE TABLE IF NOT EXISTS system_events (
  event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  pid         INTEGER NOT NULL,
  request_id  INTEGER NOT NULL,
  ts          INTEGER NOT NULL,
  source      TEXT NOT NULL,
  type        TEXT NOT NULL,
  cwd         TEXT NOT NULL,
  args        TEXT,
  FOREIGN KEY (request_id) REFERENCES requests(request_id),
  CHECK (args IS NULL OR json_valid(args))
);

CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind        TEXT NOT NULL,
  uri         TEXT NOT NULL,
  digest      TEXT NOT NULL DEFAULT '',
  created_at  INTEGER,
  updated_at  INTEGER,
  metadata    TEXT,
  CHECK (metadata IS NULL OR json_valid(metadata)),
  UNIQUE (kind, uri, digest)
);

CREATE TABLE IF NOT EXISTS relations (
  relation_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  src_kind      TEXT NOT NULL CHECK (src_kind IN ('request', 'agent_event', 'system_event', 'artifact')),
  src_id        INTEGER NOT NULL,
  dst_kind      TEXT NOT NULL CHECK (dst_kind IN ('request', 'agent_event', 'system_event', 'artifact')),
  dst_id        INTEGER NOT NULL,
  relation_type TEXT NOT NULL,
  confidence    REAL NOT NULL DEFAULT 1.0,
  evidence      TEXT,
  created_at    INTEGER NOT NULL,
  CHECK (src_kind != dst_kind OR src_id != dst_id),
  CHECK (evidence IS NULL OR json_valid(evidence)),
  UNIQUE (src_kind, src_id, dst_kind, dst_id, relation_type)
);

CREATE TABLE IF NOT EXISTS alerts (
  alert_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id  INTEGER,
  entity_kind TEXT CHECK (entity_kind IS NULL OR entity_kind IN ('request', 'agent_event', 'system_event', 'artifact')),
  entity_id   INTEGER,
  severity    TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  action      TEXT NOT NULL CHECK (action IN ('allow', 'warn', 'ask', 'block')),
  rule_id     TEXT NOT NULL,
  message     TEXT NOT NULL,
  path        TEXT,
  evidence    TEXT,
  created_at  INTEGER NOT NULL,
  -- Tamper-evident hash chain (T8): entry_hash = SHA-256(prev_hash || row
  -- content); prev_hash links to the previous alert's entry_hash. Any
  -- insertion/deletion/modification breaks the chain (see verify_alert_chain).
  prev_hash   TEXT,
  entry_hash  TEXT,
  FOREIGN KEY (request_id) REFERENCES requests(request_id),
  CHECK ((entity_kind IS NULL AND entity_id IS NULL) OR (entity_kind IS NOT NULL AND entity_id IS NOT NULL)),
  CHECK (evidence IS NULL OR json_valid(evidence))
);

CREATE INDEX IF NOT EXISTS idx_alerts_dashboard_dedupe
  ON alerts(rule_id, request_id, path, created_at, alert_id);

-- Single-row anchor for the alert hash chain: the latest entry_hash and the
-- count of chained alerts. Updated transactionally with each chained insert, so
-- tail truncation (deleting the newest alerts, which leaves survivors' links
-- intact) is detectable as a head/count mismatch. (An attacker who also rewrites
-- this row is the documented whole-DB-rewrite case -> needs a signed/off-box head.)
CREATE TABLE IF NOT EXISTS alert_chain_head (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  head_hash  TEXT NOT NULL,
  count      INTEGER NOT NULL
);

-- Append-only authorization records for intentional retention pruning. Each
-- checkpoint commits to the exact pruned alert hashes and to the alert-chain
-- head that was verified immediately before pruning. The surviving alert chain
-- is re-rooted at the checkpoint hash, so a verifier can distinguish an
-- authorized retention gap from an unexplained deletion.
CREATE TABLE IF NOT EXISTS alert_retention_checkpoints (
  checkpoint_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  prev_checkpoint_hash TEXT NOT NULL,
  checkpoint_hash      TEXT NOT NULL,
  previous_alert_head  TEXT NOT NULL,
  previous_alert_count INTEGER NOT NULL,
  pruned_count         INTEGER NOT NULL,
  highest_pruned_alert_id INTEGER NOT NULL,
  cutoff_ms            INTEGER NOT NULL,
  pruned_entries_hash  TEXT NOT NULL,
  created_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_retention_head (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  head_hash  TEXT NOT NULL,
  count      INTEGER NOT NULL
);

-- Cross-process throttle for bounded maintenance work. Hook clients are
-- intentionally short-lived, so an in-memory timer cannot prevent every hook
-- invocation from running retention.
CREATE TABLE IF NOT EXISTS maintenance_state (
  key         TEXT PRIMARY KEY,
  last_run_at INTEGER NOT NULL
);

-- Human review verdicts recorded from the dashboard: an operator's after-the-fact
-- judgement on a shield decision (the shield already enforced it inline at hook
-- time). Used to label false positives / negatives for later policy tuning and
-- shield eval. `gensee_action` is what the shield decided; `human_verdict` is
-- what the operator says ('agree' | 'allow' | 'deny'); `label` is the derived
-- relationship ('confirmed' | 'false_positive' | 'false_negative' | 'override').
CREATE TABLE IF NOT EXISTS human_feedback (
  feedback_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  event_key     TEXT,
  tool_use_id   TEXT,
  session_id    TEXT,
  gensee_action TEXT,
  human_verdict TEXT NOT NULL CHECK (human_verdict IN ('agree', 'allow', 'deny')),
  label         TEXT,
  rule_id       TEXT,
  path          TEXT,
  note          TEXT,
  created_at    INTEGER NOT NULL
);

-- Append-only history for state-changing transactional runtime operations.
-- Multiple phase rows share an operation_id (for example started/succeeded),
-- and multi-copy forks share one operation_id across their child runs.
CREATE TABLE IF NOT EXISTS transaction_events (
  transaction_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  operation_id          TEXT NOT NULL,
  environment_kind      TEXT NOT NULL,
  operation             TEXT NOT NULL,
  phase                 TEXT NOT NULL CHECK (phase IN ('started', 'succeeded', 'failed')),
  source_run_id         TEXT,
  target_run_id         TEXT,
  parent_run_id         TEXT,
  workspace             TEXT,
  summary               TEXT NOT NULL,
  error_kind            TEXT,
  error_message         TEXT,
  metadata              TEXT,
  occurred_at           INTEGER NOT NULL,
  CHECK (metadata IS NULL OR json_valid(metadata))
);

CREATE TABLE IF NOT EXISTS artifact_observations (
  observation_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  artifact_id       INTEGER NOT NULL,
  request_id        INTEGER,
  agent_event_id    INTEGER,
  session_id        TEXT,
  digest            TEXT NOT NULL,
  size_bytes        INTEGER NOT NULL,
  content_prefix    TEXT,
  content_truncated INTEGER NOT NULL DEFAULT 0,
  observed_at       INTEGER NOT NULL,
  evidence          TEXT,
  FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id),
  FOREIGN KEY (request_id) REFERENCES requests(request_id),
  FOREIGN KEY (agent_event_id) REFERENCES agent_events(event_id),
  CHECK (content_truncated IN (0, 1)),
  CHECK (evidence IS NULL OR json_valid(evidence))
);

CREATE TABLE IF NOT EXISTS artifact_risk_tags (
  tag_id             INTEGER PRIMARY KEY AUTOINCREMENT,
  artifact_id        INTEGER NOT NULL,
  digest             TEXT NOT NULL,
  rule_id            TEXT NOT NULL,
  severity           TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  action             TEXT NOT NULL CHECK (action IN ('allow', 'warn', 'ask', 'block')),
  message            TEXT NOT NULL,
  path               TEXT,
  confidence         REAL NOT NULL DEFAULT 1.0,
  source_request_id  INTEGER,
  source_event_id    INTEGER,
  source_session_id  TEXT,
  observed_at        INTEGER NOT NULL,
  evidence           TEXT,
  FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id),
  FOREIGN KEY (source_request_id) REFERENCES requests(request_id),
  FOREIGN KEY (source_event_id) REFERENCES agent_events(event_id),
  CHECK (evidence IS NULL OR json_valid(evidence)),
  UNIQUE (artifact_id, digest, rule_id, message)
);

CREATE TABLE IF NOT EXISTS artifact_facts (
  kind                              TEXT NOT NULL,
  uri                               TEXT NOT NULL,
  current_artifact_id               INTEGER,
  current_digest                    TEXT,
  last_seen_at                      INTEGER NOT NULL,
  last_modified_at                  INTEGER,
  last_modified_source              TEXT,
  last_modified_request_id          INTEGER,
  last_modified_session_id          TEXT,
  last_system_event_id              INTEGER,
  last_agent_event_id               INTEGER,
  recent_unmatched_effect_count     INTEGER NOT NULL DEFAULT 0,
  recent_cross_session_write_count  INTEGER NOT NULL DEFAULT 0,
  is_agent_authored                 INTEGER NOT NULL DEFAULT 0,
  is_unmatched_modified             INTEGER NOT NULL DEFAULT 0,
  is_memory_artifact                INTEGER NOT NULL DEFAULT 0,
  is_persistent_target              INTEGER NOT NULL DEFAULT 0,
  is_control_plane                  INTEGER NOT NULL DEFAULT 0,
  dashboard_visible                INTEGER NOT NULL DEFAULT 1,
  risk_level                        TEXT CHECK (risk_level IS NULL OR risk_level IN ('info', 'low', 'medium', 'high', 'critical')),
  risk_rule_id                      TEXT,
  risk_digest                       TEXT,
  risk_updated_at                   INTEGER,
  metadata                          TEXT,
  PRIMARY KEY (kind, uri),
  FOREIGN KEY (current_artifact_id) REFERENCES artifacts(artifact_id),
  FOREIGN KEY (last_modified_request_id) REFERENCES requests(request_id),
  FOREIGN KEY (last_system_event_id) REFERENCES system_events(event_id),
  FOREIGN KEY (last_agent_event_id) REFERENCES agent_events(event_id),
  CHECK (recent_unmatched_effect_count >= 0),
  CHECK (recent_cross_session_write_count >= 0),
  CHECK (is_agent_authored IN (0, 1)),
  CHECK (is_unmatched_modified IN (0, 1)),
  CHECK (is_memory_artifact IN (0, 1)),
  CHECK (is_persistent_target IN (0, 1)),
  CHECK (is_control_plane IN (0, 1)),
  CHECK (dashboard_visible IN (0, 1)),
  CHECK (metadata IS NULL OR json_valid(metadata))
);

-- Exact O(1) dashboard count maintained as artifact facts change. Visibility
-- is decided on ingestion and reclassified when rules_version changes instead
-- of re-running every path predicate across the complete fact table on each UI
-- refresh.
CREATE TABLE IF NOT EXISTS dashboard_artifact_count (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  count         INTEGER NOT NULL CHECK (count >= 0),
  rules_version INTEGER NOT NULL DEFAULT 0 CHECK (rules_version >= 0)
);
INSERT OR IGNORE INTO dashboard_artifact_count(id, count, rules_version)
  SELECT 1, COUNT(*), 0 FROM artifact_facts WHERE dashboard_visible = 1;

CREATE TRIGGER IF NOT EXISTS artifact_dashboard_count_insert
AFTER INSERT ON artifact_facts WHEN NEW.dashboard_visible = 1
BEGIN
  UPDATE dashboard_artifact_count SET count = count + 1 WHERE id = 1;
END;

CREATE TRIGGER IF NOT EXISTS artifact_dashboard_count_delete
AFTER DELETE ON artifact_facts WHEN OLD.dashboard_visible = 1
BEGIN
  UPDATE dashboard_artifact_count SET count = MAX(0, count - 1) WHERE id = 1;
END;

CREATE TRIGGER IF NOT EXISTS artifact_dashboard_count_update
AFTER UPDATE OF dashboard_visible ON artifact_facts
WHEN OLD.dashboard_visible != NEW.dashboard_visible
BEGIN
  UPDATE dashboard_artifact_count
     SET count = MAX(0, count + NEW.dashboard_visible - OLD.dashboard_visible)
   WHERE id = 1;
END;

-- Per-request event lookup: "show me everything that happened during request X".
CREATE INDEX IF NOT EXISTS idx_agent_events_request_ts
    ON agent_events(request_id, ts);

CREATE INDEX IF NOT EXISTS idx_requests_created_at
    ON requests(created_at);

CREATE INDEX IF NOT EXISTS idx_requests_session_id
    ON requests(session_id, request_id);

-- Supports the macOS console's bounded recent-request projection without a
-- full table scan and temporary sort on every two-second refresh.
CREATE INDEX IF NOT EXISTS idx_requests_dashboard_activity
    ON requests(COALESCE(completed_at, created_at, request_id) DESC, request_id DESC);

CREATE INDEX IF NOT EXISTS idx_agent_events_tool_use
    ON agent_events(tool_use_id);

-- File-intent correlation always starts with a narrow timestamp window. This
-- partial index prevents every Endpoint Security file event from scanning the
-- complete agent-event history before JSON path matching.
CREATE INDEX IF NOT EXISTS idx_agent_events_file_intent_ts
    ON agent_events(ts, event_id)
    WHERE type = 'file_intent' AND tool_input IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_system_events_request_ts
    ON system_events(request_id, ts);

-- Keeps dashboard visibility checks index-only even when a large historical
-- Endpoint Security stream remains in the audit database.
CREATE INDEX IF NOT EXISTS idx_system_events_dashboard_visibility
    ON system_events(source, request_id, ts DESC, event_id DESC);

CREATE INDEX IF NOT EXISTS idx_system_events_retention
    ON system_events(source, ts, event_id);

CREATE INDEX IF NOT EXISTS idx_artifacts_kind_uri
    ON artifacts(kind, uri);

CREATE INDEX IF NOT EXISTS idx_relations_src
    ON relations(src_kind, src_id);

CREATE INDEX IF NOT EXISTS idx_relations_dst
    ON relations(dst_kind, dst_id);

CREATE INDEX IF NOT EXISTS idx_relations_type
    ON relations(relation_type);

CREATE INDEX IF NOT EXISTS idx_alerts_request_created
    ON alerts(request_id, created_at);

CREATE INDEX IF NOT EXISTS idx_alerts_severity_created
    ON alerts(severity, created_at);

CREATE INDEX IF NOT EXISTS idx_alerts_path
    ON alerts(path);

CREATE INDEX IF NOT EXISTS idx_artifact_observations_artifact_digest
    ON artifact_observations(artifact_id, digest, observed_at);

CREATE INDEX IF NOT EXISTS idx_artifact_risk_tags_artifact_digest
    ON artifact_risk_tags(artifact_id, digest);

CREATE INDEX IF NOT EXISTS idx_artifact_risk_tags_rule
    ON artifact_risk_tags(rule_id, observed_at);

CREATE INDEX IF NOT EXISTS idx_artifact_facts_modified
    ON artifact_facts(last_modified_at);

CREATE INDEX IF NOT EXISTS idx_artifact_facts_risk
    ON artifact_facts(risk_level, risk_updated_at);

CREATE INDEX IF NOT EXISTS idx_human_feedback_event
    ON human_feedback(event_key, created_at);

CREATE INDEX IF NOT EXISTS idx_human_feedback_tool_use
    ON human_feedback(tool_use_id, created_at);

CREATE INDEX IF NOT EXISTS idx_transaction_events_time
    ON transaction_events(occurred_at, transaction_event_id);

CREATE INDEX IF NOT EXISTS idx_transaction_events_operation
    ON transaction_events(operation_id, transaction_event_id);

CREATE INDEX IF NOT EXISTS idx_transaction_events_source
    ON transaction_events(source_run_id, occurred_at);

CREATE INDEX IF NOT EXISTS idx_transaction_events_target
    ON transaction_events(target_run_id, occurred_at);
