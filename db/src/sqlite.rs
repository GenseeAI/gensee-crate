use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Genesis hash for the alert tamper-evident chain (64 hex zeros).
fn genesis_hash() -> String {
    "0".repeat(64)
}

/// Append a length-prefixed field to the chain hasher. The 8-byte little-endian
/// length prefix makes the concatenation injective, so no field value can be
/// shifted into an adjacent field to forge a matching hash.
fn feed_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Append an optional field with a presence tag, so `None` and `Some("")` hash
/// distinctly.
fn feed_opt(hasher: &mut Sha256, value: Option<&[u8]>) {
    match value {
        None => hasher.update([0_u8]),
        Some(bytes) => {
            hasher.update([1_u8]);
            feed_field(hasher, bytes);
        }
    }
}

/// `entry_hash = SHA-256(prev_hash || canonical(alert content))`. Binds both the
/// row's immutable content and its position in the chain.
fn alert_entry_hash(prev_hash: &str, alert: &NewAlert) -> String {
    let mut hasher = Sha256::new();
    feed_field(&mut hasher, prev_hash.as_bytes());
    feed_opt(
        &mut hasher,
        alert
            .request_id
            .map(|v| v.to_string())
            .as_deref()
            .map(str::as_bytes),
    );
    feed_opt(&mut hasher, alert.entity_kind.as_deref().map(str::as_bytes));
    feed_opt(
        &mut hasher,
        alert
            .entity_id
            .map(|v| v.to_string())
            .as_deref()
            .map(str::as_bytes),
    );
    feed_field(&mut hasher, alert.severity.as_bytes());
    feed_field(&mut hasher, alert.action.as_bytes());
    feed_field(&mut hasher, alert.rule_id.as_bytes());
    feed_field(&mut hasher, alert.message.as_bytes());
    feed_opt(&mut hasher, alert.path.as_deref().map(str::as_bytes));
    feed_opt(&mut hasher, alert.evidence.as_deref().map(str::as_bytes));
    feed_field(&mut hasher, alert.created_at.to_le_bytes().as_slice());
    format!("{:x}", hasher.finalize())
}

/// Result of [`SqliteStore::verify_alert_chain`].
#[derive(Debug, Clone, PartialEq)]
pub struct ChainVerification {
    /// Number of chained alerts verified before any break.
    pub checked: u64,
    /// `alert_id` of the first row that breaks the chain, if any.
    pub broken_at: Option<i64>,
    /// Human-readable reason for the break.
    pub reason: Option<String>,
}

impl ChainVerification {
    fn valid(checked: u64) -> Self {
        Self {
            checked,
            broken_at: None,
            reason: None,
        }
    }

    fn broken(alert_id: i64, checked: u64, reason: &str) -> Self {
        Self {
            checked,
            broken_at: Some(alert_id),
            reason: Some(reason.to_string()),
        }
    }

    /// A break with no offending row to point at — tail truncation, where the
    /// deleted rows are gone and the survivors still link cleanly, detected only
    /// against the persisted chain head/count.
    fn broken_tail(checked: u64, reason: &str) -> Self {
        Self {
            checked,
            broken_at: None,
            reason: Some(reason.to_string()),
        }
    }

    /// Whether the chain is intact (no tampering detected).
    pub fn is_valid(&self) -> bool {
        self.reason.is_none()
    }
}

#[derive(Debug, Deserialize)]
pub struct SqliteConfig {
    pub path: String,
    pub journal_mode: String,
    pub synchronous: String,
    pub auto_vacuum: String,
    #[serde(default)]
    pub shared_cache: bool,
    #[serde(default)]
    pub cipher_key: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SqliteError {
    #[error("failed to connect: {0}")]
    Connect(rusqlite::Error),
    #[error("failed to run schema: {0}")]
    Schema(rusqlite::Error),
    #[error("failed to apply pragma: {0}")]
    Pragma(rusqlite::Error),
    #[error("failed to create database directory: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "invalid journal_mode '{0}' (options: delete | truncate | persist | memory | wal | off)"
    )]
    JournalMode(String),
    #[error("invalid synchronous '{0}' (options: off | normal | full | extra)")]
    Synchronous(String),
    #[error("invalid auto_vacuum '{0}' (options: none | full | incremental)")]
    AutoVacuum(String),
    #[error("database operation failed: {0}")]
    Database(rusqlite::Error),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionRecord {
    pub session_id: String,
    pub agent_id: String,
    pub first_event_at: i64,
    pub last_event_at: Option<i64>,
    pub flagged: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewSession {
    pub session_id: String,
    pub agent_id: String,
    pub first_event_at: i64,
    pub last_event_at: Option<i64>,
    pub flagged: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestRecord {
    pub request_id: i64,
    pub session_id: String,
    pub original_user_prompt: Option<String>,
    pub final_response: Option<String>,
    pub events: Option<String>,
    pub file_accessed_rate: f64,
    pub network_rate: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewRequest {
    pub session_id: String,
    pub original_user_prompt: Option<String>,
    pub final_response: Option<String>,
    pub events: Option<String>,
    pub file_accessed_rate: f64,
    pub network_rate: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentEventRecord {
    pub event_id: i64,
    pub pid: i64,
    pub request_id: i64,
    pub ts: i64,
    pub source: String,
    pub event_type: String,
    pub cwd: String,
    pub permission_mode: Option<String>,
    pub tool_name: Option<String>,
    pub tool_input: Option<String>,
    pub tool_response: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewAgentEvent {
    pub pid: i64,
    pub request_id: i64,
    pub ts: i64,
    pub source: String,
    pub event_type: String,
    pub cwd: String,
    pub permission_mode: Option<String>,
    pub tool_name: Option<String>,
    pub tool_input: Option<String>,
    pub tool_response: Option<String>,
    pub tool_use_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SystemEventRecord {
    pub event_id: i64,
    pub pid: i64,
    pub request_id: i64,
    pub ts: i64,
    pub source: String,
    pub event_type: String,
    pub cwd: String,
    pub args: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewSystemEvent {
    pub pid: i64,
    pub request_id: i64,
    pub ts: i64,
    pub source: String,
    pub event_type: String,
    pub cwd: String,
    pub args: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactRecord {
    pub artifact_id: i64,
    pub kind: String,
    pub uri: String,
    pub digest: String,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewArtifact {
    pub kind: String,
    pub uri: String,
    pub digest: Option<String>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RelationRecord {
    pub relation_id: i64,
    pub src_kind: String,
    pub src_id: i64,
    pub dst_kind: String,
    pub dst_id: i64,
    pub relation_type: String,
    pub confidence: f64,
    pub evidence: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewRelation {
    pub src_kind: String,
    pub src_id: i64,
    pub dst_kind: String,
    pub dst_id: i64,
    pub relation_type: String,
    pub confidence: f64,
    pub evidence: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlertRecord {
    pub alert_id: i64,
    pub request_id: Option<i64>,
    pub session_id: Option<String>,
    pub entity_kind: Option<String>,
    pub entity_id: Option<i64>,
    pub severity: String,
    pub action: String,
    pub rule_id: String,
    pub message: String,
    pub path: Option<String>,
    pub evidence: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewAlert {
    pub request_id: Option<i64>,
    pub entity_kind: Option<String>,
    pub entity_id: Option<i64>,
    pub severity: String,
    pub action: String,
    pub rule_id: String,
    pub message: String,
    pub path: Option<String>,
    pub evidence: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewHumanFeedback {
    pub event_key: Option<String>,
    pub tool_use_id: Option<String>,
    pub session_id: Option<String>,
    pub gensee_action: Option<String>,
    pub human_verdict: String,
    pub label: Option<String>,
    pub rule_id: Option<String>,
    pub path: Option<String>,
    pub note: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HumanFeedbackRecord {
    pub feedback_id: i64,
    pub event_key: Option<String>,
    pub tool_use_id: Option<String>,
    pub session_id: Option<String>,
    pub gensee_action: Option<String>,
    pub human_verdict: String,
    pub label: Option<String>,
    pub rule_id: Option<String>,
    pub path: Option<String>,
    pub note: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactObservationRecord {
    pub observation_id: i64,
    pub artifact_id: i64,
    pub request_id: Option<i64>,
    pub agent_event_id: Option<i64>,
    pub session_id: Option<String>,
    pub digest: String,
    pub size_bytes: i64,
    pub content_prefix: Option<String>,
    pub content_truncated: bool,
    pub observed_at: i64,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewArtifactObservation {
    pub artifact_id: i64,
    pub request_id: Option<i64>,
    pub agent_event_id: Option<i64>,
    pub session_id: Option<String>,
    pub digest: String,
    pub size_bytes: i64,
    pub content_prefix: Option<String>,
    pub content_truncated: bool,
    pub observed_at: i64,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactRiskTagRecord {
    pub tag_id: i64,
    pub artifact_id: i64,
    pub digest: String,
    pub rule_id: String,
    pub severity: String,
    pub action: String,
    pub message: String,
    pub path: Option<String>,
    pub confidence: f64,
    pub source_request_id: Option<i64>,
    pub source_event_id: Option<i64>,
    pub source_session_id: Option<String>,
    pub observed_at: i64,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewArtifactRiskTag {
    pub artifact_id: i64,
    pub digest: String,
    pub rule_id: String,
    pub severity: String,
    pub action: String,
    pub message: String,
    pub path: Option<String>,
    pub confidence: f64,
    pub source_request_id: Option<i64>,
    pub source_event_id: Option<i64>,
    pub source_session_id: Option<String>,
    pub observed_at: i64,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactFactRecord {
    pub kind: String,
    pub uri: String,
    pub current_artifact_id: Option<i64>,
    pub current_digest: Option<String>,
    pub last_seen_at: i64,
    pub last_modified_at: Option<i64>,
    pub last_modified_source: Option<String>,
    pub last_modified_request_id: Option<i64>,
    pub last_modified_session_id: Option<String>,
    pub last_system_event_id: Option<i64>,
    pub last_agent_event_id: Option<i64>,
    pub recent_unmatched_effect_count: i64,
    pub recent_cross_session_write_count: i64,
    pub is_agent_authored: bool,
    pub is_unmatched_modified: bool,
    pub is_memory_artifact: bool,
    pub is_persistent_target: bool,
    pub is_control_plane: bool,
    pub risk_level: Option<String>,
    pub risk_rule_id: Option<String>,
    pub risk_digest: Option<String>,
    pub risk_updated_at: Option<i64>,
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewArtifactFact {
    pub kind: String,
    pub uri: String,
    pub current_artifact_id: Option<i64>,
    pub current_digest: Option<String>,
    pub last_seen_at: i64,
    pub last_modified_at: Option<i64>,
    pub last_modified_source: Option<String>,
    pub last_modified_request_id: Option<i64>,
    pub last_modified_session_id: Option<String>,
    pub last_system_event_id: Option<i64>,
    pub last_agent_event_id: Option<i64>,
    pub recent_unmatched_effect_count: i64,
    pub recent_cross_session_write_count: i64,
    pub is_agent_authored: bool,
    pub is_unmatched_modified: bool,
    pub is_memory_artifact: bool,
    pub is_persistent_target: bool,
    pub is_control_plane: bool,
    pub risk_level: Option<String>,
    pub risk_rule_id: Option<String>,
    pub risk_digest: Option<String>,
    pub risk_updated_at: Option<i64>,
    pub metadata: Option<String>,
}

/// Opens a single connection to the SQLite database, applies the configured
/// pragmas, and ensures the schema exists. SQLite is single-writer, so callers
/// should hold one long-lived connection (e.g. behind a `Mutex`) rather than a
/// pool of writers.
pub fn open(config: &SqliteConfig) -> Result<Connection, SqliteError> {
    let path = Path::new(&config.path);

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let journal_mode = match config.journal_mode.to_lowercase().as_str() {
        "delete" => "DELETE",
        "truncate" => "TRUNCATE",
        "persist" => "PERSIST",
        "memory" => "MEMORY",
        "wal" => "WAL",
        "off" => "OFF",
        other => return Err(SqliteError::JournalMode(other.to_string())),
    };

    let synchronous = match config.synchronous.to_lowercase().as_str() {
        "off" => "OFF",
        "normal" => "NORMAL",
        "full" => "FULL",
        "extra" => "EXTRA",
        other => return Err(SqliteError::Synchronous(other.to_string())),
    };

    let auto_vacuum = match config.auto_vacuum.to_lowercase().as_str() {
        "none" => "NONE",
        "full" => "FULL",
        "incremental" => "INCREMENTAL",
        other => return Err(SqliteError::AutoVacuum(other.to_string())),
    };

    let conn = if config.shared_cache {
        let uri = format!("file:{}?cache=shared", path.display());
        Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(SqliteError::Connect)?
    } else {
        Connection::open(path).map_err(SqliteError::Connect)?
    };

    if let Some(key) = config.cipher_key.as_deref() {
        conn.pragma_update(None, "key", key)
            .map_err(SqliteError::Pragma)?;
    }

    conn.busy_timeout(BUSY_TIMEOUT)
        .map_err(SqliteError::Pragma)?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(SqliteError::Pragma)?;
    conn.pragma_update(None, "journal_mode", journal_mode)
        .map_err(SqliteError::Pragma)?;
    conn.pragma_update(None, "synchronous", synchronous)
        .map_err(SqliteError::Pragma)?;
    conn.pragma_update(None, "auto_vacuum", auto_vacuum)
        .map_err(SqliteError::Pragma)?;

    migrate_legacy_ownership(&conn).map_err(SqliteError::Schema)?;
    migrate_legacy_relations(&conn).map_err(SqliteError::Schema)?;
    migrate_alert_hash_chain(&conn).map_err(SqliteError::Schema)?;
    migrate_agent_event_tool_use_id(&conn).map_err(SqliteError::Schema)?;

    conn.execute_batch(include_str!("../schema.sql"))
        .map_err(SqliteError::Schema)?;

    // Must run AFTER schema.sql creates `alert_chain_head`: a DB upgraded from a
    // chain-without-anchor version already has chained alerts but an empty
    // anchor; seed it from those rows so the next insert doesn't reset count to 1.
    backfill_alert_chain_head(&conn).map_err(SqliteError::Schema)?;

    Ok(conn)
}

pub fn open_store(config: &SqliteConfig) -> Result<SqliteStore, SqliteError> {
    Ok(SqliteStore::new(open(config)?))
}

pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn into_inner(self) -> Connection {
        self.conn
    }

    pub fn insert_session(&self, session: &NewSession) -> Result<(), SqliteError> {
        self.conn
            .execute(
                "INSERT INTO sessions (session_id, agent_id, first_event_at, last_event_at, flagged)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(session_id) DO UPDATE SET
                    agent_id = excluded.agent_id,
                    first_event_at = MIN(sessions.first_event_at, excluded.first_event_at),
                    last_event_at = COALESCE(excluded.last_event_at, sessions.last_event_at),
                    flagged = excluded.flagged",
                params![
                    session.session_id,
                    session.agent_id,
                    session.first_event_at,
                    session.last_event_at,
                    bool_to_i64(session.flagged),
                ],
            )
            .map(|_| ())
            .map_err(SqliteError::Database)
    }

    pub fn get_session(&self, session_id: &str) -> Result<Option<SessionRecord>, SqliteError> {
        self.conn
            .query_row(
                "SELECT session_id, agent_id, first_event_at, last_event_at, flagged
                 FROM sessions
                 WHERE session_id = ?1",
                [session_id],
                map_session,
            )
            .optional()
            .map_err(SqliteError::Database)
    }

    pub fn set_session_flagged(&self, session_id: &str, flagged: bool) -> Result<(), SqliteError> {
        self.conn
            .execute(
                "UPDATE sessions SET flagged = ?2 WHERE session_id = ?1",
                params![session_id, bool_to_i64(flagged)],
            )
            .map(|_| ())
            .map_err(SqliteError::Database)
    }

    pub fn insert_request(&self, request: &NewRequest) -> Result<i64, SqliteError> {
        self.conn
            .execute(
                "INSERT INTO requests (
                    session_id, original_user_prompt, final_response,
                    events, file_accessed_rate, network_rate
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    request.session_id,
                    request.original_user_prompt,
                    request.final_response,
                    request.events,
                    request.file_accessed_rate,
                    request.network_rate,
                ],
            )
            .map_err(SqliteError::Database)?;

        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_request(&self, request_id: i64) -> Result<Option<RequestRecord>, SqliteError> {
        self.conn
            .query_row(
                "SELECT request_id, session_id, original_user_prompt, final_response,
                    events, file_accessed_rate, network_rate
                 FROM requests
                 WHERE request_id = ?1",
                [request_id],
                map_request,
            )
            .optional()
            .map_err(SqliteError::Database)
    }

    pub fn latest_request_for_session(
        &self,
        session_id: &str,
    ) -> Result<Option<RequestRecord>, SqliteError> {
        self.conn
            .query_row(
                "SELECT request_id, session_id, original_user_prompt, final_response,
                    events, file_accessed_rate, network_rate
                 FROM requests
                 WHERE session_id = ?1
                 ORDER BY request_id DESC
                 LIMIT 1",
                [session_id],
                map_request,
            )
            .optional()
            .map_err(SqliteError::Database)
    }

    pub fn latest_request(&self) -> Result<Option<RequestRecord>, SqliteError> {
        self.conn
            .query_row(
                "SELECT request_id, session_id, original_user_prompt, final_response,
                    events, file_accessed_rate, network_rate
                 FROM requests
                 ORDER BY request_id DESC
                 LIMIT 1",
                [],
                map_request,
            )
            .optional()
            .map_err(SqliteError::Database)
    }

    pub fn set_request_response(
        &self,
        request_id: i64,
        final_response: Option<&str>,
    ) -> Result<(), SqliteError> {
        self.conn
            .execute(
                "UPDATE requests SET final_response = ?2 WHERE request_id = ?1",
                params![request_id, final_response],
            )
            .map(|_| ())
            .map_err(SqliteError::Database)
    }

    pub fn set_request_resource_rates(
        &self,
        request_id: i64,
        file_accessed_rate: f64,
        network_rate: f64,
    ) -> Result<(), SqliteError> {
        self.conn
            .execute(
                "UPDATE requests
                 SET file_accessed_rate = ?2,
                     network_rate = ?3
                 WHERE request_id = ?1",
                params![request_id, file_accessed_rate, network_rate],
            )
            .map(|_| ())
            .map_err(SqliteError::Database)
    }

    pub fn request_event_rate_per_minute(
        &self,
        request_id: i64,
        event_type: &str,
    ) -> Result<f64, SqliteError> {
        self.conn
            .query_row(
                "SELECT COUNT(*), MIN(ts), MAX(ts)
                 FROM agent_events
                 WHERE request_id = ?1 AND type = ?2",
                params![request_id, event_type],
                rate_from_count_window,
            )
            .map_err(SqliteError::Database)
    }

    pub fn request_file_access_rate_per_minute(&self, request_id: i64) -> Result<f64, SqliteError> {
        self.conn
            .query_row(
                "SELECT COUNT(*), MIN(ts), MAX(ts)
                 FROM agent_events
                 WHERE request_id = ?1
                   AND (
                        type = 'file_intent'
                     OR (type = 'PreToolUse'
                         AND tool_name IN ('Read', 'Write', 'Edit', 'MultiEdit'))
                   )",
                [request_id],
                rate_from_count_window,
            )
            .map_err(SqliteError::Database)
    }

    pub fn request_alert_rate_per_minute(
        &self,
        request_id: i64,
        rule_id: &str,
    ) -> Result<f64, SqliteError> {
        self.conn
            .query_row(
                "SELECT COUNT(*), MIN(created_at), MAX(created_at)
                 FROM alerts
                 WHERE request_id = ?1 AND rule_id = ?2",
                params![request_id, rule_id],
                rate_from_count_window,
            )
            .map_err(SqliteError::Database)
    }

    pub fn insert_agent_event(&self, event: &NewAgentEvent) -> Result<i64, SqliteError> {
        self.conn
            .execute(
                "INSERT INTO agent_events (
                    pid, request_id, ts, source, type, cwd, permission_mode,
                    tool_name, tool_input, tool_response, tool_use_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    event.pid,
                    event.request_id,
                    event.ts,
                    event.source,
                    event.event_type,
                    event.cwd,
                    event.permission_mode,
                    event.tool_name,
                    event.tool_input,
                    event.tool_response,
                    event.tool_use_id,
                ],
            )
            .map_err(SqliteError::Database)?;

        Ok(self.conn.last_insert_rowid())
    }

    pub fn agent_events_for_request(
        &self,
        request_id: i64,
    ) -> Result<Vec<AgentEventRecord>, SqliteError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT event_id, pid, request_id, ts, source, type,
                    cwd, permission_mode, tool_name, tool_input, tool_response
                 FROM agent_events
                 WHERE request_id = ?1
                 ORDER BY ts",
            )
            .map_err(SqliteError::Database)?;
        let rows = stmt
            .query_map([request_id], map_agent_event)
            .map_err(SqliteError::Database)?;

        collect_rows(rows)
    }

    pub fn request_for_file_intent_path(
        &self,
        path: &str,
        ts: i64,
        window_ms: i64,
    ) -> Result<Option<AgentEventRecord>, SqliteError> {
        self.conn
            .query_row(
                "SELECT event_id, pid, request_id, ts, source, type,
                    cwd, permission_mode, tool_name, tool_input, tool_response
                 FROM agent_events
                 WHERE type = 'file_intent'
                   AND tool_input IS NOT NULL
                   AND json_extract(tool_input, '$.path') IS NOT NULL
                   AND ABS(ts - ?2) <= ?3
                   AND (
                        json_extract(tool_input, '$.path') = ?1
                     OR substr(?1, 1, length(json_extract(tool_input, '$.path')) + 1) =
                        json_extract(tool_input, '$.path') || '/'
                     OR substr(json_extract(tool_input, '$.path'), 1, length(?1) + 1) = ?1 || '/'
                 )
                 ORDER BY ABS(ts - ?2), event_id DESC
                 LIMIT 1",
                params![path, ts, window_ms],
                map_agent_event,
            )
            .optional()
            .map_err(SqliteError::Database)
    }

    pub fn insert_system_event(&self, event: &NewSystemEvent) -> Result<i64, SqliteError> {
        self.conn
            .execute(
                "INSERT INTO system_events (
                    pid, request_id, ts, source, type, cwd, args
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    event.pid,
                    event.request_id,
                    event.ts,
                    event.source,
                    event.event_type,
                    event.cwd,
                    event.args,
                ],
            )
            .map_err(SqliteError::Database)?;

        Ok(self.conn.last_insert_rowid())
    }

    pub fn system_events_for_request(
        &self,
        request_id: i64,
    ) -> Result<Vec<SystemEventRecord>, SqliteError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT event_id, pid, request_id, ts, source, type, cwd, args
                 FROM system_events
                 WHERE request_id = ?1
                 ORDER BY ts",
            )
            .map_err(SqliteError::Database)?;
        let rows = stmt
            .query_map([request_id], map_system_event)
            .map_err(SqliteError::Database)?;

        collect_rows(rows)
    }

    pub fn insert_artifact(&self, artifact: &NewArtifact) -> Result<i64, SqliteError> {
        let digest = artifact.digest.as_deref().unwrap_or("");
        self.conn
            .execute(
                "INSERT INTO artifacts (
                    kind, uri, digest, created_at, updated_at, metadata
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(kind, uri, digest) DO UPDATE SET
                    updated_at = COALESCE(excluded.updated_at, artifacts.updated_at),
                    metadata = COALESCE(excluded.metadata, artifacts.metadata)",
                params![
                    artifact.kind,
                    artifact.uri,
                    digest,
                    artifact.created_at,
                    artifact.updated_at,
                    artifact.metadata,
                ],
            )
            .map_err(SqliteError::Database)?;

        self.conn
            .query_row(
                "SELECT artifact_id
                 FROM artifacts
                 WHERE kind = ?1 AND uri = ?2 AND digest = ?3",
                params![artifact.kind, artifact.uri, digest],
                |row| row.get(0),
            )
            .map_err(SqliteError::Database)
    }

    pub fn get_artifact(&self, artifact_id: i64) -> Result<Option<ArtifactRecord>, SqliteError> {
        self.conn
            .query_row(
                "SELECT artifact_id, kind, uri, digest, created_at, updated_at, metadata
                 FROM artifacts
                 WHERE artifact_id = ?1",
                [artifact_id],
                map_artifact,
            )
            .optional()
            .map_err(SqliteError::Database)
    }

    pub fn artifact_by_kind_uri_digest(
        &self,
        kind: &str,
        uri: &str,
        digest: &str,
    ) -> Result<Option<ArtifactRecord>, SqliteError> {
        self.conn
            .query_row(
                "SELECT artifact_id, kind, uri, digest, created_at, updated_at, metadata
                 FROM artifacts
                 WHERE kind = ?1 AND uri = ?2 AND digest = ?3",
                params![kind, uri, digest],
                map_artifact,
            )
            .optional()
            .map_err(SqliteError::Database)
    }

    pub fn insert_artifact_observation(
        &self,
        observation: &NewArtifactObservation,
    ) -> Result<i64, SqliteError> {
        self.conn
            .execute(
                "INSERT INTO artifact_observations (
                    artifact_id, request_id, agent_event_id, session_id, digest,
                    size_bytes, content_prefix, content_truncated, observed_at, evidence
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    observation.artifact_id,
                    observation.request_id,
                    observation.agent_event_id,
                    observation.session_id,
                    observation.digest,
                    observation.size_bytes,
                    observation.content_prefix,
                    bool_to_i64(observation.content_truncated),
                    observation.observed_at,
                    observation.evidence,
                ],
            )
            .map_err(SqliteError::Database)?;

        Ok(self.conn.last_insert_rowid())
    }

    pub fn insert_artifact_risk_tag(&self, tag: &NewArtifactRiskTag) -> Result<i64, SqliteError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO artifact_risk_tags (
                    artifact_id, digest, rule_id, severity, action, message, path,
                    confidence, source_request_id, source_event_id, source_session_id,
                    observed_at, evidence
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    tag.artifact_id,
                    tag.digest,
                    tag.rule_id,
                    tag.severity,
                    tag.action,
                    tag.message,
                    tag.path,
                    tag.confidence,
                    tag.source_request_id,
                    tag.source_event_id,
                    tag.source_session_id,
                    tag.observed_at,
                    tag.evidence,
                ],
            )
            .map_err(SqliteError::Database)?;

        self.conn
            .query_row(
                "SELECT tag_id
                 FROM artifact_risk_tags
                 WHERE artifact_id = ?1
                   AND digest = ?2
                   AND rule_id = ?3
                   AND message = ?4",
                params![tag.artifact_id, tag.digest, tag.rule_id, tag.message],
                |row| row.get(0),
            )
            .map_err(SqliteError::Database)
    }

    pub fn artifact_risk_tags_for_digest(
        &self,
        artifact_id: i64,
        digest: &str,
    ) -> Result<Vec<ArtifactRiskTagRecord>, SqliteError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT tag_id, artifact_id, digest, rule_id, severity, action,
                    message, path, confidence, source_request_id, source_event_id,
                    source_session_id, observed_at, evidence
                 FROM artifact_risk_tags
                 WHERE artifact_id = ?1 AND digest = ?2
                 ORDER BY observed_at, tag_id",
            )
            .map_err(SqliteError::Database)?;
        let rows = stmt
            .query_map(params![artifact_id, digest], map_artifact_risk_tag)
            .map_err(SqliteError::Database)?;

        collect_rows(rows)
    }

    pub fn artifact_observations_for_digest(
        &self,
        artifact_id: i64,
        digest: &str,
    ) -> Result<Vec<ArtifactObservationRecord>, SqliteError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT observation_id, artifact_id, request_id, agent_event_id,
                    session_id, digest, size_bytes, content_prefix, content_truncated,
                    observed_at, evidence
                 FROM artifact_observations
                 WHERE artifact_id = ?1 AND digest = ?2
                 ORDER BY observed_at, observation_id",
            )
            .map_err(SqliteError::Database)?;
        let rows = stmt
            .query_map(params![artifact_id, digest], map_artifact_observation)
            .map_err(SqliteError::Database)?;

        collect_rows(rows)
    }

    pub fn upsert_artifact_fact(&self, fact: &NewArtifactFact) -> Result<(), SqliteError> {
        self.conn
            .execute(
                "INSERT INTO artifact_facts (
                    kind, uri, current_artifact_id, current_digest, last_seen_at,
                    last_modified_at, last_modified_source, last_modified_request_id,
                    last_modified_session_id, last_system_event_id, last_agent_event_id,
                    recent_unmatched_effect_count, recent_cross_session_write_count,
                    is_agent_authored, is_unmatched_modified, is_memory_artifact,
                    is_persistent_target, is_control_plane, risk_level, risk_rule_id,
                    risk_digest, risk_updated_at, metadata
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                    ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23
                 )
                 ON CONFLICT(kind, uri) DO UPDATE SET
                    current_artifact_id = excluded.current_artifact_id,
                    current_digest = excluded.current_digest,
                    last_seen_at = excluded.last_seen_at,
                    last_modified_at = excluded.last_modified_at,
                    last_modified_source = excluded.last_modified_source,
                    last_modified_request_id = excluded.last_modified_request_id,
                    last_modified_session_id = excluded.last_modified_session_id,
                    last_system_event_id = excluded.last_system_event_id,
                    last_agent_event_id = excluded.last_agent_event_id,
                    recent_unmatched_effect_count = excluded.recent_unmatched_effect_count,
                    recent_cross_session_write_count = excluded.recent_cross_session_write_count,
                    is_agent_authored = excluded.is_agent_authored,
                    is_unmatched_modified = excluded.is_unmatched_modified,
                    is_memory_artifact = excluded.is_memory_artifact,
                    is_persistent_target = excluded.is_persistent_target,
                    is_control_plane = excluded.is_control_plane,
                    risk_level = excluded.risk_level,
                    risk_rule_id = excluded.risk_rule_id,
                    risk_digest = excluded.risk_digest,
                    risk_updated_at = excluded.risk_updated_at,
                    metadata = excluded.metadata",
                params![
                    fact.kind,
                    fact.uri,
                    fact.current_artifact_id,
                    fact.current_digest,
                    fact.last_seen_at,
                    fact.last_modified_at,
                    fact.last_modified_source,
                    fact.last_modified_request_id,
                    fact.last_modified_session_id,
                    fact.last_system_event_id,
                    fact.last_agent_event_id,
                    fact.recent_unmatched_effect_count,
                    fact.recent_cross_session_write_count,
                    bool_to_i64(fact.is_agent_authored),
                    bool_to_i64(fact.is_unmatched_modified),
                    bool_to_i64(fact.is_memory_artifact),
                    bool_to_i64(fact.is_persistent_target),
                    bool_to_i64(fact.is_control_plane),
                    fact.risk_level,
                    fact.risk_rule_id,
                    fact.risk_digest,
                    fact.risk_updated_at,
                    fact.metadata,
                ],
            )
            .map(|_| ())
            .map_err(SqliteError::Database)
    }

    pub fn artifact_fact(
        &self,
        kind: &str,
        uri: &str,
    ) -> Result<Option<ArtifactFactRecord>, SqliteError> {
        self.conn
            .query_row(
                "SELECT kind, uri, current_artifact_id, current_digest, last_seen_at,
                    last_modified_at, last_modified_source, last_modified_request_id,
                    last_modified_session_id, last_system_event_id, last_agent_event_id,
                    recent_unmatched_effect_count, recent_cross_session_write_count,
                    is_agent_authored, is_unmatched_modified, is_memory_artifact,
                    is_persistent_target, is_control_plane, risk_level, risk_rule_id,
                    risk_digest, risk_updated_at, metadata
                 FROM artifact_facts
                 WHERE kind = ?1 AND uri = ?2",
                params![kind, uri],
                map_artifact_fact,
            )
            .optional()
            .map_err(SqliteError::Database)
    }

    pub fn producer_request_ids_for_artifact(
        &self,
        artifact_id: i64,
    ) -> Result<Vec<i64>, SqliteError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT DISTINCT relations.src_id
                 FROM relations
                 JOIN requests ON requests.request_id = relations.src_id
                 WHERE src_kind = 'request'
                   AND dst_kind = 'artifact'
                   AND dst_id = ?1
                   AND relation_type = 'produced'
                   AND requests.original_user_prompt IS NOT NULL
                 ORDER BY relations.src_id",
            )
            .map_err(SqliteError::Database)?;
        let rows = stmt
            .query_map([artifact_id], |row| row.get(0))
            .map_err(SqliteError::Database)?;

        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(SqliteError::Database)
    }

    pub fn consumed_artifact_ids_for_request(
        &self,
        request_id: i64,
    ) -> Result<Vec<i64>, SqliteError> {
        self.artifact_ids_for_request_relation(request_id, "consumed_by")
    }

    pub fn produced_artifact_ids_for_request(
        &self,
        request_id: i64,
    ) -> Result<Vec<i64>, SqliteError> {
        let mut artifact_ids = self.artifact_ids_for_request_relation(request_id, "produced")?;
        artifact_ids.extend(self.artifact_ids_for_request_relation(request_id, "modified")?);
        artifact_ids.sort_unstable();
        artifact_ids.dedup();
        Ok(artifact_ids)
    }

    fn artifact_ids_for_request_relation(
        &self,
        request_id: i64,
        relation_type: &str,
    ) -> Result<Vec<i64>, SqliteError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT DISTINCT
                    CASE
                        WHEN src_kind = 'artifact' THEN src_id
                        ELSE dst_id
                    END AS artifact_id
                 FROM relations
                 WHERE relation_type = ?2
                   AND (
                        (src_kind = 'artifact' AND dst_kind = 'request' AND dst_id = ?1)
                     OR (src_kind = 'request' AND src_id = ?1 AND dst_kind = 'artifact')
                   )
                 ORDER BY artifact_id",
            )
            .map_err(SqliteError::Database)?;
        let rows = stmt
            .query_map(params![request_id, relation_type], |row| row.get(0))
            .map_err(SqliteError::Database)?;

        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(SqliteError::Database)
    }

    pub fn insert_relation(&self, relation: &NewRelation) -> Result<i64, SqliteError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO relations (
                    src_kind, src_id, dst_kind, dst_id, relation_type,
                    confidence, evidence, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    relation.src_kind,
                    relation.src_id,
                    relation.dst_kind,
                    relation.dst_id,
                    relation.relation_type,
                    relation.confidence,
                    relation.evidence,
                    relation.created_at,
                ],
            )
            .map_err(SqliteError::Database)?;

        self.conn
            .query_row(
                "SELECT relation_id
                 FROM relations
                 WHERE src_kind = ?1
                   AND src_id = ?2
                   AND dst_kind = ?3
                   AND dst_id = ?4
                   AND relation_type = ?5",
                params![
                    relation.src_kind,
                    relation.src_id,
                    relation.dst_kind,
                    relation.dst_id,
                    relation.relation_type,
                ],
                |row| row.get(0),
            )
            .map_err(SqliteError::Database)
    }

    pub fn relations_for_request(
        &self,
        request_id: i64,
    ) -> Result<Vec<RelationRecord>, SqliteError> {
        self.relations_for_entity("request", request_id)
    }

    pub fn relations_for_entity(
        &self,
        kind: &str,
        id: i64,
    ) -> Result<Vec<RelationRecord>, SqliteError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT relation_id, src_kind, src_id, dst_kind, dst_id,
                    relation_type, confidence, evidence, created_at
                 FROM relations
                 WHERE (src_kind = ?1 AND src_id = ?2)
                    OR (dst_kind = ?1 AND dst_id = ?2)
                 ORDER BY relation_id",
            )
            .map_err(SqliteError::Database)?;
        let rows = stmt
            .query_map(params![kind, id], map_relation)
            .map_err(SqliteError::Database)?;

        collect_rows(rows)
    }

    pub fn insert_alert(&self, alert: &NewAlert) -> Result<i64, SqliteError> {
        // Tamper-evident hash chain (T8): link this alert to the previous one.
        let prev_hash = self.latest_alert_entry_hash()?.unwrap_or_else(genesis_hash);
        let entry_hash = alert_entry_hash(&prev_hash, alert);

        // The alert insert and the anchor update must be atomic — a crash
        // between them would leave a chained alert with a stale anchor, which
        // verification would (correctly but unhelpfully) read as tampering. A
        // SAVEPOINT is atomic whether or not a caller (e.g. the store's append
        // path) already opened a transaction, and nests cleanly inside one.
        self.conn
            .execute_batch("SAVEPOINT gensee_insert_alert")
            .map_err(SqliteError::Database)?;
        let result = self.insert_alert_chained(alert, &prev_hash, &entry_hash);
        match result {
            Ok(id) => {
                self.conn
                    .execute_batch("RELEASE gensee_insert_alert")
                    .map_err(SqliteError::Database)?;
                Ok(id)
            }
            Err(error) => {
                let _ = self
                    .conn
                    .execute_batch("ROLLBACK TO gensee_insert_alert; RELEASE gensee_insert_alert");
                Err(SqliteError::Database(error))
            }
        }
    }

    /// The two chained writes (alert row + anchor advance), run inside the
    /// caller's savepoint in [`insert_alert`].
    fn insert_alert_chained(
        &self,
        alert: &NewAlert,
        prev_hash: &str,
        entry_hash: &str,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO alerts (
                request_id, entity_kind, entity_id, severity, action,
                rule_id, message, path, evidence, created_at, prev_hash, entry_hash
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                alert.request_id,
                alert.entity_kind,
                alert.entity_id,
                alert.severity,
                alert.action,
                alert.rule_id,
                alert.message,
                alert.path,
                alert.evidence,
                alert.created_at,
                prev_hash,
                entry_hash,
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        // Advance the single-row chain anchor (head hash + count) so tail
        // truncation is later detectable.
        self.conn.execute(
            "INSERT INTO alert_chain_head (id, head_hash, count) VALUES (1, ?1, 1)
             ON CONFLICT(id) DO UPDATE SET head_hash = excluded.head_hash, count = count + 1",
            params![entry_hash],
        )?;
        Ok(id)
    }

    /// The most recent alert's `entry_hash`, or `None` if no chained alert
    /// exists yet (legacy rows predating the chain have NULL `entry_hash` and
    /// are skipped, so the chain starts fresh at the first new alert).
    fn latest_alert_entry_hash(&self) -> Result<Option<String>, SqliteError> {
        match self.conn.query_row(
            "SELECT entry_hash FROM alerts
             WHERE entry_hash IS NOT NULL ORDER BY alert_id DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        ) {
            Ok(hash) => Ok(Some(hash)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(SqliteError::Database(error)),
        }
    }

    /// Recompute the alert hash chain from the genesis hash and report the first
    /// break — any inserted, deleted, reordered, or modified row.
    ///
    /// The chain begins at the first alert with a non-NULL `entry_hash`; rows
    /// before that are legacy (predating the chain) and are skipped. From the
    /// chain start onward **every** row must be chained, so a row inserted with
    /// NULL hashes after the chain exists is detected as a break rather than
    /// silently ignored.
    pub fn verify_alert_chain(&self) -> Result<ChainVerification, SqliteError> {
        // First chained row; `min()` over no matches yields NULL -> None.
        let chain_start: Option<i64> = self
            .conn
            .query_row(
                "SELECT min(alert_id) FROM alerts WHERE entry_hash IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .map_err(SqliteError::Database)?;
        let Some(chain_start) = chain_start else {
            return Ok(ChainVerification::valid(0)); // no chained alerts yet
        };

        let mut stmt = self
            .conn
            .prepare(
                "SELECT alert_id, request_id, entity_kind, entity_id, severity, action,
                    rule_id, message, path, evidence, created_at, prev_hash, entry_hash
                 FROM alerts
                 WHERE alert_id >= ?1
                 ORDER BY alert_id",
            )
            .map_err(SqliteError::Database)?;
        let rows = stmt
            .query_map([chain_start], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    NewAlert {
                        request_id: row.get(1)?,
                        entity_kind: row.get(2)?,
                        entity_id: row.get(3)?,
                        severity: row.get(4)?,
                        action: row.get(5)?,
                        rule_id: row.get(6)?,
                        message: row.get(7)?,
                        path: row.get(8)?,
                        evidence: row.get(9)?,
                        created_at: row.get(10)?,
                    },
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                ))
            })
            .map_err(SqliteError::Database)?;

        let mut expected_prev = genesis_hash();
        let mut checked = 0_u64;
        for row in rows {
            let (alert_id, alert, prev_hash, entry_hash) = row.map_err(SqliteError::Database)?;
            // Past the chain start a missing hash means a row was inserted
            // outside the chained append path.
            let (Some(prev_hash), Some(entry_hash)) = (prev_hash, entry_hash) else {
                return Ok(ChainVerification::broken(
                    alert_id,
                    checked,
                    "unchained alert (NULL hash) inserted after the chain start",
                ));
            };
            if prev_hash != expected_prev {
                return Ok(ChainVerification::broken(
                    alert_id,
                    checked,
                    "prev_hash does not link to the previous entry (insertion, deletion, or reorder)",
                ));
            }
            if alert_entry_hash(&prev_hash, &alert) != entry_hash {
                return Ok(ChainVerification::broken(
                    alert_id,
                    checked,
                    "entry_hash mismatch (row content was modified)",
                ));
            }
            expected_prev = entry_hash;
            checked += 1;
        }

        // Tail-truncation check: the survivors above all link cleanly even if the
        // newest alerts were deleted, so compare the recomputed head/count against
        // the persisted anchor. A missing anchor (DB predating it) cannot detect
        // truncation -> treated as valid for what the chain itself proved.
        let anchor: Option<(String, i64)> = self
            .conn
            .query_row(
                "SELECT head_hash, count FROM alert_chain_head WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(SqliteError::Database)?;
        if let Some((head_hash, count)) = anchor {
            if checked != count as u64 || expected_prev != head_hash {
                return Ok(ChainVerification::broken_tail(
                    checked,
                    "chain head/count does not match the anchor (tail truncation or head rewrite)",
                ));
            }
        }
        Ok(ChainVerification::valid(checked))
    }

    pub fn list_alerts(&self) -> Result<Vec<AlertRecord>, SqliteError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT alert_id, alerts.request_id, entity_kind, entity_id, severity,
                    action, rule_id, message, path, evidence, created_at,
                    requests.session_id
                 FROM alerts
                 LEFT JOIN requests ON requests.request_id = alerts.request_id
                 ORDER BY created_at, alert_id",
            )
            .map_err(SqliteError::Database)?;
        let rows = stmt
            .query_map([], map_alert)
            .map_err(SqliteError::Database)?;

        collect_rows(rows)
    }

    pub fn alerts_for_request(&self, request_id: i64) -> Result<Vec<AlertRecord>, SqliteError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT alert_id, alerts.request_id, entity_kind, entity_id, severity,
                    action, rule_id, message, path, evidence, created_at,
                    requests.session_id
                 FROM alerts
                 LEFT JOIN requests ON requests.request_id = alerts.request_id
                 WHERE alerts.request_id = ?1
                 ORDER BY created_at, alert_id",
            )
            .map_err(SqliteError::Database)?;
        let rows = stmt
            .query_map([request_id], map_alert)
            .map_err(SqliteError::Database)?;

        collect_rows(rows)
    }

    /// Record a human review verdict (dashboard-originated). Append-only; the
    /// latest row per `event_key` is the current verdict.
    pub fn insert_human_feedback(&self, feedback: &NewHumanFeedback) -> Result<i64, SqliteError> {
        self.conn
            .execute(
                "INSERT INTO human_feedback (
                    event_key, tool_use_id, session_id, gensee_action,
                    human_verdict, label, rule_id, path, note, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    feedback.event_key,
                    feedback.tool_use_id,
                    feedback.session_id,
                    feedback.gensee_action,
                    feedback.human_verdict,
                    feedback.label,
                    feedback.rule_id,
                    feedback.path,
                    feedback.note,
                    feedback.created_at,
                ],
            )
            .map_err(SqliteError::Database)?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Most recent human feedback verdicts, newest first.
    pub fn recent_human_feedback(
        &self,
        limit: i64,
    ) -> Result<Vec<HumanFeedbackRecord>, SqliteError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT feedback_id, event_key, tool_use_id, session_id, gensee_action,
                    human_verdict, label, rule_id, path, note, created_at
                 FROM human_feedback
                 ORDER BY created_at DESC, feedback_id DESC
                 LIMIT ?1",
            )
            .map_err(SqliteError::Database)?;
        let rows = stmt
            .query_map([limit], map_human_feedback)
            .map_err(SqliteError::Database)?;
        collect_rows(rows)
    }

    /// True if any alert with `rule_id` has been recorded for `session_id`.
    /// Used to escalate later actions once a per-session concern (e.g. poisoned
    /// memory) has been detected.
    pub fn session_has_alert(&self, session_id: &str, rule_id: &str) -> Result<bool, SqliteError> {
        self.conn
            .query_row(
                "SELECT 1
                 FROM alerts
                 JOIN requests ON requests.request_id = alerts.request_id
                 WHERE requests.session_id = ?1 AND alerts.rule_id = ?2
                 LIMIT 1",
                params![session_id, rule_id],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .map_err(SqliteError::Database)
    }

    pub fn session_alert_count(&self, session_id: &str, rule_id: &str) -> Result<u64, SqliteError> {
        self.conn
            .query_row(
                "SELECT COUNT(*)
                 FROM alerts
                 JOIN requests ON requests.request_id = alerts.request_id
                 WHERE requests.session_id = ?1 AND alerts.rule_id = ?2",
                params![session_id, rule_id],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| u64::try_from(count).unwrap_or(0))
            .map_err(SqliteError::Database)
    }

    pub fn session_has_alert_evidence_string(
        &self,
        session_id: &str,
        rule_id: &str,
        evidence_key: &str,
        evidence_value: &str,
    ) -> Result<bool, SqliteError> {
        let json_path = format!("$.{evidence_key}");
        self.conn
            .query_row(
                "SELECT 1
                 FROM alerts
                 JOIN requests ON requests.request_id = alerts.request_id
                 WHERE requests.session_id = ?1
                   AND alerts.rule_id = ?2
                   AND json_extract(alerts.evidence, ?3) = ?4
                 LIMIT 1",
                params![session_id, rule_id, json_path, evidence_value],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .map_err(SqliteError::Database)
    }

    pub fn session_agent_event_count(
        &self,
        session_id: &str,
        event_type: &str,
    ) -> Result<u64, SqliteError> {
        self.conn
            .query_row(
                "SELECT COUNT(*)
                 FROM agent_events
                 JOIN requests ON requests.request_id = agent_events.request_id
                 WHERE requests.session_id = ?1 AND agent_events.type = ?2",
                params![session_id, event_type],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| u64::try_from(count).unwrap_or(0))
            .map_err(SqliteError::Database)
    }
}

fn migrate_legacy_relations(conn: &Connection) -> rusqlite::Result<()> {
    let columns = table_columns(conn, "relations")?;
    if columns.is_empty() || columns.iter().any(|column| column == "src_kind") {
        return Ok(());
    }

    eprintln!(
        "gensee sqlite migration: dropping legacy relations table; legacy relation rows are derived data and cannot be safely converted to typed lineage edges"
    );
    conn.execute_batch(
        "DROP INDEX IF EXISTS idx_relations_request_src;
         DROP INDEX IF EXISTS idx_relations_request_dest;
         DROP INDEX IF EXISTS idx_relations_agent_event_src;
         DROP INDEX IF EXISTS idx_relations_agent_event_dest;
         DROP INDEX IF EXISTS idx_relations_system_event_src;
         DROP INDEX IF EXISTS idx_relations_system_event_dest;
         DROP TABLE relations;",
    )
}

fn migrate_legacy_ownership(conn: &Connection) -> rusqlite::Result<()> {
    let session_columns = table_columns(conn, "sessions")?;
    let request_columns = table_columns(conn, "requests")?;

    if !session_columns.is_empty() && !session_columns.iter().any(|column| column == "agent_id") {
        conn.execute(
            "ALTER TABLE sessions ADD COLUMN agent_id TEXT NOT NULL DEFAULT 'unknown'",
            [],
        )?;
    }

    if request_columns.iter().any(|column| column == "agent_id") {
        if !session_columns.is_empty() {
            conn.execute(
                "UPDATE sessions
                 SET agent_id = COALESCE((
                    SELECT requests.agent_id
                    FROM requests
                    WHERE requests.session_id = sessions.session_id
                    ORDER BY requests.request_id
                    LIMIT 1
                 ), sessions.agent_id)",
                [],
            )?;
        }

        conn.pragma_update(None, "foreign_keys", "OFF")?;
        let rebuild_result = conn.execute_batch(
            "BEGIN;
             CREATE TABLE requests_new (
                request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                original_user_prompt TEXT,
                final_response TEXT,
                events TEXT,
                file_accessed_rate FLOAT DEFAULT 0.0,
                network_rate FLOAT DEFAULT 0.0,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id),
                CHECK (events IS NULL OR json_valid(events))
             );
             INSERT INTO requests_new (
                request_id, session_id, original_user_prompt, final_response,
                events, file_accessed_rate, network_rate
             )
             SELECT request_id, session_id, original_user_prompt, final_response,
                events, file_accessed_rate, network_rate
             FROM requests;
             DROP TABLE requests;
             ALTER TABLE requests_new RENAME TO requests;
             COMMIT;",
        );
        if rebuild_result.is_err() {
            let _ = conn.execute_batch("ROLLBACK;");
        }
        conn.pragma_update(None, "foreign_keys", "ON")?;
        rebuild_result?;
    }

    Ok(())
}

/// Add the tamper-evident hash-chain columns to a pre-existing `alerts` table.
/// On a fresh database the table does not exist yet (columns come back empty),
/// so `schema.sql` creates it with the columns and this is a no-op. Existing
/// rows keep NULL `entry_hash` and are excluded from the chain.
fn migrate_alert_hash_chain(conn: &Connection) -> rusqlite::Result<()> {
    let columns = table_columns(conn, "alerts")?;
    if columns.is_empty() {
        return Ok(());
    }
    if !columns.iter().any(|column| column == "prev_hash") {
        conn.execute("ALTER TABLE alerts ADD COLUMN prev_hash TEXT", [])?;
    }
    if !columns.iter().any(|column| column == "entry_hash") {
        conn.execute("ALTER TABLE alerts ADD COLUMN entry_hash TEXT", [])?;
    }
    Ok(())
}

/// Seed the single-row `alert_chain_head` anchor from existing chained alerts
/// when it is missing — i.e. a database upgraded from a version that had the
/// hash chain but not the anchor. Without this, the first new insert would
/// initialize the anchor with `count = 1` despite N pre-existing chained rows,
/// and verification would then false-report tail truncation after a legitimate
/// append. Idempotent: a no-op once the anchor row exists.
fn backfill_alert_chain_head(conn: &Connection) -> rusqlite::Result<()> {
    let has_anchor: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM alert_chain_head WHERE id = 1)",
        [],
        |row| row.get(0),
    )?;
    if has_anchor {
        return Ok(());
    }
    // Latest chained entry_hash + total chained count, if any chained rows exist.
    let head: Option<(String, i64)> = conn
        .query_row(
            "SELECT entry_hash,
                    (SELECT count(*) FROM alerts WHERE entry_hash IS NOT NULL)
             FROM alerts WHERE entry_hash IS NOT NULL
             ORDER BY alert_id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((head_hash, count)) = head {
        conn.execute(
            "INSERT INTO alert_chain_head (id, head_hash, count) VALUES (1, ?1, ?2)",
            params![head_hash, count],
        )?;
    }
    Ok(())
}

/// Add the `tool_use_id` column to a pre-existing `agent_events` table. On a
/// fresh database the table does not exist yet (columns come back empty), so
/// `schema.sql` creates it with the column and this is a no-op.
fn migrate_agent_event_tool_use_id(conn: &Connection) -> rusqlite::Result<()> {
    let columns = table_columns(conn, "agent_events")?;
    if columns.is_empty() {
        return Ok(());
    }
    if !columns.iter().any(|column| column == "tool_use_id") {
        conn.execute("ALTER TABLE agent_events ADD COLUMN tool_use_id TEXT", [])?;
    }
    Ok(())
}

fn table_columns(conn: &Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&Row<'_>) -> rusqlite::Result<T>>,
) -> Result<Vec<T>, SqliteError> {
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(SqliteError::Database)
}

fn map_session(row: &Row<'_>) -> rusqlite::Result<SessionRecord> {
    Ok(SessionRecord {
        session_id: row.get(0)?,
        agent_id: row.get(1)?,
        first_event_at: row.get(2)?,
        last_event_at: row.get(3)?,
        flagged: row.get::<_, i64>(4)? != 0,
    })
}

fn map_request(row: &Row<'_>) -> rusqlite::Result<RequestRecord> {
    Ok(RequestRecord {
        request_id: row.get(0)?,
        session_id: row.get(1)?,
        original_user_prompt: row.get(2)?,
        final_response: row.get(3)?,
        events: row.get(4)?,
        file_accessed_rate: row.get(5)?,
        network_rate: row.get(6)?,
    })
}

fn rate_from_count_window(row: &Row<'_>) -> rusqlite::Result<f64> {
    let count: i64 = row.get(0)?;
    let first: Option<i64> = row.get(1)?;
    let last: Option<i64> = row.get(2)?;
    if count <= 0 {
        return Ok(0.0);
    }
    let elapsed_ms = first
        .zip(last)
        .map(|(first, last)| last.saturating_sub(first))
        .unwrap_or(0)
        .max(60_000);
    Ok((count as f64) * 60_000.0 / (elapsed_ms as f64))
}

fn map_agent_event(row: &Row<'_>) -> rusqlite::Result<AgentEventRecord> {
    Ok(AgentEventRecord {
        event_id: row.get(0)?,
        pid: row.get(1)?,
        request_id: row.get(2)?,
        ts: row.get(3)?,
        source: row.get(4)?,
        event_type: row.get(5)?,
        cwd: row.get(6)?,
        permission_mode: row.get(7)?,
        tool_name: row.get(8)?,
        tool_input: row.get(9)?,
        tool_response: row.get(10)?,
    })
}

fn map_system_event(row: &Row<'_>) -> rusqlite::Result<SystemEventRecord> {
    Ok(SystemEventRecord {
        event_id: row.get(0)?,
        pid: row.get(1)?,
        request_id: row.get(2)?,
        ts: row.get(3)?,
        source: row.get(4)?,
        event_type: row.get(5)?,
        cwd: row.get(6)?,
        args: row.get(7)?,
    })
}

fn map_artifact(row: &Row<'_>) -> rusqlite::Result<ArtifactRecord> {
    Ok(ArtifactRecord {
        artifact_id: row.get(0)?,
        kind: row.get(1)?,
        uri: row.get(2)?,
        digest: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        metadata: row.get(6)?,
    })
}

fn map_relation(row: &Row<'_>) -> rusqlite::Result<RelationRecord> {
    Ok(RelationRecord {
        relation_id: row.get(0)?,
        src_kind: row.get(1)?,
        src_id: row.get(2)?,
        dst_kind: row.get(3)?,
        dst_id: row.get(4)?,
        relation_type: row.get(5)?,
        confidence: row.get(6)?,
        evidence: row.get(7)?,
        created_at: row.get(8)?,
    })
}

fn map_alert(row: &Row<'_>) -> rusqlite::Result<AlertRecord> {
    Ok(AlertRecord {
        alert_id: row.get(0)?,
        request_id: row.get(1)?,
        entity_kind: row.get(2)?,
        entity_id: row.get(3)?,
        severity: row.get(4)?,
        action: row.get(5)?,
        rule_id: row.get(6)?,
        message: row.get(7)?,
        path: row.get(8)?,
        evidence: row.get(9)?,
        created_at: row.get(10)?,
        session_id: row.get(11)?,
    })
}

fn map_human_feedback(row: &Row<'_>) -> rusqlite::Result<HumanFeedbackRecord> {
    Ok(HumanFeedbackRecord {
        feedback_id: row.get(0)?,
        event_key: row.get(1)?,
        tool_use_id: row.get(2)?,
        session_id: row.get(3)?,
        gensee_action: row.get(4)?,
        human_verdict: row.get(5)?,
        label: row.get(6)?,
        rule_id: row.get(7)?,
        path: row.get(8)?,
        note: row.get(9)?,
        created_at: row.get(10)?,
    })
}

fn map_artifact_observation(row: &Row<'_>) -> rusqlite::Result<ArtifactObservationRecord> {
    Ok(ArtifactObservationRecord {
        observation_id: row.get(0)?,
        artifact_id: row.get(1)?,
        request_id: row.get(2)?,
        agent_event_id: row.get(3)?,
        session_id: row.get(4)?,
        digest: row.get(5)?,
        size_bytes: row.get(6)?,
        content_prefix: row.get(7)?,
        content_truncated: row.get::<_, i64>(8)? != 0,
        observed_at: row.get(9)?,
        evidence: row.get(10)?,
    })
}

fn map_artifact_risk_tag(row: &Row<'_>) -> rusqlite::Result<ArtifactRiskTagRecord> {
    Ok(ArtifactRiskTagRecord {
        tag_id: row.get(0)?,
        artifact_id: row.get(1)?,
        digest: row.get(2)?,
        rule_id: row.get(3)?,
        severity: row.get(4)?,
        action: row.get(5)?,
        message: row.get(6)?,
        path: row.get(7)?,
        confidence: row.get(8)?,
        source_request_id: row.get(9)?,
        source_event_id: row.get(10)?,
        source_session_id: row.get(11)?,
        observed_at: row.get(12)?,
        evidence: row.get(13)?,
    })
}

fn map_artifact_fact(row: &Row<'_>) -> rusqlite::Result<ArtifactFactRecord> {
    Ok(ArtifactFactRecord {
        kind: row.get(0)?,
        uri: row.get(1)?,
        current_artifact_id: row.get(2)?,
        current_digest: row.get(3)?,
        last_seen_at: row.get(4)?,
        last_modified_at: row.get(5)?,
        last_modified_source: row.get(6)?,
        last_modified_request_id: row.get(7)?,
        last_modified_session_id: row.get(8)?,
        last_system_event_id: row.get(9)?,
        last_agent_event_id: row.get(10)?,
        recent_unmatched_effect_count: row.get(11)?,
        recent_cross_session_write_count: row.get(12)?,
        is_agent_authored: row.get::<_, i64>(13)? != 0,
        is_unmatched_modified: row.get::<_, i64>(14)? != 0,
        is_memory_artifact: row.get::<_, i64>(15)? != 0,
        is_persistent_target: row.get::<_, i64>(16)? != 0,
        is_control_plane: row.get::<_, i64>(17)? != 0,
        risk_level: row.get(18)?,
        risk_rule_id: row.get(19)?,
        risk_digest: row.get(20)?,
        risk_updated_at: row.get(21)?,
        metadata: row.get(22)?,
    })
}

fn bool_to_i64(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_creates_all_tables() {
        let path = std::env::temp_dir().join(format!("gensee-db-test-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let config = SqliteConfig {
            path: path.to_string_lossy().to_string(),
            journal_mode: "wal".to_string(),
            synchronous: "normal".to_string(),
            auto_vacuum: "full".to_string(),
            shared_cache: false,
            cipher_key: None,
        };

        let conn = open(&config).expect("open should succeed");

        for table in [
            "sessions",
            "requests",
            "agent_events",
            "system_events",
            "artifacts",
            "relations",
            "alerts",
            "artifact_observations",
            "artifact_risk_tags",
            "artifact_facts",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "table {table} should exist");
        }

        drop(conn);
        let db_name = path.file_name().expect("path should have a file name");
        let _ = std::fs::remove_file(&path);
        let _ =
            std::fs::remove_file(path.with_file_name(format!("{}-wal", db_name.to_string_lossy())));
        let _ =
            std::fs::remove_file(path.with_file_name(format!("{}-shm", db_name.to_string_lossy())));
    }

    #[test]
    fn store_api_writes_reads_and_updates_rows() {
        let path = std::env::temp_dir().join(format!(
            "gensee-db-store-api-test-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let config = test_config(&path);
        let store = open_store(&config).expect("store should open");

        store
            .insert_session(&NewSession {
                session_id: "sess_1".to_string(),
                agent_id: "agent_a".to_string(),
                first_event_at: 100,
                last_event_at: None,
                flagged: false,
            })
            .unwrap();
        store.set_session_flagged("sess_1", true).unwrap();
        assert_eq!(
            store.get_session("sess_1").unwrap().unwrap(),
            SessionRecord {
                session_id: "sess_1".to_string(),
                agent_id: "agent_a".to_string(),
                first_event_at: 100,
                last_event_at: None,
                flagged: true,
            }
        );

        let request_id = store
            .insert_request(&NewRequest {
                session_id: "sess_1".to_string(),
                original_user_prompt: Some("read file".to_string()),
                final_response: None,
                events: Some("[]".to_string()),
                file_accessed_rate: 0.25,
                network_rate: 0.0,
            })
            .unwrap();
        store
            .set_request_response(request_id, Some("done"))
            .expect("request response should update");
        let request = store.get_request(request_id).unwrap().unwrap();
        assert_eq!(request.final_response.as_deref(), Some("done"));
        assert_eq!(request.file_accessed_rate, 0.25);

        let agent_event_id = store
            .insert_agent_event(&NewAgentEvent {
                pid: 123,
                request_id,
                ts: 110,
                source: "claude-code".to_string(),
                event_type: "PreToolUse".to_string(),
                cwd: "/repo".to_string(),
                permission_mode: Some("default".to_string()),
                tool_name: Some("Bash".to_string()),
                tool_input: Some(r#"{"command":"ls"}"#.to_string()),
                tool_response: None,
                tool_use_id: None,
            })
            .unwrap();

        let system_event_id = store
            .insert_system_event(&NewSystemEvent {
                pid: 123,
                request_id,
                ts: 111,
                source: "macos-eslogger".to_string(),
                event_type: "open".to_string(),
                cwd: "/repo".to_string(),
                args: Some(r#"{"path":"/repo/file.txt"}"#.to_string()),
            })
            .unwrap();

        let artifact_id = store
            .insert_artifact(&NewArtifact {
                kind: "file".to_string(),
                uri: "file:///repo/file.txt".to_string(),
                digest: None,
                created_at: Some(111),
                updated_at: Some(111),
                metadata: Some(r#"{"source":"test"}"#.to_string()),
            })
            .unwrap();
        assert_eq!(
            store.get_artifact(artifact_id).unwrap().unwrap().uri,
            "file:///repo/file.txt"
        );

        store
            .insert_relation(&NewRelation {
                src_kind: "agent_event".to_string(),
                src_id: agent_event_id,
                dst_kind: "system_event".to_string(),
                dst_id: system_event_id,
                relation_type: "caused".to_string(),
                confidence: 0.75,
                evidence: Some(r#"{"matched_by":"test"}"#.to_string()),
                created_at: 111,
            })
            .unwrap();
        store
            .insert_relation(&NewRelation {
                src_kind: "request".to_string(),
                src_id: request_id,
                dst_kind: "artifact".to_string(),
                dst_id: artifact_id,
                relation_type: "produced".to_string(),
                confidence: 1.0,
                evidence: None,
                created_at: 111,
            })
            .unwrap();

        let agent_events = store.agent_events_for_request(request_id).unwrap();
        assert_eq!(agent_events.len(), 1);
        assert_eq!(agent_events[0].request_id, request_id);
        assert_eq!(agent_events[0].tool_name.as_deref(), Some("Bash"));

        let system_events = store.system_events_for_request(request_id).unwrap();
        assert_eq!(system_events.len(), 1);
        assert_eq!(system_events[0].event_id, system_event_id);
        assert_eq!(system_events[0].event_type, "open");

        let relations = store.relations_for_request(request_id).unwrap();
        assert_eq!(relations.len(), 1);
        assert_eq!(relations[0].src_kind, "request");
        assert_eq!(relations[0].src_id, request_id);
        assert_eq!(relations[0].dst_kind, "artifact");
        assert_eq!(relations[0].dst_id, artifact_id);
        assert_eq!(relations[0].relation_type, "produced");
        assert_eq!(
            store
                .relations_for_entity("agent_event", agent_event_id)
                .unwrap()[0]
                .dst_id,
            system_event_id
        );

        let alert_id = store
            .insert_alert(&NewAlert {
                request_id: Some(request_id),
                entity_kind: Some("agent_event".to_string()),
                entity_id: Some(agent_event_id),
                severity: "high".to_string(),
                action: "block".to_string(),
                rule_id: "test_rule".to_string(),
                message: "test alert".to_string(),
                path: Some("/repo/file.txt".to_string()),
                evidence: Some(r#"{"source":"test"}"#.to_string()),
                created_at: 112,
            })
            .unwrap();
        let alerts = store.alerts_for_request(request_id).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_id, alert_id);
        assert_eq!(alerts[0].session_id.as_deref(), Some("sess_1"));
        assert_eq!(store.list_alerts().unwrap().len(), 1);

        drop(store);
        remove_sqlite_files(&path);
    }

    #[test]
    fn event_inserts_reject_unknown_request_ids() {
        let path =
            std::env::temp_dir().join(format!("gensee-db-fk-test-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let config = test_config(&path);
        let store = open_store(&config).expect("store should open");

        let agent_error = store
            .insert_agent_event(&NewAgentEvent {
                pid: 1,
                request_id: 404,
                ts: 1,
                source: "claude-code".to_string(),
                event_type: "PreToolUse".to_string(),
                cwd: "/repo".to_string(),
                permission_mode: None,
                tool_name: None,
                tool_input: None,
                tool_response: None,
                tool_use_id: None,
            })
            .unwrap_err();
        assert!(matches!(agent_error, SqliteError::Database(_)));

        let system_error = store
            .insert_system_event(&NewSystemEvent {
                pid: 1,
                request_id: 404,
                ts: 1,
                source: "macos-eslogger".to_string(),
                event_type: "open".to_string(),
                cwd: "/repo".to_string(),
                args: None,
            })
            .unwrap_err();
        assert!(matches!(system_error, SqliteError::Database(_)));

        drop(store);
        remove_sqlite_files(&path);
    }

    #[test]
    fn system_events_sort_by_numeric_timestamp() {
        let path = std::env::temp_dir().join(format!(
            "gensee-db-system-order-test-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let config = test_config(&path);
        let store = open_store(&config).expect("store should open");

        store
            .insert_session(&NewSession {
                session_id: "sess_1".to_string(),
                agent_id: "agent_a".to_string(),
                first_event_at: 1,
                last_event_at: None,
                flagged: false,
            })
            .unwrap();
        let request_id = store
            .insert_request(&NewRequest {
                session_id: "sess_1".to_string(),
                original_user_prompt: None,
                final_response: None,
                events: None,
                file_accessed_rate: 0.0,
                network_rate: 0.0,
            })
            .unwrap();

        for ts in [999, 1000, 111, 2000] {
            store
                .insert_system_event(&NewSystemEvent {
                    pid: 1,
                    request_id,
                    ts,
                    source: "macos-eslogger".to_string(),
                    event_type: "open".to_string(),
                    cwd: "/repo".to_string(),
                    args: None,
                })
                .unwrap();
        }

        let timestamps = store
            .system_events_for_request(request_id)
            .unwrap()
            .into_iter()
            .map(|event| event.ts)
            .collect::<Vec<_>>();
        assert_eq!(timestamps, vec![111, 999, 1000, 2000]);

        drop(store);
        remove_sqlite_files(&path);
    }

    #[test]
    fn request_for_file_intent_path_matches_nearby_paths() {
        let path = std::env::temp_dir().join(format!(
            "gensee-db-file-intent-match-test-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let config = test_config(&path);
        let store = open_store(&config).expect("store should open");

        store
            .insert_session(&NewSession {
                session_id: "sess_1".to_string(),
                agent_id: "claude-code".to_string(),
                first_event_at: 1,
                last_event_at: None,
                flagged: false,
            })
            .unwrap();
        let request_id = store
            .insert_request(&NewRequest {
                session_id: "sess_1".to_string(),
                original_user_prompt: None,
                final_response: None,
                events: None,
                file_accessed_rate: 0.0,
                network_rate: 0.0,
            })
            .unwrap();

        store
            .insert_agent_event(&NewAgentEvent {
                pid: 1,
                request_id,
                ts: 1_000,
                source: "claude-bash-command-parser".to_string(),
                event_type: "file_intent".to_string(),
                cwd: "/repo".to_string(),
                permission_mode: None,
                tool_name: Some("Bash".to_string()),
                tool_input: Some(r#"{"path":"/repo/out.txt","operation":"write"}"#.to_string()),
                tool_response: None,
                tool_use_id: None,
            })
            .unwrap();
        store
            .insert_agent_event(&NewAgentEvent {
                pid: 1,
                request_id,
                ts: 1_001,
                source: "claude-bash-command-parser".to_string(),
                event_type: "file_intent".to_string(),
                cwd: "/repo".to_string(),
                permission_mode: None,
                tool_name: Some("Bash".to_string()),
                tool_input: Some(r#"{"path":"/repo/a_b/p%q.txt","operation":"write"}"#.to_string()),
                tool_response: None,
                tool_use_id: None,
            })
            .unwrap();

        let matched = store
            .request_for_file_intent_path("/repo/out.txt", 1_010, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(matched.request_id, request_id);
        assert_eq!(
            store
                .request_for_file_intent_path("/repo/out.txt", 3_000, 1_000)
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .request_for_file_intent_path("/repo/other.txt", 1_010, 1_000)
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .request_for_file_intent_path("/repo/axb/pxq.txt", 1_010, 1_000)
                .unwrap(),
            None
        );
        let literal_wildcards = store
            .request_for_file_intent_path("/repo/a_b/p%q.txt", 1_010, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(literal_wildcards.request_id, request_id);

        drop(store);
        remove_sqlite_files(&path);
    }

    fn chain_alert(n: i64) -> NewAlert {
        NewAlert {
            request_id: None,
            entity_kind: None,
            entity_id: None,
            severity: "high".to_string(),
            action: "block".to_string(),
            rule_id: format!("rule_{n}"),
            message: format!("alert {n}"),
            path: Some(format!("/repo/file_{n}")),
            evidence: None,
            created_at: 100 + n,
        }
    }

    #[test]
    fn alert_chain_verifies_and_detects_content_tampering() {
        let path =
            std::env::temp_dir().join(format!("gensee-db-chain-content-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = open_store(&test_config(&path)).expect("store should open");

        let id1 = store.insert_alert(&chain_alert(1)).unwrap();
        store.insert_alert(&chain_alert(2)).unwrap();
        let id3 = store.insert_alert(&chain_alert(3)).unwrap();

        let intact = store.verify_alert_chain().unwrap();
        assert!(intact.is_valid(), "fresh chain should verify: {intact:?}");
        assert_eq!(intact.checked, 3);

        // The first chained alert links to the genesis hash.
        let prev1: String = store
            .connection()
            .query_row(
                "SELECT prev_hash FROM alerts WHERE alert_id = ?1",
                [id1],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(prev1, "0".repeat(64));

        // Mutating stored content (without recomputing the chain) is detected.
        store
            .connection()
            .execute(
                "UPDATE alerts SET message = 'tampered' WHERE alert_id = ?1",
                [id3],
            )
            .unwrap();
        let broken = store.verify_alert_chain().unwrap();
        assert!(!broken.is_valid());
        assert_eq!(broken.broken_at, Some(id3));
        assert_eq!(broken.checked, 2);

        drop(store);
        remove_sqlite_files(&path);
    }

    #[test]
    fn alert_chain_detects_unchained_insert() {
        let path =
            std::env::temp_dir().join(format!("gensee-db-chain-insert-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = open_store(&test_config(&path)).expect("store should open");

        store.insert_alert(&chain_alert(1)).unwrap();
        store.insert_alert(&chain_alert(2)).unwrap();

        // Forge a row directly (NULL prev_hash/entry_hash), bypassing the chain.
        store
            .connection()
            .execute(
                "INSERT INTO alerts (request_id, severity, action, rule_id, message, created_at)
                 VALUES (NULL, 'high', 'block', 'forged', 'injected', 999)",
                [],
            )
            .unwrap();
        let forged_id = store.connection().last_insert_rowid();

        let broken = store.verify_alert_chain().unwrap();
        assert!(
            !broken.is_valid(),
            "unchained insert must break verification"
        );
        assert_eq!(broken.broken_at, Some(forged_id));
        assert_eq!(broken.checked, 2);

        drop(store);
        remove_sqlite_files(&path);
    }

    #[test]
    fn alert_chain_detects_deletion() {
        let path =
            std::env::temp_dir().join(format!("gensee-db-chain-delete-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = open_store(&test_config(&path)).expect("store should open");

        store.insert_alert(&chain_alert(1)).unwrap();
        let id2 = store.insert_alert(&chain_alert(2)).unwrap();
        let id3 = store.insert_alert(&chain_alert(3)).unwrap();

        // Deleting a middle row breaks the prev_hash linkage at the next row.
        store
            .connection()
            .execute("DELETE FROM alerts WHERE alert_id = ?1", [id2])
            .unwrap();
        let broken = store.verify_alert_chain().unwrap();
        assert!(!broken.is_valid());
        assert_eq!(broken.broken_at, Some(id3));

        drop(store);
        remove_sqlite_files(&path);
    }

    #[test]
    fn alert_chain_detects_tail_deletion() {
        let path =
            std::env::temp_dir().join(format!("gensee-db-chain-tail-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = open_store(&test_config(&path)).expect("store should open");

        store.insert_alert(&chain_alert(1)).unwrap();
        store.insert_alert(&chain_alert(2)).unwrap();
        let id3 = store.insert_alert(&chain_alert(3)).unwrap();

        // Delete the newest alert: survivors still link cleanly, so this is only
        // detectable against the persisted head/count anchor.
        store
            .connection()
            .execute("DELETE FROM alerts WHERE alert_id = ?1", [id3])
            .unwrap();
        let broken = store.verify_alert_chain().unwrap();
        assert!(!broken.is_valid(), "tail deletion must break verification");
        assert_eq!(broken.checked, 2);
        assert_eq!(broken.broken_at, None); // no surviving row is the offender

        drop(store);
        remove_sqlite_files(&path);
    }

    #[test]
    fn alert_chain_head_backfills_on_upgrade() {
        let path = std::env::temp_dir().join(format!(
            "gensee-db-chain-backfill-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        {
            let store = open_store(&test_config(&path)).expect("store should open");
            store.insert_alert(&chain_alert(1)).unwrap();
            store.insert_alert(&chain_alert(2)).unwrap();
            store.insert_alert(&chain_alert(3)).unwrap();
            // Simulate a DB upgraded from a chain-without-anchor version: chained
            // alerts exist but the anchor row does not.
            store
                .connection()
                .execute("DELETE FROM alert_chain_head", [])
                .unwrap();
        }

        // Re-open triggers backfill_alert_chain_head (count=3, head=latest).
        let store = open_store(&test_config(&path)).expect("store should reopen");
        // A legitimate append must NOT be flagged as tampering.
        store.insert_alert(&chain_alert(4)).unwrap();
        let verification = store.verify_alert_chain().unwrap();
        assert!(
            verification.is_valid(),
            "post-upgrade append must verify, not false-report: {verification:?}"
        );
        assert_eq!(verification.checked, 4);

        drop(store);
        remove_sqlite_files(&path);
    }

    fn test_config(path: &std::path::Path) -> SqliteConfig {
        SqliteConfig {
            path: path.to_string_lossy().to_string(),
            journal_mode: "wal".to_string(),
            synchronous: "normal".to_string(),
            auto_vacuum: "full".to_string(),
            shared_cache: false,
            cipher_key: None,
        }
    }

    fn remove_sqlite_files(path: &std::path::Path) {
        let db_name = path.file_name().expect("path should have a file name");
        let _ = std::fs::remove_file(path);
        let _ =
            std::fs::remove_file(path.with_file_name(format!("{}-wal", db_name.to_string_lossy())));
        let _ =
            std::fs::remove_file(path.with_file_name(format!("{}-shm", db_name.to_string_lossy())));
    }
}
