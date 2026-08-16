use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use gensee_crate_core::{
    extract_apply_patch_input, normalize_agent_path, parse_apply_patch_changes,
    parse_mcp_file_intents, parse_vscode_file_intents, AgentHookEvent, AgentSession, FileIntent,
    ProcessObservation, SystemEvent, WorkspaceEffect,
};
use gensee_crate_db::sqlite::{
    open_store, AgentEventRecord, NewAgentEvent, NewAlert, NewArtifact, NewArtifactFact,
    NewArtifactObservation, NewArtifactRiskTag, NewHumanFeedback, NewRelation, NewRequest,
    NewSession, NewSystemEvent, NewTransactionEvent, SqliteConfig, SqliteError, SqliteStore,
    TranscriptTokenStateRecord,
};
pub use gensee_crate_db::sqlite::{
    AlertRecord, ArtifactFactRecord, ArtifactObservationRecord, ArtifactRiskTagRecord,
    ChainVerification, HumanFeedbackRecord,
};
use gensee_crate_rules::policy::Policy;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

pub const DEFAULT_RETENTION_DAYS: u32 = 7;
const STORE_KEY_FILE: &str = "gensee.key";
const JSONL_ENCRYPTED_PREFIX: &str = "gensee-jsonl-v1";
const UNKNOWN_SESSION_ID: &str = "unknown";
const SYSTEM_SESSION_ID: &str = "system";
const SYSTEM_AGENT_ID: &str = "system-monitor";
const SYSTEM_EVENT_CORRELATION_WINDOW_MS: i64 = 60_000;
const ARTIFACT_FACT_RECENT_WINDOW_MS: i64 = 24 * 60 * 60 * 1_000;
// Tool inputs are operator-visible telemetry. Bound their at-rest size so a
// single tool invocation cannot bloat the local store with arbitrary payloads.
const MAX_STORED_TOOL_INPUT_BYTES: usize = 16 * 1024;
const MAX_STORED_TOOL_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_TRANSACTION_TEXT_CHARS: usize = 2 * 1024;
const MAX_TRANSACTION_METADATA_BYTES: usize = 16 * 1024;
const MAX_TOKEN_TRANSCRIPT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub retention_days: u32,
    pub encrypt_at_rest: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            retention_days: DEFAULT_RETENTION_DAYS,
            encrypt_at_rest: true,
        }
    }
}

#[derive(Clone)]
pub struct EventStore {
    root: PathBuf,
    sqlite: Arc<Mutex<SqliteStore>>,
    encryption_key: Option<[u8; 32]>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct TranscriptTokenState {
    offset: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    claude_messages: HashMap<String, i64>,
    codex_total: i64,
}

struct TranscriptTokenUpdate {
    total: Option<i64>,
    record: TranscriptTokenStateRecord,
}

#[derive(Debug, Clone)]
pub struct PolicyAlert {
    pub session_id: Option<String>,
    pub tool_use_id: Option<String>,
    pub severity: String,
    pub action: String,
    pub rule_id: String,
    pub message: String,
    pub path: Option<String>,
    pub evidence: Option<Value>,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ArtifactObservationInput {
    pub session_id: Option<String>,
    pub path: String,
    pub digest: String,
    pub size_bytes: i64,
    pub content_prefix: Option<String>,
    pub content_truncated: bool,
    pub mutation: bool,
    pub evidence: Option<Value>,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ArtifactRiskTagInput {
    pub rule_id: String,
    pub severity: String,
    pub action: String,
    pub message: String,
    pub path: Option<String>,
    pub confidence: f64,
    pub evidence: Option<Value>,
}

/// A bounded, append-only lifecycle event for a transactional environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionEventInput {
    pub operation_id: String,
    pub environment_kind: String,
    pub operation: String,
    pub phase: String,
    pub source_run_id: Option<String>,
    pub target_run_id: Option<String>,
    pub parent_run_id: Option<String>,
    pub workspace: Option<String>,
    pub summary: String,
    pub error_kind: Option<String>,
    pub error_message: Option<String>,
    pub metadata: Option<Value>,
    pub occurred_at_ms: u64,
}

struct AlertInput<'a> {
    request_id: Option<i64>,
    entity: Option<EntityRef>,
    severity: &'a str,
    action: &'a str,
    rule_id: &'a str,
    message: &'a str,
    path: Option<&'a str>,
    evidence: Option<Value>,
    created_at: i64,
}

impl fmt::Debug for EventStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventStore")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl EventStore {
    pub fn default_local() -> io::Result<Self> {
        Self::new(default_root()?)
    }

    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        let encryption_key = store_encryption_key(&root)?;
        let sqlite = open_store(&sqlite_config_for_root(&root, encryption_key.as_ref()))
            .map_err(sqlite_error)?;
        Ok(Self {
            root,
            sqlite: Arc::new(Mutex::new(sqlite)),
            encryption_key,
        })
    }

    pub fn sessions_path(&self) -> PathBuf {
        self.root.join("sessions.jsonl")
    }

    pub fn database_path(&self) -> PathBuf {
        database_path_for_root(&self.root)
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }

    pub fn hooks_path(&self) -> PathBuf {
        self.root.join("hooks.jsonl")
    }

    pub fn process_observations_path(&self) -> PathBuf {
        self.root.join("process-observations.jsonl")
    }

    pub fn file_intents_path(&self) -> PathBuf {
        self.root.join("file-intents.jsonl")
    }

    pub fn system_events_path(&self) -> PathBuf {
        self.root.join("system-events.jsonl")
    }

    pub fn workspace_effects_path(&self) -> PathBuf {
        self.root.join("workspace-effects.jsonl")
    }

    pub fn append_session(&self, session: &AgentSession) -> io::Result<()> {
        if session.ended_at_ms.is_none() {
            let duplicate = self
                .sqlite_store()?
                .get_session(&session.session_id)
                .map_err(sqlite_error)?
                .is_some_and(|existing| {
                    existing.last_event_at.is_none()
                        && existing.root_pid == i64::from(session.root_pid)
                        && existing.agent_id == session.agent_binary
                });
            if duplicate {
                return Ok(());
            }
        }
        let db = self.sqlite_store()?;
        db.insert_session(&NewSession {
            session_id: session.session_id.clone(),
            agent_id: session.agent_binary.clone(),
            root_pid: i64::from(session.root_pid),
            first_event_at: to_i64(session.started_at_ms)?,
            last_event_at: session.ended_at_ms.map(to_i64).transpose()?,
            flagged: false,
        })
        .map_err(sqlite_error)?;
        append_jsonl(&self.sessions_path(), session, self.encryption_key.as_ref())
    }

    pub fn end_session(
        &self,
        session_id: &str,
        ended_at_ms: u64,
        exit_code: Option<i32>,
    ) -> io::Result<bool> {
        let Some(mut session) = latest_session_by_id(
            &self.sessions_path(),
            self.encryption_key.as_ref(),
            session_id,
        )?
        .filter(|session| session.ended_at_ms.is_none()) else {
            return Ok(false);
        };
        session.ended_at_ms = Some(ended_at_ms);
        session.exit_code = exit_code;
        self.append_session(&session)?;
        self.sqlite_store()?
            .delete_transcript_token_state_for_session(session_id)
            .map_err(sqlite_error)?;
        Ok(true)
    }

    pub fn append_hook_event(&self, event: &AgentHookEvent) -> io::Result<()> {
        self.append_hook_event_database(event)?;
        append_jsonl(&self.hooks_path(), event, self.encryption_key.as_ref())
    }

    pub fn append_process_observation(&self, observation: &ProcessObservation) -> io::Result<()> {
        self.append_process_observation_database(observation)?;
        append_jsonl(
            &self.process_observations_path(),
            observation,
            self.encryption_key.as_ref(),
        )
    }

    pub fn append_file_intent(&self, intent: &FileIntent) -> io::Result<()> {
        self.append_file_intent_database(intent)?;
        append_jsonl(
            &self.file_intents_path(),
            intent,
            self.encryption_key.as_ref(),
        )
    }

    pub fn append_system_event(&self, event: &SystemEvent) -> io::Result<()> {
        self.append_system_event_database(event)?;
        append_jsonl(
            &self.system_events_path(),
            event,
            self.encryption_key.as_ref(),
        )
    }

    pub fn append_workspace_effect(&self, effect: &WorkspaceEffect) -> io::Result<()> {
        self.append_workspace_effect_database(effect)?;
        append_jsonl(
            &self.workspace_effects_path(),
            effect,
            self.encryption_key.as_ref(),
        )
    }

    pub fn append_transaction_event(&self, event: &TransactionEventInput) -> io::Result<i64> {
        let db = self.sqlite_store()?;
        db.insert_transaction_event(&NewTransactionEvent {
            operation_id: event.operation_id.clone(),
            environment_kind: event.environment_kind.clone(),
            operation: event.operation.clone(),
            phase: event.phase.clone(),
            source_run_id: event.source_run_id.clone(),
            target_run_id: event.target_run_id.clone(),
            parent_run_id: event.parent_run_id.clone(),
            workspace: event.workspace.clone(),
            summary: bounded_transaction_text(&event.summary),
            error_kind: event.error_kind.clone(),
            error_message: event.error_message.as_deref().map(bounded_transaction_text),
            metadata: event
                .metadata
                .as_ref()
                .map(bounded_transaction_metadata)
                .transpose()?,
            occurred_at: to_i64(event.occurred_at_ms)?,
        })
        .map_err(sqlite_error)
    }

    pub fn list_sessions(&self) -> io::Result<Vec<AgentSession>> {
        let sessions =
            read_jsonl::<AgentSession>(&self.sessions_path(), self.encryption_key.as_ref())?;
        let mut positions = HashMap::new();
        let mut deduplicated = Vec::with_capacity(sessions.len());
        for session in sessions {
            if let Some(index) = positions.get(&session.session_id).copied() {
                // Session lifecycle updates and daemon retry fallbacks may append
                // the same logical session more than once. Keep its original
                // position while making the latest record authoritative.
                deduplicated[index] = session;
            } else {
                positions.insert(session.session_id.clone(), deduplicated.len());
                deduplicated.push(session);
            }
        }
        Ok(deduplicated)
    }

    pub fn list_hook_events(&self) -> io::Result<Vec<AgentHookEvent>> {
        read_jsonl(&self.hooks_path(), self.encryption_key.as_ref())
    }

    pub fn list_process_observations(&self) -> io::Result<Vec<ProcessObservation>> {
        read_jsonl(
            &self.process_observations_path(),
            self.encryption_key.as_ref(),
        )
    }

    pub fn list_file_intents(&self) -> io::Result<Vec<FileIntent>> {
        read_jsonl(&self.file_intents_path(), self.encryption_key.as_ref())
    }

    pub fn list_system_events(&self) -> io::Result<Vec<SystemEvent>> {
        read_jsonl(&self.system_events_path(), self.encryption_key.as_ref())
    }

    pub fn list_workspace_effects(&self) -> io::Result<Vec<WorkspaceEffect>> {
        read_jsonl(&self.workspace_effects_path(), self.encryption_key.as_ref())
    }

    pub fn list_alerts(&self) -> io::Result<Vec<AlertRecord>> {
        let db = self.sqlite_store()?;
        db.list_alerts().map_err(sqlite_error)
    }

    pub fn has_recent_file_intent(&self, path: &str, observed_at_ms: u64) -> io::Result<bool> {
        let db = self.sqlite_store()?;
        let ts = to_i64(observed_at_ms)?;
        db.request_for_file_intent_path(path, ts, SYSTEM_EVENT_CORRELATION_WINDOW_MS)
            .map(|event| event.is_some())
            .map_err(sqlite_error)
    }

    pub fn dashboard_state(&self) -> io::Result<Value> {
        let db = self.sqlite_store()?;
        let conn = db.connection();
        let alerts = query_json_rows(
            conn,
            "SELECT alerts.alert_id, alerts.request_id, alerts.entity_kind, alerts.entity_id,
                alerts.severity, alerts.action, alerts.rule_id, alerts.message,
                alerts.path, alerts.evidence, alerts.created_at,
                requests.session_id,
                substr(requests.original_user_prompt, 1, 1024),
                trigger_event.source, trigger_event.type, trigger_event.tool_name,
                trigger_event.tool_input, trigger_event.tool_use_id,
                feedback.human_verdict, feedback.label, feedback.created_at
             FROM alerts
             LEFT JOIN requests ON requests.request_id = alerts.request_id
             LEFT JOIN agent_events AS trigger_event
               ON trigger_event.event_id = COALESCE(
                 CASE
                   WHEN alerts.entity_kind = 'agent_event' THEN alerts.entity_id
                 END,
                 (
                   SELECT candidate.event_id
                   FROM agent_events AS candidate
                   WHERE candidate.request_id = alerts.request_id
                     AND candidate.tool_use_id = json_extract(alerts.evidence, '$.tool_use_id')
                   ORDER BY candidate.type = 'PreToolUse' DESC,
                            candidate.ts DESC,
                            candidate.event_id DESC
                   LIMIT 1
                 ),
                 (
                   SELECT candidate.event_id
                   FROM agent_events AS candidate
                   WHERE candidate.request_id = alerts.request_id
                     AND candidate.type = 'PreToolUse'
                     AND candidate.ts <= alerts.created_at
                   ORDER BY candidate.ts DESC, candidate.event_id DESC
                   LIMIT 1
                 ),
                 (
                   SELECT candidate.event_id
                   FROM agent_events AS candidate
                   WHERE candidate.request_id = alerts.request_id
                     AND candidate.ts <= alerts.created_at
                   ORDER BY candidate.ts DESC, candidate.event_id DESC
                   LIMIT 1
                 )
               )
             LEFT JOIN human_feedback AS feedback
               ON feedback.feedback_id = (
                 SELECT candidate_feedback.feedback_id
                 FROM human_feedback AS candidate_feedback
                 WHERE candidate_feedback.event_key = 'alert:' || alerts.alert_id
                 ORDER BY candidate_feedback.created_at DESC,
                          candidate_feedback.feedback_id DESC
                 LIMIT 1
               )
             WHERE NOT (
                (alerts.rule_id = 'unmatched_system_effect'
                 AND alerts.evidence LIKE '%\"source\":\"macos-endpoint-security\"%')
             )
             ORDER BY alerts.created_at DESC, alerts.alert_id DESC
             LIMIT 200",
            |row| {
                Ok(json!({
                    "alert_id": row.get::<_, i64>(0)?,
                    "request_id": row.get::<_, Option<i64>>(1)?,
                    "entity_kind": row.get::<_, Option<String>>(2)?,
                    "entity_id": row.get::<_, Option<i64>>(3)?,
                    "severity": row.get::<_, String>(4)?,
                    "action": row.get::<_, String>(5)?,
                    "rule_id": row.get::<_, String>(6)?,
                    "message": row.get::<_, String>(7)?,
                    "path": row.get::<_, Option<String>>(8)?,
                    "evidence": row.get::<_, Option<String>>(9)?,
                    "created_at": row.get::<_, i64>(10)?,
                    "session_id": row.get::<_, Option<String>>(11)?,
                    "original_user_prompt": row.get::<_, Option<String>>(12)?,
                    "event_source": row.get::<_, Option<String>>(13)?,
                    "event_type": row.get::<_, Option<String>>(14)?,
                    "tool_name": row.get::<_, Option<String>>(15)?,
                    "tool_input": row.get::<_, Option<String>>(16)?,
                    "tool_use_id": row.get::<_, Option<String>>(17)?,
                    "human_verdict": row.get::<_, Option<String>>(18)?,
                    "feedback_label": row.get::<_, Option<String>>(19)?,
                    "feedback_created_at": row.get::<_, Option<i64>>(20)?,
                }))
            },
        )?;
        let agent_events = query_json_rows(
            conn,
            "SELECT event_id, pid, agent_events.request_id, requests.session_id, ts,
                source, type, cwd, permission_mode, tool_name, tool_input,
                json_extract(tool_response, '$.duration_ms'), tool_use_id
             FROM agent_events
             LEFT JOIN requests ON requests.request_id = agent_events.request_id
             ORDER BY ts DESC, event_id DESC
             LIMIT 200",
            |row| {
                Ok(json!({
                    "event_id": row.get::<_, i64>(0)?,
                    "pid": row.get::<_, i64>(1)?,
                    "request_id": row.get::<_, i64>(2)?,
                    "session_id": row.get::<_, Option<String>>(3)?,
                    "ts": row.get::<_, i64>(4)?,
                    "source": row.get::<_, String>(5)?,
                    "type": row.get::<_, String>(6)?,
                    "cwd": row.get::<_, String>(7)?,
                    "permission_mode": row.get::<_, Option<String>>(8)?,
                    "tool_name": row.get::<_, Option<String>>(9)?,
                    "tool_input": row.get::<_, Option<String>>(10)?,
                    "duration_ms": row.get::<_, Option<i64>>(11)?,
                    "tool_use_id": row.get::<_, Option<String>>(12)?,
                }))
            },
        )?;
        let system_events = query_json_rows(
            conn,
            "SELECT event_id, pid, request_id, ts, source, type, cwd, args
             FROM system_events
             WHERE NOT (
                source = 'macos-endpoint-security'
                AND args LIKE '%\"session_id\":null%'
             )
             ORDER BY ts DESC, event_id DESC
             LIMIT 200",
            |row| {
                Ok(json!({
                    "event_id": row.get::<_, i64>(0)?,
                    "pid": row.get::<_, i64>(1)?,
                    "request_id": row.get::<_, i64>(2)?,
                    "ts": row.get::<_, i64>(3)?,
                    "source": row.get::<_, String>(4)?,
                    "type": row.get::<_, String>(5)?,
                    "cwd": row.get::<_, String>(6)?,
                    "args": row.get::<_, Option<String>>(7)?,
                }))
            },
        )?;
        let sessions = query_json_rows(
            conn,
            "SELECT s.session_id, s.agent_id, s.first_event_at, s.last_event_at, s.flagged,
                (SELECT COUNT(*) FROM requests r WHERE r.session_id = s.session_id),
                (SELECT COUNT(*) FROM agent_events ae
                   JOIN requests r ON ae.request_id = r.request_id
                  WHERE r.session_id = s.session_id)
             FROM sessions s
             ORDER BY COALESCE(last_event_at, first_event_at) DESC
             LIMIT 100",
            |row| {
                Ok(json!({
                    "session_id": row.get::<_, String>(0)?,
                    "agent_id": row.get::<_, String>(1)?,
                    "first_event_at": row.get::<_, i64>(2)?,
                    "last_event_at": row.get::<_, Option<i64>>(3)?,
                    "flagged": row.get::<_, i64>(4)?,
                    "req_count": row.get::<_, i64>(5)?,
                    "event_count": row.get::<_, i64>(6)?,
                }))
            },
        )?;
        let requests = query_json_rows(
            conn,
            "SELECT request_id, session_id,
                substr(original_user_prompt, 1, 1024), created_at, completed_at
             FROM requests
             ORDER BY COALESCE(completed_at, created_at, request_id) DESC, request_id DESC
             LIMIT 500",
            |row| {
                Ok(json!({
                    "request_id": row.get::<_, i64>(0)?,
                    "session_id": row.get::<_, String>(1)?,
                    "original_user_prompt": row.get::<_, Option<String>>(2)?,
                    "created_at": row.get::<_, Option<i64>>(3)?,
                    "completed_at": row.get::<_, Option<i64>>(4)?,
                }))
            },
        )?;
        let artifact_visibility = dashboard_artifact_visibility_sql(
            "observation_source",
            "observation_mode",
            "observation_path",
        );
        let artifact_query = format!(
            "WITH candidates AS (
                SELECT facts.kind, facts.uri, facts.current_digest, facts.last_seen_at,
                    facts.last_modified_at, facts.last_modified_source,
                    facts.last_modified_session_id, facts.risk_level,
                    facts.risk_rule_id, facts.is_agent_authored,
                    facts.is_unmatched_modified, facts.is_memory_artifact,
                    facts.is_persistent_target, facts.is_control_plane,
                    COALESCE(json_extract(facts.metadata, '$.source'),
                             facts.last_modified_source, last_event.source) AS observation_source,
                    json_extract(last_event.args, '$.file.mode') AS observation_mode,
                    CASE WHEN facts.uri LIKE 'file://%'
                         THEN substr(facts.uri, 8)
                         ELSE facts.uri
                    END AS observation_path
                 FROM artifact_facts AS facts
                 LEFT JOIN system_events AS last_event
                   ON last_event.event_id = facts.last_system_event_id
             )
             SELECT kind, uri, current_digest, last_seen_at,
                    last_modified_at, last_modified_source,
                    last_modified_session_id, risk_level, risk_rule_id,
                    is_agent_authored, is_unmatched_modified, is_memory_artifact,
                    is_persistent_target, is_control_plane,
                    observation_source, observation_mode
             FROM candidates
             WHERE {artifact_visibility}
             ORDER BY last_seen_at DESC
             LIMIT 80"
        );
        let artifact_rows = query_json_rows(conn, &artifact_query, |row| {
            Ok(json!({
                "kind": row.get::<_, String>(0)?,
                "uri": row.get::<_, String>(1)?,
                "current_digest": row.get::<_, Option<String>>(2)?,
                "last_seen_at": row.get::<_, i64>(3)?,
                "last_modified_at": row.get::<_, Option<i64>>(4)?,
                "last_modified_source": row.get::<_, Option<String>>(5)?,
                "last_modified_session_id": row.get::<_, Option<String>>(6)?,
                "risk_level": row.get::<_, Option<String>>(7)?,
                "risk_rule_id": row.get::<_, Option<String>>(8)?,
                "is_agent_authored": row.get::<_, i64>(9)?,
                "is_unmatched_modified": row.get::<_, i64>(10)?,
                "is_memory_artifact": row.get::<_, i64>(11)?,
                "is_persistent_target": row.get::<_, i64>(12)?,
                "is_control_plane": row.get::<_, i64>(13)?,
                "_observation_source": row.get::<_, Option<String>>(14)?,
                "_observation_mode": row.get::<_, Option<i64>>(15)?,
            }))
        })?;
        debug_assert!(artifact_rows.iter().all(dashboard_artifact_is_visible));
        let visible_artifact_count = artifact_rows.len();
        let artifacts = artifact_rows
            .into_iter()
            .map(|mut artifact| {
                if let Some(object) = artifact.as_object_mut() {
                    object.remove("_observation_source");
                    object.remove("_observation_mode");
                }
                artifact
            })
            .collect::<Vec<_>>();
        let source_visibility = dashboard_path_visibility_sql("src_path");
        let destination_visibility = dashboard_path_visibility_sql("dst_path");
        let relation_query = format!(
            "WITH candidates AS (
                SELECT r.relation_id, r.relation_type AS type, r.confidence AS confidence,
                    sa.uri AS src_uri, da.uri AS dst_uri,
                    CASE WHEN sa.uri LIKE 'file://%' THEN substr(sa.uri, 8) ELSE sa.uri END AS src_path,
                    CASE WHEN da.uri LIKE 'file://%' THEN substr(da.uri, 8) ELSE da.uri END AS dst_path
                 FROM relations r
                 JOIN artifacts sa ON r.src_kind = 'artifact' AND r.src_id = sa.artifact_id
                 JOIN artifacts da ON r.dst_kind = 'artifact' AND r.dst_id = da.artifact_id
             )
             SELECT type, confidence, src_uri, dst_uri
             FROM candidates
             WHERE {source_visibility} AND {destination_visibility}
             ORDER BY relation_id DESC
             LIMIT 200"
        );
        let relations = query_json_rows(conn, &relation_query, |row| {
            Ok(json!({
                "type": row.get::<_, String>(0)?,
                "confidence": row.get::<_, f64>(1)?,
                "src_uri": row.get::<_, String>(2)?,
                "dst_uri": row.get::<_, String>(3)?,
            }))
        })?;
        debug_assert!(relations.iter().all(dashboard_relation_is_visible));
        let human_feedback = query_json_rows(
            conn,
            "SELECT event_key, tool_use_id, session_id, gensee_action, human_verdict,
                label, rule_id, path, note, created_at
             FROM human_feedback
             ORDER BY created_at DESC, feedback_id DESC
             LIMIT 200",
            |row| {
                Ok(json!({
                    "event_key": row.get::<_, Option<String>>(0)?,
                    "tool_use_id": row.get::<_, Option<String>>(1)?,
                    "session_id": row.get::<_, Option<String>>(2)?,
                    "gensee_action": row.get::<_, Option<String>>(3)?,
                    "human_verdict": row.get::<_, String>(4)?,
                    "label": row.get::<_, Option<String>>(5)?,
                    "rule_id": row.get::<_, Option<String>>(6)?,
                    "path": row.get::<_, Option<String>>(7)?,
                    "note": row.get::<_, Option<String>>(8)?,
                    "created_at": row.get::<_, i64>(9)?,
                }))
            },
        )?;
        let mut dashboard_summary = query_json_rows(
            conn,
            "SELECT
                (SELECT COUNT(*) FROM sessions),
                (SELECT COUNT(*) FROM requests),
                (SELECT COUNT(*) FROM agent_events),
                (SELECT COUNT(*) FROM system_events
                  WHERE NOT (
                    source = 'macos-endpoint-security'
                    AND args LIKE '%\"session_id\":null%'
                  )),
                (SELECT COUNT(*) FROM alerts
                  WHERE NOT (
                    (rule_id = 'unmatched_system_effect'
                     AND evidence LIKE '%\"source\":\"macos-endpoint-security\"%')
                  )),
                (SELECT COUNT(*) FROM alerts
                  WHERE severity IN ('high', 'critical')
                    AND created_at >= (unixepoch('now') - 86400) * 1000),
                (SELECT COUNT(*) FROM artifact_facts)",
            |row| {
                Ok(json!({
                    "sessions_count": row.get::<_, i64>(0)?,
                    "requests_count": row.get::<_, i64>(1)?,
                    "agent_events_count": row.get::<_, i64>(2)?,
                    "system_events_count": row.get::<_, i64>(3)?,
                    "alerts_count": row.get::<_, i64>(4)?,
                    "recent_high_alerts": row.get::<_, i64>(5)?,
                    "artifacts_count": row.get::<_, i64>(6)?,
                }))
            },
        )?
        .into_iter()
        .next()
        .unwrap_or_else(|| json!({}));
        dashboard_summary["artifacts_count"] = json!(visible_artifact_count);
        let daily_activity = query_json_rows(
            conn,
            "WITH
             daily_requests AS (
                SELECT date(created_at / 1000, 'unixepoch', 'localtime') AS day,
                       COUNT(*) AS count,
                       COALESCE(SUM(total_tokens), 0) AS tokens
                FROM requests
                WHERE created_at IS NOT NULL
                  AND session_id != 'system'
                  AND (
                    original_user_prompt IS NOT NULL
                    OR completed_at IS NOT NULL
                    OR EXISTS (
                        SELECT 1 FROM agent_events
                        WHERE agent_events.request_id = requests.request_id
                    )
                  )
                  AND date(created_at / 1000, 'unixepoch', 'localtime') >= date('now', 'localtime', '-371 days')
                GROUP BY day
             ),
             daily_tools AS (
                SELECT date(ts / 1000, 'unixepoch', 'localtime') AS day,
                       COUNT(*) AS count
                FROM agent_events
                WHERE type = 'PreToolUse'
                  AND date(ts / 1000, 'unixepoch', 'localtime') >= date('now', 'localtime', '-371 days')
                GROUP BY day
             ),
             daily_alerts AS (
                SELECT date(created_at / 1000, 'unixepoch', 'localtime') AS day,
                       COUNT(*) AS count
                FROM alerts
                WHERE date(created_at / 1000, 'unixepoch', 'localtime') >= date('now', 'localtime', '-371 days')
                  AND NOT (
                    (rule_id = 'unmatched_system_effect'
                     AND evidence LIKE '%\"source\":\"macos-endpoint-security\"%')
                  )
                GROUP BY day
             ),
             days AS (
                SELECT day FROM daily_requests
                UNION SELECT day FROM daily_tools
                UNION SELECT day FROM daily_alerts
             )
             SELECT days.day,
                    COALESCE(daily_requests.count, 0),
                    COALESCE(daily_tools.count, 0),
                    COALESCE(daily_alerts.count, 0),
                    COALESCE(daily_requests.tokens, 0)
             FROM days
             LEFT JOIN daily_requests ON daily_requests.day = days.day
             LEFT JOIN daily_tools ON daily_tools.day = days.day
             LEFT JOIN daily_alerts ON daily_alerts.day = days.day
             ORDER BY days.day",
            |row| {
                Ok(json!({
                    "date": row.get::<_, String>(0)?,
                    "requests": row.get::<_, i64>(1)?,
                    "tool_calls": row.get::<_, i64>(2)?,
                    "alerts": row.get::<_, i64>(3)?,
                    "tokens": row.get::<_, i64>(4)?,
                }))
            },
        )?;
        Ok(json!({
            "source": "gensee",
            "summary": dashboard_summary,
            "alerts": alerts,
            "agentEvents": agent_events,
            "systemEvents": system_events,
            "sessions": sessions,
            "requests": requests,
            "artifacts": artifacts,
            "relations": relations,
            "humanFeedback": human_feedback,
            "dailyActivity": daily_activity,
            "jsonSessions": self.list_sessions()?,
        }))
    }

    pub fn dashboard_day(&self, day: &str) -> io::Result<Value> {
        if day.len() != 10
            || day.as_bytes().get(4) != Some(&b'-')
            || day.as_bytes().get(7) != Some(&b'-')
            || !day
                .chars()
                .enumerate()
                .all(|(index, character)| matches!(index, 4 | 7) || character.is_ascii_digit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dashboard day must use YYYY-MM-DD",
            ));
        }

        let db = self.sqlite_store()?;
        let conn = db.connection();
        let valid: i64 = conn
            .query_row("SELECT date(?1) = ?1", [day], |row| row.get(0))
            .map_err(sqlite_error_from_rusqlite)?;
        if valid != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dashboard day is not a valid calendar date",
            ));
        }

        let totals = conn
            .query_row(
                "SELECT
                   (SELECT COUNT(DISTINCT session_id) FROM requests
                     WHERE session_id != 'system'
                       AND date(created_at / 1000, 'unixepoch', 'localtime') = ?1),
                   (SELECT COUNT(*) FROM requests
                     WHERE session_id != 'system'
                       AND date(created_at / 1000, 'unixepoch', 'localtime') = ?1
                       AND (original_user_prompt IS NOT NULL OR completed_at IS NOT NULL
                            OR EXISTS (SELECT 1 FROM agent_events ae WHERE ae.request_id = requests.request_id))),
                   (SELECT COUNT(*) FROM agent_events
                     WHERE type = 'PreToolUse' AND date(ts / 1000, 'unixepoch', 'localtime') = ?1),
                   (SELECT COUNT(*) FROM alerts
                     WHERE date(created_at / 1000, 'unixepoch', 'localtime') = ?1
                       AND NOT (rule_id = 'unmatched_system_effect'
                                AND evidence LIKE '%\"source\":\"macos-endpoint-security\"%')),
                   (SELECT COALESCE(SUM(total_tokens), 0) FROM requests
                     WHERE session_id != 'system'
                       AND date(created_at / 1000, 'unixepoch', 'localtime') = ?1),
                   (SELECT COUNT(*) FROM agent_events
                     WHERE type = 'PreToolUse' AND date(ts / 1000, 'unixepoch', 'localtime') = ?1
                       AND (lower(COALESCE(tool_name, '')) LIKE '%write%'
                            OR lower(COALESCE(tool_name, '')) LIKE '%edit%'
                            OR lower(COALESCE(tool_name, '')) LIKE '%create%')),
                   (SELECT COUNT(*) FROM agent_events
                     WHERE type = 'PreToolUse' AND date(ts / 1000, 'unixepoch', 'localtime') = ?1
                       AND lower(COALESCE(tool_name, '')) LIKE '%read%'),
                   (SELECT COUNT(*) FROM agent_events
                     WHERE type = 'PreToolUse' AND date(ts / 1000, 'unixepoch', 'localtime') = ?1
                       AND (lower(COALESCE(tool_name, '')) LIKE '%search%'
                            OR lower(COALESCE(tool_name, '')) LIKE '%fetch%'))",
                [day],
                |row| {
                    Ok(json!({
                        "sessions": row.get::<_, i64>(0)?,
                        "requests": row.get::<_, i64>(1)?,
                        "tool_calls": row.get::<_, i64>(2)?,
                        "alerts": row.get::<_, i64>(3)?,
                        "tokens": row.get::<_, i64>(4)?,
                        "files_written": row.get::<_, i64>(5)?,
                        "files_read": row.get::<_, i64>(6)?,
                        "web_requests": row.get::<_, i64>(7)?,
                    }))
                },
            )
            .map_err(sqlite_error_from_rusqlite)?;

        let grouped = |sql: &str| -> io::Result<Vec<Value>> {
            let mut statement = conn.prepare(sql).map_err(sqlite_error_from_rusqlite)?;
            let rows = statement
                .query_map([day], |row| {
                    Ok(json!({
                        "name": row.get::<_, String>(0)?,
                        "count": row.get::<_, i64>(1)?,
                    }))
                })
                .map_err(sqlite_error_from_rusqlite)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(sqlite_error_from_rusqlite)
        };
        let top_tools = grouped(
            "SELECT tool_name, COUNT(*) FROM agent_events
             WHERE type = 'PreToolUse' AND tool_name IS NOT NULL
               AND date(ts / 1000, 'unixepoch', 'localtime') = ?1
             GROUP BY tool_name ORDER BY COUNT(*) DESC, tool_name LIMIT 8",
        )?;
        let alerts_by_action = grouped(
            "SELECT action, COUNT(*) FROM alerts
             WHERE date(created_at / 1000, 'unixepoch', 'localtime') = ?1
               AND NOT (rule_id = 'unmatched_system_effect'
                        AND evidence LIKE '%\"source\":\"macos-endpoint-security\"%')
             GROUP BY action ORDER BY COUNT(*) DESC, action",
        )?;
        let alerts_by_severity = grouped(
            "SELECT severity, COUNT(*) FROM alerts
             WHERE date(created_at / 1000, 'unixepoch', 'localtime') = ?1
               AND NOT (rule_id = 'unmatched_system_effect'
                        AND evidence LIKE '%\"source\":\"macos-endpoint-security\"%')
             GROUP BY severity ORDER BY COUNT(*) DESC, severity",
        )?;

        let mut result = totals.as_object().cloned().unwrap_or_default();
        result.insert("date".to_string(), json!(day));
        result.insert("top_tools".to_string(), json!(top_tools));
        result.insert("alerts_by_action".to_string(), json!(alerts_by_action));
        result.insert("alerts_by_severity".to_string(), json!(alerts_by_severity));
        Ok(Value::Object(result))
    }

    pub fn append_policy_alert(&self, alert: &PolicyAlert) -> io::Result<()> {
        self.with_sqlite_transaction(|db| {
            let session_id = alert.session_id.as_deref().unwrap_or(UNKNOWN_SESSION_ID);
            ensure_session(db, session_id, "policy", alert.observed_at_ms)?;
            let request_id = latest_or_create_request(db, session_id)?;
            insert_alert(
                db,
                AlertInput {
                    request_id: Some(request_id),
                    entity: None,
                    severity: &alert.severity,
                    action: &alert.action,
                    rule_id: &alert.rule_id,
                    message: &alert.message,
                    path: alert.path.as_deref(),
                    evidence: merge_alert_evidence(
                        alert.evidence.clone(),
                        alert.tool_use_id.as_deref(),
                    ),
                    created_at: to_i64(alert.observed_at_ms)?,
                },
            )?;
            if alert.rule_id == "policy_network_egress" {
                refresh_request_resource_rates(db, request_id)?;
            }
            Ok(())
        })
    }

    pub fn artifact_risk_tags_for_file_digest(
        &self,
        path: &str,
        digest: &str,
    ) -> io::Result<Vec<ArtifactRiskTagRecord>> {
        let db = self.sqlite_store()?;
        let Some(artifact) = db
            .artifact_by_kind_uri_digest("file", &file_uri(path), digest)
            .map_err(sqlite_error)?
        else {
            return Ok(Vec::new());
        };
        db.artifact_risk_tags_for_digest(artifact.artifact_id, digest)
            .map_err(sqlite_error)
    }

    pub fn artifact_observations_for_file_digest(
        &self,
        path: &str,
        digest: &str,
    ) -> io::Result<Vec<ArtifactObservationRecord>> {
        let db = self.sqlite_store()?;
        let Some(artifact) = db
            .artifact_by_kind_uri_digest("file", &file_uri(path), digest)
            .map_err(sqlite_error)?
        else {
            return Ok(Vec::new());
        };
        db.artifact_observations_for_digest(artifact.artifact_id, digest)
            .map_err(sqlite_error)
    }

    pub fn artifact_fact_for_file(&self, path: &str) -> io::Result<Option<ArtifactFactRecord>> {
        let db = self.sqlite_store()?;
        db.artifact_fact("file", &file_uri(path))
            .map_err(sqlite_error)
    }

    /// True if an alert with `rule_id` was already recorded for this session
    /// (e.g. a poisoned-memory finding earlier in the conversation).
    pub fn session_has_alert(&self, session_id: &str, rule_id: &str) -> io::Result<bool> {
        let db = self.sqlite_store()?;
        db.session_has_alert(session_id, rule_id)
            .map_err(sqlite_error)
    }

    pub fn session_alert_count(&self, session_id: &str, rule_id: &str) -> io::Result<u64> {
        let db = self.sqlite_store()?;
        db.session_alert_count(session_id, rule_id)
            .map_err(sqlite_error)
    }

    pub fn session_has_alert_evidence_string(
        &self,
        session_id: &str,
        rule_id: &str,
        evidence_key: &str,
        evidence_value: &str,
    ) -> io::Result<bool> {
        let db = self.sqlite_store()?;
        db.session_has_alert_evidence_string(session_id, rule_id, evidence_key, evidence_value)
            .map_err(sqlite_error)
    }

    pub fn session_agent_event_count(&self, session_id: &str, event_type: &str) -> io::Result<u64> {
        let db = self.sqlite_store()?;
        db.session_agent_event_count(session_id, event_type)
            .map_err(sqlite_error)
    }

    pub fn latest_request_resource_rates(
        &self,
        session_id: &str,
    ) -> io::Result<Option<(i64, f64, f64)>> {
        let db = self.sqlite_store()?;
        db.latest_request_for_session(session_id)
            .map(|request| {
                request.map(|request| {
                    (
                        request.request_id,
                        request.file_accessed_rate,
                        request.network_rate,
                    )
                })
            })
            .map_err(sqlite_error)
    }

    pub fn record_artifact_observation_and_tags(
        &self,
        observation: &ArtifactObservationInput,
        tags: &[ArtifactRiskTagInput],
    ) -> io::Result<()> {
        self.with_sqlite_transaction(|db| {
            let session_id = observation
                .session_id
                .as_deref()
                .unwrap_or(UNKNOWN_SESSION_ID);
            ensure_session(db, session_id, "policy", observation.observed_at_ms)?;
            let request_id = latest_or_create_request(db, session_id)?;
            let observed_at = to_i64(observation.observed_at_ms)?;
            let artifact_id = db
                .insert_artifact(&NewArtifact {
                    kind: "file".to_string(),
                    uri: file_uri(&observation.path),
                    digest: Some(observation.digest.clone()),
                    created_at: Some(observed_at),
                    updated_at: Some(observed_at),
                    metadata: Some(
                        json!({
                            "source": "preexec-content-inspection",
                            "content_truncated": observation.content_truncated,
                        })
                        .to_string(),
                    ),
                })
                .map_err(sqlite_error)?;
            db.insert_artifact_observation(&NewArtifactObservation {
                artifact_id,
                request_id: Some(request_id),
                agent_event_id: None,
                session_id: Some(session_id.to_string()),
                digest: observation.digest.clone(),
                size_bytes: observation.size_bytes,
                content_prefix: observation.content_prefix.clone(),
                content_truncated: observation.content_truncated,
                observed_at,
                evidence: observation.evidence.clone().map(|value| value.to_string()),
            })
            .map_err(sqlite_error)?;

            for tag in tags {
                db.insert_artifact_risk_tag(&NewArtifactRiskTag {
                    artifact_id,
                    digest: observation.digest.clone(),
                    rule_id: tag.rule_id.clone(),
                    severity: tag.severity.clone(),
                    action: tag.action.clone(),
                    message: tag.message.clone(),
                    path: tag.path.clone(),
                    confidence: tag.confidence,
                    source_request_id: Some(request_id),
                    source_event_id: None,
                    source_session_id: Some(session_id.to_string()),
                    observed_at,
                    evidence: tag.evidence.clone().map(|value| value.to_string()),
                })
                .map_err(sqlite_error)?;
            }

            let risk = strongest_artifact_risk(tags).map(|tag| ArtifactFactRisk {
                level: tag.severity.as_str(),
                rule_id: tag.rule_id.as_str(),
                digest: observation.digest.as_str(),
            });
            update_artifact_fact(
                db,
                ArtifactFactUpdate {
                    path: &observation.path,
                    artifact_id,
                    digest: Some(&observation.digest),
                    observed_at,
                    source: "artifact_content_inspection",
                    request_id: Some(request_id),
                    session_id: Some(session_id),
                    agent_event_id: None,
                    system_event_id: None,
                    mutating: observation.mutation,
                    agent_authored: observation.mutation && session_id != UNKNOWN_SESSION_ID,
                    unmatched_effect: false,
                    risk,
                    metadata: Some(json!({
                        "source": "artifact_content_inspection",
                        "content_truncated": observation.content_truncated,
                    })),
                },
            )?;

            Ok(())
        })
    }

    /// Verify the tamper-evident alert hash chain (T8). Returns the number of
    /// chained alerts checked and the first break (if any).
    pub fn verify_alert_chain(&self) -> io::Result<ChainVerification> {
        let db = self.sqlite_store()?;
        db.verify_alert_chain().map_err(sqlite_error)
    }

    /// Record a human review verdict on a shield decision. `human_verdict` is one
    /// of "agree" | "allow" | "deny"; `label` is the derived relationship
    /// ("confirmed" | "false_positive" | "false_negative" | "override").
    #[allow(clippy::too_many_arguments)]
    pub fn record_human_feedback(
        &self,
        event_key: Option<String>,
        tool_use_id: Option<String>,
        session_id: Option<String>,
        gensee_action: Option<String>,
        human_verdict: String,
        label: Option<String>,
        rule_id: Option<String>,
        path: Option<String>,
        note: Option<String>,
        observed_at_ms: u64,
    ) -> io::Result<i64> {
        let feedback = NewHumanFeedback {
            event_key,
            tool_use_id,
            session_id,
            gensee_action,
            human_verdict,
            label,
            rule_id,
            path,
            note,
            created_at: to_i64(observed_at_ms)?,
        };
        let db = self.sqlite_store()?;
        db.insert_human_feedback(&feedback).map_err(sqlite_error)
    }

    /// Most recent human feedback verdicts (newest first).
    pub fn human_feedback(&self, limit: i64) -> io::Result<Vec<HumanFeedbackRecord>> {
        let db = self.sqlite_store()?;
        db.recent_human_feedback(limit).map_err(sqlite_error)
    }

    fn sqlite_store(&self) -> io::Result<MutexGuard<'_, SqliteStore>> {
        Ok(self
            .sqlite
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()))
    }

    fn with_sqlite_transaction<T>(
        &self,
        operation: impl FnOnce(&SqliteStore) -> io::Result<T>,
    ) -> io::Result<T> {
        let db = self.sqlite_store()?;
        db.connection()
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(SqliteError::Database)
            .map_err(sqlite_error)?;

        let result = operation(&db);
        match result {
            Ok(value) => {
                if let Err(error) = db.connection().execute_batch("COMMIT") {
                    let _ = db.connection().execute_batch("ROLLBACK");
                    return Err(sqlite_error(SqliteError::Database(error)));
                }
                Ok(value)
            }
            Err(error) => {
                let _ = db.connection().execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    fn append_hook_event_database(&self, event: &AgentHookEvent) -> io::Result<()> {
        let session_id = event.session_id.as_deref().unwrap_or(UNKNOWN_SESSION_ID);
        // Transcript reads can be tens of megabytes. Prepare their incremental
        // state before BEGIN IMMEDIATE so dashboard readers and other hook
        // writers are never blocked on filesystem I/O. Token accounting is
        // best-effort: the Stop event remains durable if the transcript cannot
        // be read.
        let transcript_update: Option<TranscriptTokenUpdate> =
            if event.hook_event_name.as_deref() == Some("Stop") {
                event.transcript_path.as_deref().and_then(|path| {
                    self.prepare_transcript_token_update(
                        session_id,
                        &event.provider,
                        Path::new(path),
                        event.observed_at_ms,
                    )
                    .ok()
                    .flatten()
                })
            } else {
                None
            };
        self.with_sqlite_transaction(|db| {
            ensure_session(db, session_id, &event.provider, event.observed_at_ms)?;

            match event.hook_event_name.as_deref() {
                Some("UserPromptSubmit") => {
                    let request_id = db
                        .insert_request(&NewRequest {
                            session_id: session_id.to_string(),
                            original_user_prompt: text_from_raw_json(
                                &event.raw_json,
                                &["prompt", "user_prompt", "message"],
                            ),
                            final_response: None,
                            events: Some(event.raw_json.clone()),
                            file_accessed_rate: 0.0,
                            network_rate: 0.0,
                        })
                        .map_err(sqlite_error)?;
                    db.set_request_created_at(request_id, to_i64(event.observed_at_ms)?)
                        .map_err(sqlite_error)?;
                }
                Some("Stop") => {
                    let transcript_tokens = transcript_update.as_ref().and_then(|update| {
                        db.upsert_transcript_token_state(&update.record)
                            .ok()
                            .and(update.total)
                    });
                    let response = text_from_raw_json(&event.raw_json, &["last_assistant_message"]);
                    let request_id = if let Some(request) = db
                        .latest_request_for_session(session_id)
                        .map_err(sqlite_error)?
                    {
                        db.set_request_response(request.request_id, response.as_deref())
                            .map_err(sqlite_error)?;
                        request.request_id
                    } else {
                        let request_id = db
                            .insert_request(&NewRequest {
                                session_id: session_id.to_string(),
                                original_user_prompt: None,
                                final_response: response,
                                events: Some(event.raw_json.clone()),
                                file_accessed_rate: 0.0,
                                network_rate: 0.0,
                            })
                            .map_err(sqlite_error)?;
                        db.set_request_created_at(request_id, to_i64(event.observed_at_ms)?)
                            .map_err(sqlite_error)?;
                        request_id
                    };
                    db.complete_request_with_token_total(
                        request_id,
                        to_i64(event.observed_at_ms)?,
                        transcript_tokens,
                    )
                    .map_err(sqlite_error)?;
                }
                _ if is_agent_event(event) => {
                    let request_id = latest_or_create_request(db, session_id)?;
                    let agent_event = NewAgentEvent {
                        pid: i64::from(std::process::id()),
                        request_id,
                        ts: to_i64(event.observed_at_ms)?,
                        source: event.provider.clone(),
                        event_type: event
                            .hook_event_name
                            .clone()
                            .unwrap_or_else(|| "tool_event".to_string()),
                        cwd: event.cwd.clone().unwrap_or_default(),
                        permission_mode: event.permission_mode.clone(),
                        tool_name: event.tool_name.clone(),
                        tool_input: tool_input_json(event),
                        tool_response: tool_response_json(event),
                        tool_use_id: event.tool_use_id.clone(),
                    };
                    let event_id = db.insert_agent_event(&agent_event).map_err(sqlite_error)?;
                    record_native_tool_artifact(db, request_id, event_id, event)?;
                    refresh_request_resource_rates(db, request_id)?;
                }
                _ => {}
            }

            Ok(())
        })
    }

    fn prepare_transcript_token_update(
        &self,
        session_id: &str,
        provider: &str,
        path: &Path,
        observed_at_ms: u64,
    ) -> io::Result<Option<TranscriptTokenUpdate>> {
        let Some(canonical) = allowed_transcript_path(provider, path)? else {
            return Ok(None);
        };
        let canonical_text = canonical.to_string_lossy().into_owned();
        let persisted = self
            .sqlite_store()?
            .transcript_token_state(session_id, &canonical_text)
            .map_err(sqlite_error)?;
        let mut state = persisted
            .as_ref()
            .and_then(|record| serde_json::from_str(&record.state_json).ok())
            .unwrap_or_default();
        let total = transcript_total_tokens_with_state(&canonical, &mut state)?;
        Ok(Some(TranscriptTokenUpdate {
            total,
            record: TranscriptTokenStateRecord {
                session_id: session_id.to_string(),
                transcript_path: canonical_text,
                state_json: serde_json::to_string(&state).map_err(io::Error::other)?,
                updated_at: to_i64(observed_at_ms)?,
            },
        }))
    }

    #[cfg(test)]
    fn transcript_total_tokens_at_path(
        &self,
        db: &SqliteStore,
        session_id: &str,
        canonical: &Path,
        observed_at_ms: u64,
    ) -> io::Result<Option<i64>> {
        let canonical_text = canonical.to_string_lossy().into_owned();
        let persisted = db
            .transcript_token_state(session_id, &canonical_text)
            .map_err(sqlite_error)?;
        let mut state = persisted
            .as_ref()
            .and_then(|record| serde_json::from_str(&record.state_json).ok())
            .unwrap_or_default();
        let total = transcript_total_tokens_with_state(canonical, &mut state)?;
        db.upsert_transcript_token_state(&TranscriptTokenStateRecord {
            session_id: session_id.to_string(),
            transcript_path: canonical_text,
            state_json: serde_json::to_string(&state).map_err(io::Error::other)?,
            updated_at: to_i64(observed_at_ms)?,
        })
        .map_err(sqlite_error)?;
        Ok(total)
    }

    fn append_process_observation_database(
        &self,
        observation: &ProcessObservation,
    ) -> io::Result<()> {
        self.with_sqlite_transaction(|db| {
            let session_id = observation
                .session_id
                .as_deref()
                .unwrap_or(SYSTEM_SESSION_ID);
            ensure_session(
                db,
                session_id,
                &observation.provider,
                observation.observed_at_ms,
            )?;
            let request_id = latest_or_create_request(db, session_id)?;
            db.insert_system_event(&NewSystemEvent {
                pid: i64::from(observation.pid),
                request_id,
                ts: to_i64(observation.observed_at_ms)?,
                source: observation.provider.clone(),
                event_type: "process_observation".to_string(),
                cwd: String::new(),
                args: Some(json_record(observation)?),
            })
            .map(|_| ())
            .map_err(sqlite_error)
        })
    }

    fn append_file_intent_database(&self, intent: &FileIntent) -> io::Result<()> {
        self.with_sqlite_transaction(|db| {
            let session_id = intent.session_id.as_deref().unwrap_or(UNKNOWN_SESSION_ID);
            ensure_session(db, session_id, &intent.provider, intent.observed_at_ms)?;
            let request_id = latest_or_create_request(db, session_id)?;
            let event_id = db
                .insert_agent_event(&NewAgentEvent {
                    pid: i64::from(std::process::id()),
                    request_id,
                    ts: to_i64(intent.observed_at_ms)?,
                    source: intent.provider.clone(),
                    event_type: "file_intent".to_string(),
                    cwd: String::new(),
                    permission_mode: None,
                    tool_name: Some("Bash".to_string()),
                    tool_input: Some(json_record(intent)?),
                    tool_response: None,
                    tool_use_id: intent.tool_use_id.clone(),
                })
                .map_err(sqlite_error)?;
            record_file_intent_artifact(db, request_id, event_id, intent)?;
            if intent.provider != "bash-command-parser" {
                record_file_operation_alerts(
                    db,
                    request_id,
                    Some(EntityRef::agent_event(event_id)),
                    &intent.operation,
                    &intent.path,
                    Some(json!({
                        "source": intent.provider,
                        "tool_use_id": intent.tool_use_id,
                        "confidence": intent.confidence,
                        "sensitive": intent.sensitive,
                    })),
                    to_i64(intent.observed_at_ms)?,
                )?;
            }
            refresh_request_resource_rates(db, request_id)?;
            Ok(())
        })
    }

    fn append_system_event_database(&self, event: &SystemEvent) -> io::Result<()> {
        self.with_sqlite_transaction(|db| {
            let ts = to_i64(event.observed_at_ms)?;
            let matched_agent_event = agent_event_for_system_event(db, event, ts)?;
            let endpoint_session_id = endpoint_security_session_id(event);
            let request_id = if let Some(session_id) = endpoint_session_id.as_deref() {
                ensure_session(
                    db,
                    session_id,
                    "macos-endpoint-security",
                    event.observed_at_ms,
                )?;
                latest_or_create_request(db, session_id)?
            } else if let Some(agent_event) = &matched_agent_event {
                agent_event.request_id
            } else {
                system_request_id(db, event.observed_at_ms)?
            };

            let event_id = db
                .insert_system_event(&NewSystemEvent {
                    pid: event.pid.map(i64::from).unwrap_or(0),
                    request_id,
                    ts,
                    source: event.source.clone(),
                    event_type: event.event_type.clone(),
                    cwd: String::new(),
                    args: Some(event.raw_json.clone()),
                })
                .map_err(sqlite_error)?;
            let process_tree_matched = endpoint_session_id.is_some();
            let matched = matched_agent_event.is_some() || process_tree_matched;
            if let Some(agent_event) = matched_agent_event {
                insert_entity_relation(
                    db,
                    EntityRef::agent_event(agent_event.event_id),
                    EntityRef::system_event(event_id),
                    "caused",
                    0.75,
                    Some(json!({
                        "matched_by": "file_intent_path",
                        "system_event_type": event.event_type,
                        "time_delta_ms": (ts - agent_event.ts).abs(),
                    })),
                    ts,
                )?;
            }
            if process_tree_matched {
                insert_entity_relation(
                    db,
                    EntityRef::request(request_id),
                    EntityRef::system_event(event_id),
                    "observed",
                    1.0,
                    Some(json!({
                        "matched_by": "endpoint_security_process_tree",
                        "session_id": endpoint_session_id,
                        "system_event_type": event.event_type,
                    })),
                    ts,
                )?;
            }
            record_system_event_artifacts(db, request_id, event_id, event, ts, matched)?;
            if !matched && event.source != "macos-endpoint-security" {
                record_unmatched_system_event_alert(db, request_id, event_id, event, ts)?;
            }

            Ok(())
        })
    }

    fn append_workspace_effect_database(&self, effect: &WorkspaceEffect) -> io::Result<()> {
        self.with_sqlite_transaction(|db| {
            let session_id = effect.session_id.as_deref().unwrap_or(SYSTEM_SESSION_ID);
            ensure_session(db, session_id, &effect.source, effect.observed_at_ms)?;
            let request_id = latest_or_create_request(db, session_id)?;
            let ts = to_i64(effect.observed_at_ms)?;
            let matched_agent_event = agent_event_for_path(db, &effect.path, ts)?;
            let event_id = db
                .insert_system_event(&NewSystemEvent {
                    pid: 0,
                    request_id,
                    ts,
                    source: effect.source.clone(),
                    event_type: effect.effect_type.clone(),
                    cwd: effect.workspace.clone(),
                    args: Some(json_record(effect)?),
                })
                .map_err(sqlite_error)?;
            let artifact_id = upsert_file_artifact(
                db,
                &effect.path,
                ts,
                Some(json!({
                    "source": effect.source,
                    "confidence": effect.confidence,
                    "attribution": effect.attribution,
                })),
            )?;
            insert_entity_relation(
                db,
                EntityRef::system_event(event_id),
                EntityRef::artifact(artifact_id),
                system_artifact_relation_type(&effect.effect_type),
                0.5,
                Some(json!({ "matched_by": "workspace_effect" })),
                ts,
            )?;
            if let Some(agent_event) = &matched_agent_event {
                insert_entity_relation(
                    db,
                    EntityRef::agent_event(agent_event.event_id),
                    EntityRef::system_event(event_id),
                    "caused",
                    0.6,
                    Some(json!({
                        "matched_by": "workspace_effect_file_intent_path",
                        "system_event_type": effect.effect_type,
                        "time_delta_ms": (ts - agent_event.ts).abs(),
                    })),
                    ts,
                )?;
            }
            record_request_artifact_relation(
                db,
                request_id,
                artifact_id,
                request_artifact_relation_type(&effect.effect_type),
                0.5,
                Some(json!({ "source": effect.source })),
                ts,
            )?;
            let request_relation = request_artifact_relation_type(&effect.effect_type);
            let unmatched_effect = matched_agent_event.is_none()
                && matches!(request_relation, "produced" | "modified" | "deleted");
            update_artifact_fact(
                db,
                ArtifactFactUpdate {
                    path: &effect.path,
                    artifact_id,
                    digest: None,
                    observed_at: ts,
                    source: &effect.source,
                    request_id: Some(request_id),
                    session_id: Some(session_id),
                    agent_event_id: None,
                    system_event_id: Some(event_id),
                    mutating: matches!(request_relation, "produced" | "modified" | "deleted"),
                    agent_authored: false,
                    unmatched_effect,
                    risk: None,
                    metadata: Some(json!({
                        "source": effect.source,
                        "confidence": effect.confidence,
                        "attribution": effect.attribution,
                        "effect_type": effect.effect_type,
                        "matched_agent_intent": matched_agent_event.is_some(),
                    })),
                },
            )?;
            record_file_operation_alerts(
                db,
                request_id,
                Some(EntityRef::system_event(event_id)),
                &effect.effect_type,
                &effect.path,
                Some(json!({
                    "source": effect.source,
                    "confidence": effect.confidence,
                    "attribution": effect.attribution,
                })),
                to_i64(effect.observed_at_ms)?,
            )
        })
    }
}

fn database_path_for_root(root: &Path) -> PathBuf {
    root.join("gensee.db")
}

/// Resolve the Gensee data root (`GENSEE_HOME`, else `~/.gensee`) WITHOUT opening
/// the store. Lets the hook client find the daemon socket cheaply before
/// deciding whether to fall back to the in-process path.
pub fn default_root() -> io::Result<PathBuf> {
    if let Some(root) = env::var_os("GENSEE_HOME") {
        return Ok(PathBuf::from(root));
    }
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    Ok(home.join(".gensee"))
}

/// Unix socket path the daemon listens on for hook events.
pub fn daemon_socket_path(root: &Path) -> PathBuf {
    root.join("gensee.sock")
}

fn sqlite_config_for_root(root: &Path, encryption_key: Option<&[u8; 32]>) -> SqliteConfig {
    SqliteConfig {
        path: database_path_for_root(root).to_string_lossy().to_string(),
        journal_mode: "wal".to_string(),
        synchronous: "normal".to_string(),
        auto_vacuum: "full".to_string(),
        shared_cache: false,
        cipher_key: encryption_key.map(|key| hex_encode(key)),
    }
}

fn ensure_session(
    db: &SqliteStore,
    session_id: &str,
    agent_id: &str,
    observed_at_ms: u64,
) -> io::Result<()> {
    if db.get_session(session_id).map_err(sqlite_error)?.is_some() {
        return Ok(());
    }

    db.insert_session(&NewSession {
        session_id: session_id.to_string(),
        agent_id: agent_id.to_string(),
        root_pid: 0,
        first_event_at: to_i64(observed_at_ms)?,
        last_event_at: None,
        flagged: false,
    })
    .map_err(sqlite_error)
}

/// Read only numeric usage metadata from a supported JSONL transcript. Claude
/// emits usage per assistant message (sometimes repeating a message while it is
/// streaming), while Codex emits a cumulative `total_token_usage` snapshot.
/// Prompt and response content is never persisted by this path.
#[cfg(test)]
fn transcript_total_tokens(path: &Path) -> io::Result<Option<i64>> {
    transcript_total_tokens_cached(path, &mut HashMap::new())
}

fn allowed_transcript_path(provider: &str, path: &Path) -> io::Result<Option<PathBuf>> {
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let claude_config = env::var_os("CLAUDE_CONFIG_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let codex_home = env::var_os("CODEX_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let Some(allowed_root) = transcript_root(provider, home, claude_config, codex_home) else {
        return Ok(None);
    };
    let Ok(allowed_root) = allowed_root.canonicalize() else {
        return Ok(None);
    };
    let Ok(canonical) = path.canonicalize() else {
        return Ok(None);
    };
    Ok(canonical.starts_with(&allowed_root).then_some(canonical))
}

fn transcript_root(
    provider: &str,
    home: Option<PathBuf>,
    claude_config: Option<PathBuf>,
    codex_home: Option<PathBuf>,
) -> Option<PathBuf> {
    match provider {
        "claude-code" => claude_config
            .or_else(|| home.map(|home| home.join(".claude")))
            .map(|root| root.join("projects")),
        "codex" => codex_home
            .or_else(|| home.map(|home| home.join(".codex")))
            .map(|root| root.join("sessions")),
        _ => None,
    }
}

#[cfg(test)]
fn transcript_total_tokens_cached(
    path: &Path,
    cache: &mut HashMap<PathBuf, TranscriptTokenState>,
) -> io::Result<Option<i64>> {
    let state = cache.entry(path.to_path_buf()).or_default();
    transcript_total_tokens_with_state(path, state)
}

fn transcript_total_tokens_with_state(
    path: &Path,
    state: &mut TranscriptTokenState,
) -> io::Result<Option<i64>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_TOKEN_TRANSCRIPT_BYTES {
        return Ok(None);
    }

    #[cfg(unix)]
    let identity_changed =
        state.offset > 0 && (state.device != metadata.dev() || state.inode != metadata.ino());
    #[cfg(not(unix))]
    let identity_changed = false;
    if identity_changed || metadata.len() < state.offset {
        *state = TranscriptTokenState::default();
    }
    #[cfg(unix)]
    {
        state.device = metadata.dev();
        state.inode = metadata.ino();
    }

    if metadata.len() > state.offset {
        let mut file = fs::File::open(path)?;
        file.seek(SeekFrom::Start(state.offset))?;
        let mut appended = Vec::new();
        file.read_to_end(&mut appended)?;

        let complete_len = appended
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map(|index| index + 1)
            .or_else(|| {
                serde_json::from_slice::<Value>(&appended)
                    .ok()
                    .map(|_| appended.len())
            })
            .unwrap_or(0);
        for line in String::from_utf8_lossy(&appended[..complete_len]).lines() {
            process_transcript_usage_line(line, state);
        }
        state.offset += complete_len as u64;
    }

    let total = state
        .codex_total
        .max(state.claude_messages.values().sum::<i64>());
    Ok((total > 0).then_some(total))
}

fn process_transcript_usage_line(line: &str, state: &mut TranscriptTokenState) {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return;
    };
    if let Some(total) = value
        .pointer("/payload/info/total_token_usage/total_tokens")
        .and_then(Value::as_i64)
    {
        state.codex_total = state.codex_total.max(total);
    }

    let Some(message_id) = value.pointer("/message/id").and_then(Value::as_str) else {
        return;
    };
    let Some(usage) = value.pointer("/message/usage") else {
        return;
    };
    let total = [
        "input_tokens",
        "output_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    ]
    .into_iter()
    .filter_map(|key| usage.get(key).and_then(Value::as_i64))
    .sum::<i64>();
    if total > 0 {
        state
            .claude_messages
            .entry(message_id.to_string())
            .and_modify(|stored| *stored = (*stored).max(total))
            .or_insert(total);
    }
}

fn latest_or_create_request(db: &SqliteStore, session_id: &str) -> io::Result<i64> {
    if let Some(request) = db
        .latest_request_for_session(session_id)
        .map_err(sqlite_error)?
    {
        return Ok(request.request_id);
    }

    db.insert_request(&NewRequest {
        session_id: session_id.to_string(),
        original_user_prompt: None,
        final_response: None,
        events: Some("{}".to_string()),
        file_accessed_rate: 0.0,
        network_rate: 0.0,
    })
    .map_err(sqlite_error)
}

fn refresh_request_resource_rates(db: &SqliteStore, request_id: i64) -> io::Result<()> {
    let file_accessed_rate = db
        .request_file_access_rate_per_minute(request_id)
        .map_err(sqlite_error)?;
    let network_rate = db
        .request_alert_rate_per_minute(request_id, "policy_network_egress")
        .map_err(sqlite_error)?;
    db.set_request_resource_rates(request_id, file_accessed_rate, network_rate)
        .map_err(sqlite_error)
}

fn system_request_id(db: &SqliteStore, observed_at_ms: u64) -> io::Result<i64> {
    ensure_session(db, SYSTEM_SESSION_ID, SYSTEM_AGENT_ID, observed_at_ms)?;
    latest_or_create_request(db, SYSTEM_SESSION_ID)
}

fn agent_event_for_system_event(
    db: &SqliteStore,
    event: &SystemEvent,
    ts: i64,
) -> io::Result<Option<AgentEventRecord>> {
    for path in system_event_paths(event) {
        if let Some(agent_event) = agent_event_for_path(db, &path, ts)? {
            return Ok(Some(agent_event));
        }
    }

    Ok(None)
}

fn agent_event_for_path(
    db: &SqliteStore,
    path: &str,
    ts: i64,
) -> io::Result<Option<AgentEventRecord>> {
    let mut paths = BTreeSet::new();
    add_path_variants(path, &mut paths);
    for candidate in paths {
        if let Some(agent_event) = db
            .request_for_file_intent_path(&candidate, ts, SYSTEM_EVENT_CORRELATION_WINDOW_MS)
            .map_err(sqlite_error)?
        {
            return Ok(Some(agent_event));
        }
    }
    Ok(None)
}

#[derive(Clone, Copy)]
struct EntityRef {
    kind: &'static str,
    id: i64,
}

impl EntityRef {
    fn request(id: i64) -> Self {
        Self {
            kind: "request",
            id,
        }
    }

    fn agent_event(id: i64) -> Self {
        Self {
            kind: "agent_event",
            id,
        }
    }

    fn system_event(id: i64) -> Self {
        Self {
            kind: "system_event",
            id,
        }
    }

    fn artifact(id: i64) -> Self {
        Self {
            kind: "artifact",
            id,
        }
    }
}

fn insert_entity_relation(
    db: &SqliteStore,
    src: EntityRef,
    dst: EntityRef,
    relation_type: &str,
    confidence: f64,
    evidence: Option<Value>,
    created_at: i64,
) -> io::Result<()> {
    db.insert_relation(&NewRelation {
        src_kind: src.kind.to_string(),
        src_id: src.id,
        dst_kind: dst.kind.to_string(),
        dst_id: dst.id,
        relation_type: relation_type.to_string(),
        confidence,
        evidence: evidence.map(|value| value.to_string()),
        created_at,
    })
    .map(|_| ())
    .map_err(sqlite_error)
}

fn insert_alert(db: &SqliteStore, input: AlertInput<'_>) -> io::Result<()> {
    db.insert_alert(&NewAlert {
        request_id: input.request_id,
        entity_kind: input.entity.map(|entity| entity.kind.to_string()),
        entity_id: input.entity.map(|entity| entity.id),
        severity: input.severity.to_string(),
        action: input.action.to_string(),
        rule_id: input.rule_id.to_string(),
        message: input.message.to_string(),
        path: input.path.map(str::to_string),
        evidence: input.evidence.map(|value| value.to_string()),
        created_at: input.created_at,
    })
    .map(|_| ())
    .map_err(sqlite_error)
}

fn merge_alert_evidence(evidence: Option<Value>, tool_use_id: Option<&str>) -> Option<Value> {
    match (evidence, tool_use_id) {
        (Some(Value::Object(mut map)), Some(tool_use_id)) => {
            map.insert(
                "tool_use_id".to_string(),
                Value::String(tool_use_id.to_string()),
            );
            Some(Value::Object(map))
        }
        (Some(value), Some(tool_use_id)) => Some(json!({
            "details": value,
            "tool_use_id": tool_use_id,
        })),
        (None, Some(tool_use_id)) => Some(json!({ "tool_use_id": tool_use_id })),
        (evidence, None) => evidence,
    }
}

struct ArtifactFactUpdate<'a> {
    path: &'a str,
    artifact_id: i64,
    digest: Option<&'a str>,
    observed_at: i64,
    source: &'a str,
    request_id: Option<i64>,
    session_id: Option<&'a str>,
    agent_event_id: Option<i64>,
    system_event_id: Option<i64>,
    mutating: bool,
    agent_authored: bool,
    unmatched_effect: bool,
    risk: Option<ArtifactFactRisk<'a>>,
    metadata: Option<Value>,
}

struct ArtifactFactRisk<'a> {
    level: &'a str,
    rule_id: &'a str,
    digest: &'a str,
}

fn strongest_artifact_risk(tags: &[ArtifactRiskTagInput]) -> Option<&ArtifactRiskTagInput> {
    tags.iter()
        .max_by_key(|tag| (severity_rank(&tag.severity), action_rank(&tag.action)))
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn action_rank(action: &str) -> u8 {
    match action {
        "block" => 3,
        "ask" => 2,
        "warn" => 1,
        _ => 0,
    }
}

fn update_artifact_fact(db: &SqliteStore, update: ArtifactFactUpdate<'_>) -> io::Result<()> {
    let policy = Policy::global();
    let uri = file_uri(update.path);
    let existing = db.artifact_fact("file", &uri).map_err(sqlite_error)?;
    let fresh_existing = existing.as_ref().filter(|fact| {
        update.observed_at.saturating_sub(fact.last_seen_at) <= ARTIFACT_FACT_RECENT_WINDOW_MS
    });

    let mut recent_unmatched = fresh_existing
        .map(|fact| fact.recent_unmatched_effect_count)
        .unwrap_or(0);
    let mut recent_cross_session = fresh_existing
        .map(|fact| fact.recent_cross_session_write_count)
        .unwrap_or(0);
    if update.mutating && update.unmatched_effect {
        recent_unmatched += 1;
    }
    if update.mutating && update.agent_authored {
        if let (Some(previous), Some(current)) = (
            fresh_existing.and_then(|fact| fact.last_modified_session_id.as_deref()),
            update.session_id,
        ) {
            if previous != current {
                recent_cross_session += 1;
            }
        }
    }

    let previous = existing.as_ref();
    let last_modified_at = if update.mutating {
        Some(update.observed_at)
    } else {
        previous.and_then(|fact| fact.last_modified_at)
    };
    let last_modified_source = if update.mutating {
        Some(update.source.to_string())
    } else {
        previous.and_then(|fact| fact.last_modified_source.clone())
    };
    let last_modified_request_id = if update.mutating && update.agent_authored {
        update.request_id
    } else {
        previous.and_then(|fact| fact.last_modified_request_id)
    };
    let last_modified_session_id = if update.mutating && update.agent_authored {
        update.session_id.map(str::to_string)
    } else {
        previous.and_then(|fact| fact.last_modified_session_id.clone())
    };
    let last_system_event_id = update
        .system_event_id
        .or_else(|| previous.and_then(|fact| fact.last_system_event_id));
    let last_agent_event_id = update
        .agent_event_id
        .or_else(|| previous.and_then(|fact| fact.last_agent_event_id));

    let previous_recent = fresh_existing;
    let risk_level = update
        .risk
        .as_ref()
        .map(|risk| risk.level.to_string())
        .or_else(|| previous_recent.and_then(|fact| fact.risk_level.clone()));
    let risk_rule_id = update
        .risk
        .as_ref()
        .map(|risk| risk.rule_id.to_string())
        .or_else(|| previous_recent.and_then(|fact| fact.risk_rule_id.clone()));
    let risk_digest = update
        .risk
        .as_ref()
        .map(|risk| risk.digest.to_string())
        .or_else(|| previous_recent.and_then(|fact| fact.risk_digest.clone()));
    let risk_updated_at = if update.risk.is_some() {
        Some(update.observed_at)
    } else {
        previous_recent.and_then(|fact| fact.risk_updated_at)
    };

    db.upsert_artifact_fact(&NewArtifactFact {
        kind: "file".to_string(),
        uri,
        current_artifact_id: Some(update.artifact_id),
        current_digest: update
            .digest
            .map(str::to_string)
            .or_else(|| previous.and_then(|fact| fact.current_digest.clone())),
        last_seen_at: update.observed_at,
        last_modified_at,
        last_modified_source,
        last_modified_request_id,
        last_modified_session_id,
        last_system_event_id,
        last_agent_event_id,
        recent_unmatched_effect_count: recent_unmatched,
        recent_cross_session_write_count: recent_cross_session,
        is_agent_authored: previous.is_some_and(|fact| fact.is_agent_authored)
            || update.agent_authored,
        is_unmatched_modified: previous_recent.is_some_and(|fact| fact.is_unmatched_modified)
            || (update.mutating && update.unmatched_effect),
        is_memory_artifact: policy.is_memory_artifact_path(update.path),
        is_persistent_target: policy.is_persistent_target_path(update.path),
        is_control_plane: policy.is_control_plane_path(update.path),
        risk_level,
        risk_rule_id,
        risk_digest,
        risk_updated_at,
        metadata: update.metadata.map(|value| value.to_string()),
    })
    .map_err(sqlite_error)
}

fn record_file_intent_artifact(
    db: &SqliteStore,
    request_id: i64,
    agent_event_id: i64,
    intent: &FileIntent,
) -> io::Result<()> {
    let ts = to_i64(intent.observed_at_ms)?;
    let artifact_id = upsert_file_artifact(
        db,
        &intent.path,
        ts,
        Some(json!({
            "operation": intent.operation,
            "source": intent.provider,
            "tool_use_id": intent.tool_use_id,
            "sensitive": intent.sensitive,
            "confidence": intent.confidence,
        })),
    )?;

    let access = artifact_access(&intent.operation);
    match access {
        ArtifactAccess::Consumed => {
            insert_entity_relation(
                db,
                EntityRef::artifact(artifact_id),
                EntityRef::agent_event(agent_event_id),
                "consumed_by",
                0.8,
                Some(json!({ "operation": intent.operation })),
                ts,
            )?;
            record_request_artifact_relation(
                db,
                request_id,
                artifact_id,
                "consumed_by",
                0.8,
                Some(json!({ "operation": intent.operation })),
                ts,
            )?;
        }
        ArtifactAccess::Produced | ArtifactAccess::Modified | ArtifactAccess::Deleted => {
            let relation_type = match access {
                ArtifactAccess::Produced => "produced",
                ArtifactAccess::Modified => "modified",
                ArtifactAccess::Deleted => "deleted",
                ArtifactAccess::Consumed => unreachable!(),
            };
            insert_entity_relation(
                db,
                EntityRef::agent_event(agent_event_id),
                EntityRef::artifact(artifact_id),
                relation_type,
                0.8,
                Some(json!({ "operation": intent.operation })),
                ts,
            )?;
            record_request_artifact_relation(
                db,
                request_id,
                artifact_id,
                relation_type,
                0.8,
                Some(json!({ "operation": intent.operation })),
                ts,
            )?;
        }
    }
    update_artifact_fact(
        db,
        ArtifactFactUpdate {
            path: &intent.path,
            artifact_id,
            digest: None,
            observed_at: ts,
            source: &intent.provider,
            request_id: Some(request_id),
            session_id: intent.session_id.as_deref(),
            agent_event_id: Some(agent_event_id),
            system_event_id: None,
            mutating: access != ArtifactAccess::Consumed,
            agent_authored: true,
            unmatched_effect: false,
            risk: None,
            metadata: Some(json!({
                "source": intent.provider,
                "operation": intent.operation,
                "tool_use_id": intent.tool_use_id,
            })),
        },
    )?;

    Ok(())
}

fn record_native_tool_artifact(
    db: &SqliteStore,
    request_id: i64,
    agent_event_id: i64,
    event: &AgentHookEvent,
) -> io::Result<()> {
    if event.hook_event_name.as_deref() != Some("PreToolUse") {
        return Ok(());
    }
    let tools = native_file_tools(event);
    if tools.is_empty() {
        return Ok(());
    }

    let ts = to_i64(event.observed_at_ms)?;
    for tool in tools {
        let artifact_id = upsert_file_artifact(
            db,
            &tool.path,
            ts,
            Some(json!({
                "operation": tool.operation,
                "source": event.provider,
                "tool_name": event.tool_name,
                "tool_use_id": event.tool_use_id,
            })),
        )?;

        let access = artifact_access(&tool.operation);
        match access {
            ArtifactAccess::Consumed => {
                insert_entity_relation(
                    db,
                    EntityRef::artifact(artifact_id),
                    EntityRef::agent_event(agent_event_id),
                    "consumed_by",
                    0.9,
                    Some(json!({ "operation": tool.operation, "tool_name": event.tool_name })),
                    ts,
                )?;
                record_request_artifact_relation(
                    db,
                    request_id,
                    artifact_id,
                    "consumed_by",
                    0.9,
                    Some(json!({ "operation": tool.operation, "tool_name": event.tool_name })),
                    ts,
                )?;
            }
            ArtifactAccess::Produced | ArtifactAccess::Modified | ArtifactAccess::Deleted => {
                let relation_type = match access {
                    ArtifactAccess::Produced => "produced",
                    ArtifactAccess::Modified => "modified",
                    ArtifactAccess::Deleted => "deleted",
                    ArtifactAccess::Consumed => unreachable!(),
                };
                insert_entity_relation(
                    db,
                    EntityRef::agent_event(agent_event_id),
                    EntityRef::artifact(artifact_id),
                    relation_type,
                    0.9,
                    Some(json!({ "operation": tool.operation, "tool_name": event.tool_name })),
                    ts,
                )?;
                record_request_artifact_relation(
                    db,
                    request_id,
                    artifact_id,
                    relation_type,
                    0.9,
                    Some(json!({ "operation": tool.operation, "tool_name": event.tool_name })),
                    ts,
                )?;
            }
        }

        if should_record_native_tool_file_alert(&event.provider) {
            record_file_operation_alerts(
                db,
                request_id,
                Some(EntityRef::agent_event(agent_event_id)),
                &tool.operation,
                &tool.path,
                Some(json!({
                    "source": event.provider,
                    "tool_name": event.tool_name,
                    "tool_use_id": event.tool_use_id,
                })),
                ts,
            )?;
        }
        update_artifact_fact(
            db,
            ArtifactFactUpdate {
                path: &tool.path,
                artifact_id,
                digest: None,
                observed_at: ts,
                source: &event.provider,
                request_id: Some(request_id),
                session_id: event.session_id.as_deref(),
                agent_event_id: Some(agent_event_id),
                system_event_id: None,
                mutating: access != ArtifactAccess::Consumed,
                agent_authored: true,
                unmatched_effect: false,
                risk: None,
                metadata: Some(json!({
                    "source": event.provider,
                    "operation": tool.operation,
                    "tool_name": event.tool_name,
                    "tool_use_id": event.tool_use_id,
                })),
            },
        )?;
    }

    Ok(())
}

fn should_record_native_tool_file_alert(provider: &str) -> bool {
    !matches!(provider, "claude-code" | "codex")
}

fn record_request_artifact_relation(
    db: &SqliteStore,
    request_id: i64,
    artifact_id: i64,
    relation_type: &str,
    confidence: f64,
    evidence: Option<Value>,
    created_at: i64,
) -> io::Result<()> {
    match relation_type {
        "consumed_by" => {
            if request_has_output_artifact(db, request_id, artifact_id)? {
                return Ok(());
            }
            insert_entity_relation(
                db,
                EntityRef::artifact(artifact_id),
                EntityRef::request(request_id),
                "consumed_by",
                confidence,
                evidence,
                created_at,
            )?;
            if !is_human_request(db, request_id)? {
                return Ok(());
            }
            for produced_artifact_id in db
                .produced_artifact_ids_for_request(request_id)
                .map_err(sqlite_error)?
            {
                record_artifact_derivation(
                    db,
                    artifact_id,
                    produced_artifact_id,
                    request_id,
                    confidence,
                    created_at,
                )?;
            }
            for producer_request_id in db
                .producer_request_ids_for_artifact(artifact_id)
                .map_err(sqlite_error)?
            {
                if producer_request_id != request_id {
                    insert_entity_relation(
                        db,
                        EntityRef::request(producer_request_id),
                        EntityRef::request(request_id),
                        "derived_from",
                        confidence,
                        Some(json!({ "artifact_id": artifact_id })),
                        created_at,
                    )?;
                }
            }
        }
        "produced" | "modified" | "deleted" => {
            insert_entity_relation(
                db,
                EntityRef::request(request_id),
                EntityRef::artifact(artifact_id),
                relation_type,
                confidence,
                evidence,
                created_at,
            )?;
            for consumed_artifact_id in db
                .consumed_artifact_ids_for_request(request_id)
                .map_err(sqlite_error)?
            {
                record_artifact_derivation(
                    db,
                    consumed_artifact_id,
                    artifact_id,
                    request_id,
                    confidence,
                    created_at,
                )?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn request_has_output_artifact(
    db: &SqliteStore,
    request_id: i64,
    artifact_id: i64,
) -> io::Result<bool> {
    Ok(db
        .produced_artifact_ids_for_request(request_id)
        .map_err(sqlite_error)?
        .into_iter()
        .any(|produced_artifact_id| produced_artifact_id == artifact_id))
}

fn record_artifact_derivation(
    db: &SqliteStore,
    source_artifact_id: i64,
    derived_artifact_id: i64,
    request_id: i64,
    confidence: f64,
    created_at: i64,
) -> io::Result<()> {
    if source_artifact_id == derived_artifact_id {
        return Ok(());
    }

    insert_entity_relation(
        db,
        EntityRef::artifact(source_artifact_id),
        EntityRef::artifact(derived_artifact_id),
        "derived_from",
        confidence,
        Some(json!({
            "request_id": request_id,
            "reason": "request consumed source artifact and produced destination artifact",
        })),
        created_at,
    )
}

fn is_human_request(db: &SqliteStore, request_id: i64) -> io::Result<bool> {
    Ok(db
        .get_request(request_id)
        .map_err(sqlite_error)?
        .and_then(|request| request.original_user_prompt)
        .is_some_and(|prompt| !prompt.trim().is_empty()))
}

fn record_system_event_artifacts(
    db: &SqliteStore,
    request_id: i64,
    system_event_id: i64,
    event: &SystemEvent,
    ts: i64,
    matched_agent_intent: bool,
) -> io::Result<()> {
    let raw_event = serde_json::from_str::<Value>(&event.raw_json).ok();
    let modified = raw_event
        .as_ref()
        .and_then(|value| value.get("modified"))
        .and_then(Value::as_bool);
    let relation_type = system_artifact_relation_type_for_event(event);
    let request_relation_type = request_artifact_relation_type_for_event(event);
    for path in system_event_paths(event) {
        if !should_materialize_system_artifact(event, &path, raw_event.as_ref()) {
            continue;
        }
        let artifact_id = upsert_file_artifact(
            db,
            &path,
            ts,
            Some(json!({
                "source": event.source,
                "system_event_type": event.event_type,
                "system_event_kind": event.event_kind,
                "modified": modified,
            })),
        )?;
        match relation_type {
            "read_by" => insert_entity_relation(
                db,
                EntityRef::artifact(artifact_id),
                EntityRef::system_event(system_event_id),
                relation_type,
                0.7,
                Some(json!({ "matched_by": "system_event_path" })),
                ts,
            )?,
            _ => insert_entity_relation(
                db,
                EntityRef::system_event(system_event_id),
                EntityRef::artifact(artifact_id),
                relation_type,
                0.7,
                Some(json!({ "matched_by": "system_event_path" })),
                ts,
            )?,
        }
        record_request_artifact_relation(
            db,
            request_id,
            artifact_id,
            request_relation_type,
            0.7,
            Some(json!({ "source": event.source, "system_event_type": event.event_type })),
            ts,
        )?;
        update_artifact_fact(
            db,
            ArtifactFactUpdate {
                path: &path,
                artifact_id,
                digest: None,
                observed_at: ts,
                source: &event.source,
                request_id: Some(request_id),
                session_id: None,
                agent_event_id: None,
                system_event_id: Some(system_event_id),
                mutating: matches!(request_relation_type, "produced" | "modified" | "deleted"),
                agent_authored: false,
                unmatched_effect: !matched_agent_intent
                    && matches!(request_relation_type, "produced" | "modified" | "deleted"),
                risk: None,
                metadata: Some(json!({
                    "source": event.source,
                    "system_event_type": event.event_type,
                    "system_event_kind": event.event_kind,
                    "modified": modified,
                    "matched_agent_intent": matched_agent_intent,
                })),
            },
        )?;
    }

    Ok(())
}

fn record_file_operation_alerts(
    db: &SqliteStore,
    request_id: i64,
    entity: Option<EntityRef>,
    operation: &str,
    path: &str,
    evidence: Option<Value>,
    created_at: i64,
) -> io::Result<()> {
    // Passive risk findings over an observed artifact, evaluated by the shared
    // data-driven policy engine (same rules as the active PreToolUse path).
    for finding in Policy::global().evaluate_observation(operation, path) {
        insert_alert(
            db,
            AlertInput {
                request_id: Some(request_id),
                entity,
                severity: &finding.severity,
                action: finding.action.as_str(),
                rule_id: &finding.rule_id,
                message: &finding.message,
                path: finding.path.as_deref().or(Some(path)),
                evidence: merge_rule_evidence(evidence.clone(), operation),
                created_at,
            },
        )?;
    }

    Ok(())
}

fn record_unmatched_system_event_alert(
    db: &SqliteStore,
    request_id: i64,
    system_event_id: i64,
    event: &SystemEvent,
    created_at: i64,
) -> io::Result<()> {
    let request_relation = request_artifact_relation_type(&event.event_type);
    if !matches!(request_relation, "produced" | "modified" | "deleted") {
        return Ok(());
    }

    insert_alert(
        db,
        AlertInput {
            request_id: Some(request_id),
            entity: Some(EntityRef::system_event(system_event_id)),
            severity: "medium",
            action: "warn",
            rule_id: "unmatched_system_effect",
            message: "Filesystem effect was observed without a matching agent file intent",
            path: event.file_path.as_deref(),
            evidence: Some(json!({
                "source": event.source,
                "event_type": event.event_type,
                "event_kind": event.event_kind,
                "process_name": event.process_name,
            })),
            created_at,
        },
    )
}

fn merge_rule_evidence(evidence: Option<Value>, operation: &str) -> Option<Value> {
    match evidence {
        Some(Value::Object(mut map)) => {
            map.insert(
                "operation".to_string(),
                Value::String(operation.to_string()),
            );
            Some(Value::Object(map))
        }
        Some(value) => Some(json!({ "operation": operation, "details": value })),
        None => Some(json!({ "operation": operation })),
    }
}

fn upsert_file_artifact(
    db: &SqliteStore,
    path: &str,
    ts: i64,
    metadata: Option<Value>,
) -> io::Result<i64> {
    db.insert_artifact(&NewArtifact {
        kind: "file".to_string(),
        uri: file_uri(path),
        digest: None,
        created_at: Some(ts),
        updated_at: Some(ts),
        metadata: metadata.map(|value| value.to_string()),
    })
    .map_err(sqlite_error)
}

fn is_agent_event(event: &AgentHookEvent) -> bool {
    matches!(
        event.hook_event_name.as_deref(),
        Some("PreToolUse") | Some("PostToolUse")
    ) || event.tool_name.is_some()
        || event.tool_use_id.is_some()
}

fn text_from_raw_json(raw_json: &str, keys: &[&str]) -> Option<String> {
    let value = serde_json::from_str::<Value>(raw_json).ok()?;
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str).map(str::to_string))
}

fn endpoint_security_session_id(event: &SystemEvent) -> Option<String> {
    if event.source != "macos-endpoint-security" {
        return None;
    }
    serde_json::from_str::<Value>(&event.raw_json)
        .ok()?
        .get("attribution")?
        .get("session_id")?
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
}

fn system_event_paths(event: &SystemEvent) -> Vec<String> {
    let mut paths = BTreeSet::new();
    if let Some(path) = &event.file_path {
        add_path_variants(path, &mut paths);
    }

    if let Ok(value) = serde_json::from_str::<Value>(&event.raw_json) {
        collect_path_values(&value, &mut paths);
    }

    paths.into_iter().collect()
}

fn collect_path_values(value: &Value, paths: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if is_path_key(key) {
                    if let Some(path) = child.as_str() {
                        add_path_variants(path, paths);
                    }
                }
                collect_path_values(child, paths);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_path_values(item, paths);
            }
        }
        _ => {}
    }
}

fn is_path_key(key: &str) -> bool {
    matches!(
        key,
        "path"
            | "target_path"
            | "file_path"
            | "destination_path"
            | "source_path"
            | "new_path"
            | "old_path"
    )
}

fn add_path_variants(path: &str, paths: &mut BTreeSet<String>) {
    if path.is_empty() {
        return;
    }

    paths.insert(path.to_string());
    if let Some(rest) = path.strip_prefix("/tmp/") {
        paths.insert(format!("/private/tmp/{rest}"));
    } else if let Some(rest) = path.strip_prefix("/private/tmp/") {
        paths.insert(format!("/tmp/{rest}"));
    }
}

fn should_materialize_system_artifact(
    event: &SystemEvent,
    path: &str,
    raw_event: Option<&Value>,
) -> bool {
    if event.source != "macos-endpoint-security" {
        return true;
    }

    // Authorization records describe an attempted operation. The matching
    // notify record represents the operation that actually happened; a denied
    // authorization should remain audit evidence without becoming lineage.
    if event.event_type.starts_with("auth_")
        || raw_event
            .and_then(|value| value.get("action"))
            .and_then(Value::as_str)
            == Some("auth")
    {
        return false;
    }

    // Endpoint Security emits close notifications for ordinary reads too. A
    // close is a mutation only when ES explicitly reports modified=true.
    if event.event_type == "close"
        && raw_event
            .and_then(|value| value.get("modified"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        return false;
    }

    // Directories, devices, FIFOs, and sockets are useful in the raw event
    // stream but are not file artifacts. Preserve regular files and symlinks.
    if raw_event
        .and_then(|value| value.get("file"))
        .and_then(|value| value.get("mode"))
        .and_then(Value::as_u64)
        .is_some_and(lineage_mode_is_non_file)
    {
        return false;
    }

    if lineage_path_is_harness_runtime_noise(path) || lineage_path_is_system_dependency(path) {
        return false;
    }
    true
}

fn lineage_path_is_harness_runtime_noise(path: &str) -> bool {
    path.starts_with("/dev/")
        || path.starts_with("/private/tmp/cc-socks/")
        || path.starts_with("/tmp/cc-socks/")
        || path.starts_with("/private/tmp/claude-")
        || path.starts_with("/tmp/claude-")
        || path.starts_with("/private/var/tmp/sh-thd-")
        || path.contains("/.claude/sessions/")
        || path.contains("/.claude/projects/")
        || path.contains("/.claude/shell-snapshots/")
        || (path.contains("/.claude/plugins/cache/")
            && (path.ends_with("/.in_use") || path.contains("/.in_use/")))
}

fn lineage_path_is_system_dependency(path: &str) -> bool {
    path == "/bin"
        || path.starts_with("/bin/")
        || path == "/sbin"
        || path.starts_with("/sbin/")
        || path == "/usr/bin"
        || path.starts_with("/usr/bin/")
        || path == "/usr/local/bin"
        || path.starts_with("/usr/local/bin/")
        || path.starts_with("/usr/lib/")
        || path.starts_with("/usr/share/")
        || path.starts_with("/System/")
        || path.starts_with("/Library/Developer/")
        || path.starts_with("/Applications/Xcode.app/Contents/Developer/")
        || path.starts_with("/Library/Preferences/Logging/")
        || path.starts_with("/Library/Preferences/")
        || path.starts_with("/private/var/db/")
        || path.starts_with("/private/var/folders/")
        || path.starts_with("/opt/homebrew/Cellar/")
}

fn lineage_mode_is_non_file(mode: u64) -> bool {
    matches!(
        mode & 0o170000,
        0o010000 | 0o020000 | 0o040000 | 0o060000 | 0o140000
    )
}

fn file_path_from_uri(uri: &str) -> &str {
    uri.strip_prefix("file://").unwrap_or(uri)
}

fn dashboard_path_visibility_sql(path: &str) -> String {
    format!(
        "NOT (
            {path} GLOB '/dev/*'
            OR {path} GLOB '/private/tmp/cc-socks/*'
            OR {path} GLOB '/tmp/cc-socks/*'
            OR {path} GLOB '/private/tmp/claude-*'
            OR {path} GLOB '/tmp/claude-*'
            OR {path} GLOB '/private/var/tmp/sh-thd-*'
            OR {path} GLOB '*/.claude/sessions/*'
            OR {path} GLOB '*/.claude/projects/*'
            OR {path} GLOB '*/.claude/shell-snapshots/*'
            OR (
                {path} GLOB '*/.claude/plugins/cache/*'
                AND ({path} GLOB '*/.in_use' OR {path} GLOB '*/.in_use/*')
            )
            OR {path} = '/bin'
            OR {path} GLOB '/bin/*'
            OR {path} = '/sbin'
            OR {path} GLOB '/sbin/*'
            OR {path} = '/usr/bin'
            OR {path} GLOB '/usr/bin/*'
            OR {path} = '/usr/local/bin'
            OR {path} GLOB '/usr/local/bin/*'
            OR {path} GLOB '/usr/lib/*'
            OR {path} GLOB '/usr/share/*'
            OR {path} GLOB '/System/*'
            OR {path} GLOB '/Library/Developer/*'
            OR {path} GLOB '/Applications/Xcode.app/Contents/Developer/*'
            OR {path} GLOB '/Library/Preferences/Logging/*'
            OR {path} GLOB '/Library/Preferences/*'
            OR {path} GLOB '/private/var/db/*'
            OR {path} GLOB '/private/var/folders/*'
            OR {path} GLOB '/opt/homebrew/Cellar/*'
        )"
    )
}

fn dashboard_artifact_visibility_sql(source: &str, mode: &str, path: &str) -> String {
    let path_visibility = dashboard_path_visibility_sql(path);
    format!(
        "COALESCE({source}, '') != 'macos-endpoint-security'
         OR (
            ({mode} IS NULL OR ({mode} & 61440) NOT IN (4096, 8192, 16384, 24576, 49152))
            AND {path_visibility}
         )"
    )
}

fn dashboard_artifact_is_visible(artifact: &Value) -> bool {
    let observed_by_endpoint_security = artifact.get("_observation_source").and_then(Value::as_str)
        == Some("macos-endpoint-security");
    if !observed_by_endpoint_security {
        return true;
    }

    let Some(path) = artifact
        .get("uri")
        .and_then(Value::as_str)
        .map(file_path_from_uri)
    else {
        return true;
    };
    if lineage_path_is_harness_runtime_noise(path) {
        return false;
    }
    if artifact
        .get("_observation_mode")
        .and_then(Value::as_u64)
        .is_some_and(lineage_mode_is_non_file)
    {
        return false;
    }
    !lineage_path_is_system_dependency(path)
}

fn dashboard_relation_is_visible(relation: &Value) -> bool {
    ["src_uri", "dst_uri"].into_iter().all(|key| {
        relation
            .get(key)
            .and_then(Value::as_str)
            .map(file_path_from_uri)
            .is_none_or(|path| {
                !lineage_path_is_harness_runtime_noise(path)
                    && !lineage_path_is_system_dependency(path)
            })
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArtifactAccess {
    Consumed,
    Produced,
    Modified,
    Deleted,
}

fn artifact_access(operation: &str) -> ArtifactAccess {
    match operation {
        "read" | "copy_source" | "rename" => ArtifactAccess::Consumed,
        "write" | "create" | "copy_dest" => ArtifactAccess::Produced,
        "delete" => ArtifactAccess::Deleted,
        "metadata" | "edit" | "multi_edit" => ArtifactAccess::Modified,
        _ => ArtifactAccess::Modified,
    }
}

fn system_artifact_relation_type_for_event(event: &SystemEvent) -> &'static str {
    if event.event_kind == "file_read" {
        return "read_by";
    }
    if event.event_type == "open" && event.event_kind == "file_mutation" {
        return "modified";
    }
    system_artifact_relation_type(&event.event_type)
}

fn system_artifact_relation_type(event_type: &str) -> &'static str {
    match event_type {
        value if value.starts_with("auth_") => "attempted_access",
        "open" | "lookup" | "access" | "stat" | "getattrlist" | "readlink" | "readdir"
        | "getextattr" | "listextattr" | "fsgetpath" | "mmap" => "read_by",
        "unlink" => "deleted",
        "close" | "truncate" | "rename" | "setmode" | "setowner" | "setflags" | "setacl"
        | "setextattr" | "deleteextattr" => "modified",
        _ => "wrote",
    }
}

fn request_artifact_relation_type_for_event(event: &SystemEvent) -> &'static str {
    if event.event_kind == "file_read" {
        return "consumed_by";
    }
    if event.event_type == "open" && event.event_kind == "file_mutation" {
        return "modified";
    }
    request_artifact_relation_type(&event.event_type)
}

fn request_artifact_relation_type(event_type: &str) -> &'static str {
    match event_type {
        value if value.starts_with("auth_") => "attempted_access",
        "open" | "lookup" | "access" | "stat" | "getattrlist" | "readlink" | "readdir"
        | "getextattr" | "listextattr" | "fsgetpath" | "mmap" => "consumed_by",
        "unlink" => "deleted",
        "close" | "truncate" | "rename" | "setmode" | "setowner" | "setflags" | "setacl"
        | "setextattr" | "deleteextattr" => "modified",
        _ => "produced",
    }
}

fn file_uri(path: &str) -> String {
    let normalized = path
        .strip_prefix("/tmp/")
        .map(|rest| format!("/private/tmp/{rest}"))
        .unwrap_or_else(|| path.to_string());
    if normalized.starts_with('/') {
        format!("file://{normalized}")
    } else {
        format!("file:{normalized}")
    }
}

struct NativeFileTool {
    operation: String,
    path: String,
}

fn native_file_tools(event: &AgentHookEvent) -> Vec<NativeFileTool> {
    let Some(tool_name) = event.tool_name.as_deref() else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&event.raw_json) else {
        return Vec::new();
    };
    let Some(input) = value.get("tool_input") else {
        return Vec::new();
    };
    if tool_name == "apply_patch" {
        let Some(patch) = extract_apply_patch_input(input) else {
            return Vec::new();
        };
        return parse_apply_patch_changes(patch)
            .into_iter()
            .map(|change| NativeFileTool {
                operation: change.operation,
                path: resolve_tool_path(&change.path, event.cwd.as_deref()),
            })
            .collect();
    }
    if tool_name.starts_with("mcp__") {
        return parse_mcp_file_intents(tool_name, input)
            .into_iter()
            .map(|intent| NativeFileTool {
                operation: intent.operation,
                path: resolve_tool_path(&intent.path, event.cwd.as_deref()),
            })
            .collect();
    }
    if event.provider == "vscode" {
        return parse_vscode_file_intents(tool_name, input)
            .into_iter()
            .map(|intent| NativeFileTool {
                operation: intent.operation,
                path: resolve_tool_path(&intent.path, event.cwd.as_deref()),
            })
            .collect();
    }

    let (operation, path_key) = match tool_name {
        "Read" => ("read", "file_path"),
        "Write" => ("write", "file_path"),
        "Edit" => ("edit", "file_path"),
        "MultiEdit" => ("multi_edit", "file_path"),
        "NotebookRead" => ("read", "notebook_path"),
        "NotebookEdit" => ("edit", "notebook_path"),
        _ => return Vec::new(),
    };
    let Some(path) = input.get(path_key).and_then(Value::as_str) else {
        return Vec::new();
    };
    vec![NativeFileTool {
        operation: operation.to_string(),
        path: resolve_tool_path(path, event.cwd.as_deref()),
    }]
}

fn resolve_tool_path(path: &str, cwd: Option<&str>) -> String {
    normalize_agent_path(path, cwd.unwrap_or("."))
}

fn tool_input_json(event: &AgentHookEvent) -> Option<String> {
    if event.tool_input_command.is_some() || event.tool_input_description.is_some() {
        return store_tool_input(json!({
            "tool_use_id": event.tool_use_id.as_deref(),
            "command": event.tool_input_command.as_deref(),
            "description": event.tool_input_description.as_deref(),
        }));
    }

    let tools = native_file_tools(event);
    match tools.as_slice() {
        [] => {
            // Preserve query/URL metadata for the discovery tools displayed by
            // Timeline. Do not generically persist arbitrary tool payloads:
            // they can include prompts, command arguments, or secret material.
            let tool_name = event.tool_name.as_deref()?;
            if event.provider == "vscode" && matches!(tool_name, "file_search" | "grep_search") {
                let value = serde_json::from_str::<Value>(&event.raw_json).ok()?;
                let query = value
                    .get("tool_input")?
                    .get("query")?
                    .as_str()
                    .filter(|query| !query.is_empty())?;
                return store_tool_input(json!({
                    "tool_use_id": event.tool_use_id.as_deref(),
                    "query": query,
                }));
            }
            if !matches!(tool_name, "WebSearch" | "WebFetch" | "ToolSearch") {
                return None;
            }
            let value = serde_json::from_str::<Value>(&event.raw_json).ok()?;
            let input = value.get("tool_input")?;
            if input.is_null() {
                return None;
            }
            if let Some(map) = input.as_object() {
                if map.is_empty() {
                    return None;
                }
                let mut out = serde_json::Map::new();
                if let Some(id) = event.tool_use_id.as_deref() {
                    out.insert("tool_use_id".to_string(), json!(id));
                }
                out.extend(map.clone());
                return store_tool_input(Value::Object(out));
            }
            None
        }
        [tool] => store_tool_input(json!({
            "tool_use_id": event.tool_use_id.as_deref(),
            "operation": tool.operation,
            "path": tool.path,
        })),
        _ => store_tool_input(json!({
            "tool_use_id": event.tool_use_id.as_deref(),
            "changes": tools
                .iter()
                .map(|tool| json!({
                    "operation": tool.operation,
                    "path": tool.path,
                }))
                .collect::<Vec<_>>(),
        })),
    }
}

/// Serialize telemetry input only when it stays within the storage budget.
/// Returning a valid metadata record rather than a partial JSON string keeps the
/// SQLite JSON constraint intact and makes truncation visible to consumers.
fn store_tool_input(value: Value) -> Option<String> {
    let encoded = value.to_string();
    if encoded.len() <= MAX_STORED_TOOL_INPUT_BYTES {
        return Some(encoded);
    }

    Some(
        json!({
            "truncated": true,
            "original_bytes": encoded.len(),
            "max_bytes": MAX_STORED_TOOL_INPUT_BYTES,
        })
        .to_string(),
    )
}

fn bounded_transaction_text(value: &str) -> String {
    let mut bounded = value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(MAX_TRANSACTION_TEXT_CHARS + 1)
        .collect::<String>();
    if bounded.chars().count() > MAX_TRANSACTION_TEXT_CHARS {
        bounded = bounded
            .chars()
            .take(MAX_TRANSACTION_TEXT_CHARS.saturating_sub(1))
            .collect();
        bounded.push('…');
    }
    bounded
}

fn bounded_transaction_metadata(value: &Value) -> io::Result<String> {
    let encoded = serde_json::to_string(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if encoded.len() <= MAX_TRANSACTION_METADATA_BYTES {
        return Ok(encoded);
    }
    Ok(json!({
        "truncated": true,
        "original_bytes": encoded.len(),
        "max_bytes": MAX_TRANSACTION_METADATA_BYTES,
    })
    .to_string())
}

fn tool_response_json(event: &AgentHookEvent) -> Option<String> {
    if event.tool_response_stdout.is_none()
        && event.tool_response_stderr.is_none()
        && event.tool_response_interrupted.is_none()
        && event.duration_ms.is_none()
    {
        return None;
    }

    let response = json!({
        "stdout": event.tool_response_stdout.as_deref(),
        "stderr": event.tool_response_stderr.as_deref(),
        "interrupted": event.tool_response_interrupted,
        "duration_ms": event.duration_ms,
    });
    let encoded = response.to_string();
    if encoded.len() <= MAX_STORED_TOOL_RESPONSE_BYTES {
        return Some(encoded);
    }

    Some(
        json!({
            "truncated": true,
            "original_bytes": encoded.len(),
            "max_bytes": MAX_STORED_TOOL_RESPONSE_BYTES,
            "interrupted": event.tool_response_interrupted,
            "duration_ms": event.duration_ms,
        })
        .to_string(),
    )
}

fn to_i64(value: u64) -> io::Result<i64> {
    i64::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "timestamp too large"))
}

fn sqlite_error(error: gensee_crate_db::sqlite::SqliteError) -> io::Error {
    io::Error::other(error)
}

fn sqlite_error_from_rusqlite(error: rusqlite::Error) -> io::Error {
    io::Error::other(error)
}

fn query_json_rows<F>(
    conn: &rusqlite::Connection,
    sql: &str,
    mut mapper: F,
) -> io::Result<Vec<Value>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<Value>,
{
    let mut stmt = conn
        .prepare(sql)
        .map_err(|error| sqlite_error(SqliteError::Database(error)))?;
    let rows = stmt
        .query_map([], |row| mapper(row))
        .map_err(|error| sqlite_error(SqliteError::Database(error)))?;
    let mut values = Vec::new();
    for row in rows {
        values.push(row.map_err(|error| sqlite_error(SqliteError::Database(error)))?);
    }
    Ok(values)
}

fn json_record<T: Serialize>(value: &T) -> io::Result<String> {
    serde_json::to_string(value).map_err(io::Error::other)
}

fn append_jsonl<T: Serialize>(
    path: &PathBuf,
    value: &T,
    encryption_key: Option<&[u8; 32]>,
) -> io::Result<()> {
    let mut line = json_record(value)?;
    if let Some(key) = encryption_key {
        line = encrypt_jsonl_line(key, line.as_bytes())?;
    }
    line.push('\n');

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())
}

/// Read newline-delimited JSON records. Lines that fail to parse are skipped
/// rather than failing the whole read, so a single corrupt line cannot blind
/// the timeline to every other record.
fn read_jsonl<T: DeserializeOwned>(
    path: &PathBuf,
    encryption_key: Option<&[u8; 32]>,
) -> io::Result<Vec<T>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = OpenOptions::new().read(true).open(path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let decoded = if line.starts_with(JSONL_ENCRYPTED_PREFIX) {
            let Some(key) = encryption_key else {
                continue;
            };
            match decrypt_jsonl_line(key, &line) {
                Ok(decoded) => decoded,
                Err(_) => continue,
            }
        } else {
            line
        };
        if let Ok(record) = serde_json::from_str(&decoded) {
            records.push(record);
        }
    }

    Ok(records)
}

/// Scan lifecycle records for one session without materializing and
/// decrypting every session into a collection. The latest matching record is
/// authoritative, matching `list_sessions` semantics.
fn latest_session_by_id(
    path: &Path,
    encryption_key: Option<&[u8; 32]>,
    session_id: &str,
) -> io::Result<Option<AgentSession>> {
    if !path.exists() {
        return Ok(None);
    }

    let file = OpenOptions::new().read(true).open(path)?;
    let mut latest = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let decoded = if line.starts_with(JSONL_ENCRYPTED_PREFIX) {
            let Some(key) = encryption_key else { continue };
            let Ok(decoded) = decrypt_jsonl_line(key, &line) else {
                continue;
            };
            decoded
        } else {
            line
        };
        let Ok(session) = serde_json::from_str::<AgentSession>(&decoded) else {
            continue;
        };
        if session.session_id == session_id {
            latest = Some(session);
        }
    }
    Ok(latest)
}

fn store_encryption_enabled() -> bool {
    !matches!(
        env::var("GENSEE_STORE_ENCRYPTION").ok().as_deref(),
        Some("0") | Some("false") | Some("no") | Some("off")
    )
}

fn store_encryption_key(root: &Path) -> io::Result<Option<[u8; 32]>> {
    if !store_encryption_enabled() {
        return Ok(None);
    }
    if database_is_plaintext_sqlite(root)? {
        return Ok(None);
    }
    let key_path = root.join(STORE_KEY_FILE);
    if key_path.exists() {
        let text = fs::read_to_string(&key_path)?;
        return hex_decode_key(text.trim()).map(Some);
    }
    let key = random_key()?;
    let encoded = hex_encode(&key);
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&key_path)?;
    file.write_all(encoded.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(Some(key))
}

fn database_is_plaintext_sqlite(root: &Path) -> io::Result<bool> {
    let path = database_path_for_root(root);
    if !path.exists() {
        return Ok(false);
    }
    let mut header = [0_u8; 16];
    let mut file = OpenOptions::new().read(true).open(path)?;
    if file.read(&mut header)? != header.len() {
        return Ok(false);
    }
    Ok(&header == b"SQLite format 3\0")
}

fn random_key() -> io::Result<[u8; 32]> {
    let mut key = [0_u8; 32];
    let mut file = OpenOptions::new().read(true).open("/dev/urandom")?;
    file.read_exact(&mut key)?;
    Ok(key)
}

fn random_nonce() -> io::Result<[u8; 12]> {
    let mut nonce = [0_u8; 12];
    let mut file = OpenOptions::new().read(true).open("/dev/urandom")?;
    file.read_exact(&mut nonce)?;
    Ok(nonce)
}

fn encrypt_jsonl_line(key: &[u8; 32], plaintext: &[u8]) -> io::Result<String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = random_nonce()?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| io::Error::other("failed to encrypt JSONL record"))?;
    Ok(format!(
        "{JSONL_ENCRYPTED_PREFIX}:{}:{}",
        hex_encode(&nonce),
        hex_encode(&ciphertext)
    ))
}

fn decrypt_jsonl_line(key: &[u8; 32], line: &str) -> io::Result<String> {
    let mut parts = line.splitn(3, ':');
    let prefix = parts.next();
    let nonce_hex = parts.next();
    let ciphertext_hex = parts.next();
    if prefix != Some(JSONL_ENCRYPTED_PREFIX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not an encrypted JSONL record",
        ));
    }
    let nonce = hex_decode(nonce_hex.unwrap_or(""))?;
    let ciphertext = hex_decode(ciphertext_hex.unwrap_or(""))?;
    if nonce.len() != 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid encrypted JSONL nonce",
        ));
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "encrypted JSONL decrypt failed")
        })?;
    String::from_utf8(plaintext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encrypted JSONL was not UTF-8"))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode_key(text: &str) -> io::Result<[u8; 32]> {
    let bytes = hex_decode(text)?;
    bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid store key length"))
}

fn hex_decode(text: &str) -> io::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hex input has odd length",
        ));
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let raw = text.as_bytes();
    for chunk in raw.chunks_exact(2) {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid hex digit",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_token_usage_supports_claude_and_codex_jsonl() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-token-transcript-test-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        fs::create_dir_all(&dir).unwrap();
        let claude_path = dir.join("claude.jsonl");
        fs::write(
            &claude_path,
            concat!(
                "{\"message\":{\"id\":\"m1\",\"usage\":{\"input_tokens\":10,\"output_tokens\":2,\"cache_creation_input_tokens\":3,\"cache_read_input_tokens\":4}}}\n",
                "{\"message\":{\"id\":\"m1\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5,\"cache_creation_input_tokens\":3,\"cache_read_input_tokens\":4}}}\n",
                "{\"message\":{\"id\":\"m2\",\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\n"
            ),
        )
        .unwrap();
        assert_eq!(transcript_total_tokens(&claude_path).unwrap(), Some(25));
        let mut cache = HashMap::new();
        assert_eq!(
            transcript_total_tokens_cached(&claude_path, &mut cache).unwrap(),
            Some(25)
        );
        writeln!(
            OpenOptions::new().append(true).open(&claude_path).unwrap(),
            "{{\"message\":{{\"id\":\"m3\",\"usage\":{{\"input_tokens\":3,\"output_tokens\":2}}}}}}"
        )
        .unwrap();
        assert_eq!(
            transcript_total_tokens_cached(&claude_path, &mut cache).unwrap(),
            Some(30)
        );

        let codex_path = dir.join("codex.jsonl");
        fs::write(
            &codex_path,
            concat!(
                "{\"payload\":{\"info\":{\"total_token_usage\":{\"total_tokens\":21}}}}\n",
                "{\"payload\":{\"info\":{\"total_token_usage\":{\"total_tokens\":42}}}}\n"
            ),
        )
        .unwrap();
        assert_eq!(transcript_total_tokens(&codex_path).unwrap(), Some(42));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn transcript_roots_honor_harness_configuration_directories() {
        let home = PathBuf::from("/Users/tester");
        assert_eq!(
            transcript_root(
                "claude-code",
                Some(home.clone()),
                Some(PathBuf::from("/Volumes/config/claude")),
                None,
            ),
            Some(PathBuf::from("/Volumes/config/claude/projects"))
        );
        assert_eq!(
            transcript_root(
                "codex",
                Some(home.clone()),
                None,
                Some(PathBuf::from("/Volumes/config/codex")),
            ),
            Some(PathBuf::from("/Volumes/config/codex/sessions"))
        );
        assert_eq!(
            transcript_root("claude-code", Some(home.clone()), None, None),
            Some(home.join(".claude/projects"))
        );
        assert_eq!(transcript_root("cursor", None, None, None), None);
    }

    #[test]
    fn transcript_offset_survives_event_store_restarts() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "gensee-transcript-state-test-{}-{now}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let transcript = dir.join("claude.jsonl");
        fs::write(
            &transcript,
            "{\"message\":{\"id\":\"m1\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n",
        )
        .unwrap();

        {
            let store = EventStore::new(&dir).unwrap();
            let db = store.sqlite_store().unwrap();
            ensure_session(&db, "persisted-session", "claude-code", 1).unwrap();
            assert_eq!(
                store
                    .transcript_total_tokens_at_path(&db, "persisted-session", &transcript, 1,)
                    .unwrap(),
                Some(15)
            );
        }

        writeln!(
            OpenOptions::new().append(true).open(&transcript).unwrap(),
            "{{\"message\":{{\"id\":\"m2\",\"usage\":{{\"input_tokens\":3,\"output_tokens\":2}}}}}}"
        )
        .unwrap();
        {
            let store = EventStore::new(&dir).unwrap();
            let db = store.sqlite_store().unwrap();
            assert_eq!(
                store
                    .transcript_total_tokens_at_path(&db, "persisted-session", &transcript, 2,)
                    .unwrap(),
                Some(20)
            );
        }

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_reports_daily_turn_tool_alert_and_token_totals() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let dir = std::env::temp_dir().join(format!(
            "gensee-daily-activity-test-{}-{now}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"test"}"#,
                now,
            ))
            .unwrap();
        let mut read = hook_event(
            "PreToolUse",
            r#"{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Read"}"#,
            now + 1,
        );
        read.tool_name = Some("Read".to_string());
        store.append_hook_event(&read).unwrap();

        let transcript = dir.join("transcript.jsonl");
        fs::write(
            &transcript,
            "{\"message\":{\"id\":\"m1\",\"usage\":{\"input_tokens\":20,\"output_tokens\":5}}}\n",
        )
        .unwrap();
        let mut stop = hook_event(
            "Stop",
            r#"{"session_id":"s1","hook_event_name":"Stop","last_assistant_message":"done"}"#,
            now + 2,
        );
        stop.transcript_path = Some(transcript.display().to_string());
        store.append_hook_event(&stop).unwrap();
        store
            .append_policy_alert(&PolicyAlert {
                session_id: Some("s1".to_string()),
                tool_use_id: None,
                severity: "medium".to_string(),
                action: "warn".to_string(),
                rule_id: "test_alert".to_string(),
                message: "test".to_string(),
                path: None,
                evidence: None,
                observed_at_ms: now + 3,
            })
            .unwrap();

        let dashboard = store.dashboard_state().unwrap();
        let today = dashboard["dailyActivity"]
            .as_array()
            .unwrap()
            .last()
            .unwrap();
        assert_eq!(today["requests"], 1);
        assert_eq!(today["tool_calls"], 1);
        assert_eq!(today["alerts"], 1);
        // The first cumulative transcript observation establishes a baseline;
        // it must not attribute earlier session usage to this request.
        assert_eq!(today["tokens"], 0);
        let day = today["date"].as_str().unwrap();
        let detail = store.dashboard_day(day).unwrap();
        assert_eq!(detail["sessions"], 1);
        assert_eq!(detail["requests"], 1);
        assert_eq!(detail["tool_calls"], 1);
        assert_eq!(detail["alerts"], 1);
        assert_eq!(detail["files_read"], 1);
        assert_eq!(detail["top_tools"][0]["name"], "Read");
        assert!(store.dashboard_day("2026-02-30").is_err());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn transaction_text_is_bounded_and_strips_control_characters() {
        let input = format!("safe\0{}", "x".repeat(MAX_TRANSACTION_TEXT_CHARS + 20));
        let bounded = bounded_transaction_text(&input);
        assert!(!bounded.contains('\0'));
        assert_eq!(bounded.chars().count(), MAX_TRANSACTION_TEXT_CHARS);
        assert!(bounded.ends_with('…'));
    }

    #[test]
    fn transaction_metadata_is_replaced_with_valid_truncation_metadata() {
        let input = json!({ "paths": ["x".repeat(MAX_TRANSACTION_METADATA_BYTES)] });
        let bounded = bounded_transaction_metadata(&input).unwrap();
        let decoded: Value = serde_json::from_str(&bounded).unwrap();
        assert_eq!(decoded["truncated"], true);
        assert_eq!(decoded["max_bytes"], MAX_TRANSACTION_METADATA_BYTES);
    }

    #[test]
    fn oversized_tool_response_is_replaced_with_truncation_metadata() {
        let mut event = hook_event("PostToolUse", "{}", 100);
        event.tool_response_stdout = Some("x".repeat(MAX_STORED_TOOL_RESPONSE_BYTES + 1));
        event.tool_response_stderr = Some("sensitive stderr".to_string());
        event.tool_response_interrupted = Some(false);
        event.duration_ms = Some(42);

        let encoded = tool_response_json(&event).unwrap();
        let decoded: Value = serde_json::from_str(&encoded).unwrap();

        assert!(encoded.len() < MAX_STORED_TOOL_RESPONSE_BYTES);
        assert_eq!(decoded["truncated"], true);
        assert_eq!(decoded["max_bytes"], MAX_STORED_TOOL_RESPONSE_BYTES);
        assert_eq!(decoded["duration_ms"], 42);
        assert!(decoded.get("stdout").is_none());
        assert!(decoded.get("stderr").is_none());
    }

    #[test]
    fn session_round_trips_through_jsonl() {
        let dir = std::env::temp_dir().join(format!("gensee-store-test-{}", std::process::id()));
        let store = EventStore::new(&dir).unwrap();

        let session = AgentSession {
            session_id: "run_1".to_string(),
            agent_binary: "claude".to_string(),
            root_pid: 1234,
            cwd: "/repo".to_string(),
            repo_path: Some("/repo".to_string()),
            mode: Some("managed-run".to_string()),
            workspace_mode: None,
            original_workspace: None,
            staged_workspace: None,
            sandbox_profile: None,
            sandbox_profile_path: None,
            started_at_ms: 100,
            ended_at_ms: None,
            exit_code: None,
        };
        store.append_session(&session).unwrap();

        let loaded = store.list_sessions().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].session_id, "run_1");
        assert_eq!(loaded[0].root_pid, 1234);
        assert_eq!(loaded[0].repo_path.as_deref(), Some("/repo"));
        assert!(loaded[0].ended_at_ms.is_none());

        let db = store.sqlite_store().unwrap();
        let stored = db.get_session("run_1").unwrap().unwrap();
        assert_eq!(stored.session_id, "run_1");
        assert_eq!(stored.first_event_at, 100);
        assert_eq!(stored.last_event_at, None);
        assert!(!stored.flagged);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn repeated_session_appends_are_deduplicated_by_session_id() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-session-dedupe-test-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        let session = AgentSession {
            session_id: "run_deduplicated".to_string(),
            agent_binary: "codex".to_string(),
            root_pid: 1234,
            cwd: "/repo".to_string(),
            repo_path: Some("/repo".to_string()),
            mode: Some("managed-run".to_string()),
            workspace_mode: None,
            original_workspace: None,
            staged_workspace: None,
            sandbox_profile: None,
            sandbox_profile_path: None,
            started_at_ms: 100,
            ended_at_ms: None,
            exit_code: None,
        };
        store.append_session(&session).unwrap();
        // Model both a lost daemon acknowledgement retry and the eventual
        // lifecycle update. Consumers must see one latest session record.
        store.append_session(&session).unwrap();
        {
            let db = store.sqlite_store().unwrap();
            db.upsert_transcript_token_state(&TranscriptTokenStateRecord {
                session_id: session.session_id.clone(),
                transcript_path: "/tmp/test-transcript.jsonl".to_string(),
                state_json: "{}".to_string(),
                updated_at: 150,
            })
            .unwrap();
        }
        assert!(store
            .end_session(&session.session_id, 200, Some(0))
            .unwrap());

        let loaded = store.list_sessions().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].session_id, "run_deduplicated");
        assert_eq!(loaded[0].ended_at_ms, Some(200));
        assert_eq!(loaded[0].exit_code, Some(0));
        assert_eq!(
            fs::read_to_string(store.sessions_path())
                .unwrap()
                .lines()
                .count(),
            2,
            "one start and one end record should be persisted"
        );
        assert!(store
            .sqlite_store()
            .unwrap()
            .transcript_token_state(&session.session_id, "/tmp/test-transcript.jsonl")
            .unwrap()
            .is_none());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn local_telemetry_is_encrypted_at_rest() {
        if !store_encryption_enabled() {
            return;
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-encryption-test-{}-{nanos}",
            std::process::id()
        ));
        let marker = "top-secret-telemetry-marker";
        let store = EventStore::new(&dir).unwrap();
        let event = AgentHookEvent {
            provider: "codex".to_string(),
            session_id: Some("encrypted-session".to_string()),
            hook_event_name: Some("PreToolUse".to_string()),
            cwd: Some("/repo".to_string()),
            transcript_path: None,
            tool_name: Some("Bash".to_string()),
            tool_use_id: Some("tool-1".to_string()),
            tool_input_command: Some(format!("echo {marker}")),
            tool_input_description: None,
            tool_response_stdout: None,
            tool_response_stderr: None,
            tool_response_interrupted: None,
            duration_ms: None,
            permission_mode: Some("default".to_string()),
            effort_level: None,
            observed_at_ms: 123,
            raw_json: format!(
                r#"{{"session_id":"encrypted-session","hook_event_name":"PreToolUse","cwd":"/repo","tool_name":"Bash","tool_use_id":"tool-1","tool_input":{{"command":"echo {marker}"}}}}"#
            ),
        };

        store.append_hook_event(&event).unwrap();
        let loaded = store.list_hook_events().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].tool_input_command.as_deref(),
            Some(format!("echo {marker}").as_str())
        );
        assert!(store
            .dashboard_state()
            .unwrap()
            .to_string()
            .contains(marker));
        assert!(dir.join(STORE_KEY_FILE).exists());

        let hooks = fs::read_to_string(dir.join("hooks.jsonl")).unwrap();
        assert!(hooks.starts_with(JSONL_ENCRYPTED_PREFIX));
        assert!(!hooks.contains(marker));

        for file_name in ["gensee.db", "gensee.db-wal", "gensee.db-shm"] {
            let path = dir.join(file_name);
            if path.exists() {
                let bytes = fs::read(path).unwrap();
                assert!(!String::from_utf8_lossy(&bytes).contains(marker));
            }
        }

        let reopened = EventStore::new(&dir).unwrap();
        let loaded = reopened.list_hook_events().unwrap();
        assert_eq!(
            loaded[0].tool_input_command.as_deref(),
            Some(format!("echo {marker}").as_str())
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn encrypted_jsonl_reader_accepts_plaintext_records() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-plaintext-jsonl-test-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sessions.jsonl");
        fs::write(
            &path,
            r#"{"session_id":"plain","agent_binary":"codex","root_pid":7,"cwd":"/repo","repo_path":null,"mode":null,"workspace_mode":null,"original_workspace":null,"staged_workspace":null,"sandbox_profile":null,"sandbox_profile_path":null,"started_at_ms":1,"ended_at_ms":null,"exit_code":null}"#,
        )
        .unwrap();

        let records: Vec<AgentSession> = read_jsonl(&path, Some(&[1_u8; 32])).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].session_id, "plain");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn existing_plaintext_sqlite_store_stays_readable() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-plaintext-db-test-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let config = SqliteConfig {
            path: database_path_for_root(&dir).to_string_lossy().to_string(),
            journal_mode: "wal".to_string(),
            synchronous: "normal".to_string(),
            auto_vacuum: "full".to_string(),
            shared_cache: false,
            cipher_key: None,
        };
        open_store(&config).unwrap();
        fs::write(dir.join(STORE_KEY_FILE), hex_encode(&[7_u8; 32])).unwrap();

        let store = EventStore::new(&dir).unwrap();
        assert!(store.encryption_key.is_none());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn embedded_quotes_and_newlines_survive_round_trip() {
        let dir =
            std::env::temp_dir().join(format!("gensee-store-test-quotes-{}", std::process::id()));
        let store = EventStore::new(&dir).unwrap();

        let command_line = "echo \"hi\"\nrun --flag={\"a\":1}";
        let raw_json = r#"{"nested":"value with \"quotes\" and , commas"}"#;
        let event = SystemEvent {
            source: "test".to_string(),
            event_type: "exec".to_string(),
            event_kind: "process".to_string(),
            observed_at_ms: 1,
            pid: Some(1),
            ppid: Some(0),
            process_name: Some("sh".to_string()),
            executable_path: Some("/bin/sh".to_string()),
            file_path: None,
            command_line: Some(command_line.to_string()),
            raw_json: raw_json.to_string(),
        };
        store.append_system_event(&event).unwrap();

        let loaded = store.list_system_events().unwrap();
        assert_eq!(loaded.len(), 1);
        // Embedded quotes, newlines, commas, and braces survive the round trip
        // exactly — the failure mode of the old hand-rolled (de)serializer.
        assert_eq!(loaded[0].command_line.as_deref(), Some(command_line));
        assert_eq!(loaded[0].raw_json, raw_json);

        let db = store.sqlite_store().unwrap();
        let request = db.latest_request().unwrap().unwrap();
        let stored = db.system_events_for_request(request.request_id).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].source, "test");
        assert_eq!(stored[0].event_type, "exec");
        assert_eq!(stored[0].pid, 1);
        assert_eq!(stored[0].ts, 1);
        assert_eq!(stored[0].args.as_deref(), Some(raw_json));
        assert_eq!(
            db.relations_for_request(request.request_id).unwrap().len(),
            0
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hook_request_and_tool_events_write_to_database() {
        let dir =
            std::env::temp_dir().join(format!("gensee-store-test-hooks-{}", std::process::id()));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"please inspect"}"#,
                100,
            ))
            .unwrap();
        store
            .append_hook_event(&AgentHookEvent {
                provider: "claude-code".to_string(),
                session_id: Some("s1".to_string()),
                hook_event_name: Some("PreToolUse".to_string()),
                cwd: Some("/repo".to_string()),
                transcript_path: None,
                tool_name: Some("Bash".to_string()),
                tool_use_id: Some("tool_1".to_string()),
                tool_input_command: Some("ls".to_string()),
                tool_input_description: Some("list files".to_string()),
                tool_response_stdout: None,
                tool_response_stderr: None,
                tool_response_interrupted: None,
                duration_ms: None,
                permission_mode: Some("default".to_string()),
                effort_level: None,
                observed_at_ms: 110,
                raw_json: r#"{"session_id":"s1","hook_event_name":"PreToolUse","cwd":"/repo","tool_name":"Bash","tool_use_id":"tool_1","tool_input":{"command":"ls","description":"list files"}}"#.to_string(),
            })
            .unwrap();
        store
            .append_hook_event(&hook_event(
                "Stop",
                r#"{"session_id":"s1","hook_event_name":"Stop","cwd":"/repo","last_assistant_message":"done"}"#,
                120,
            ))
            .unwrap();

        let db = store.sqlite_store().unwrap();
        let session = db.get_session("s1").unwrap().unwrap();
        assert_eq!(session.agent_id, "claude-code");
        assert_eq!(session.first_event_at, 100);

        let request = db.latest_request_for_session("s1").unwrap().unwrap();
        assert_eq!(
            request.original_user_prompt.as_deref(),
            Some("please inspect")
        );
        assert_eq!(request.final_response.as_deref(), Some("done"));

        let agent_events = db.agent_events_for_request(request.request_id).unwrap();
        assert_eq!(agent_events.len(), 1);
        assert_eq!(agent_events[0].event_type, "PreToolUse");
        assert_eq!(agent_events[0].cwd, "/repo");
        assert_eq!(agent_events[0].tool_name.as_deref(), Some("Bash"));
        assert_eq!(
            serde_json::from_str::<Value>(agent_events[0].tool_input.as_deref().unwrap()).unwrap()
                ["command"],
            "ls"
        );
        let relations = db.relations_for_request(request.request_id).unwrap();
        assert_eq!(relations.len(), 0);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn risky_file_intents_create_alert_rows() {
        let dir =
            std::env::temp_dir().join(format!("gensee-store-test-alerts-{}", std::process::id()));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"read creds"}"#,
                100,
            ))
            .unwrap();
        store
            .append_file_intent(&FileIntent {
                provider: "bash-command-parser".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_1".to_string()),
                observed_at_ms: 110,
                operation: "read".to_string(),
                path: "/Users/test/.ssh/config".to_string(),
                source_command: "cat ~/.ssh/config".to_string(),
                sensitive: true,
                confidence: "low".to_string(),
            })
            .unwrap();

        let alerts = store.list_alerts().unwrap();
        assert_eq!(alerts.len(), 0);

        store
            .append_file_intent(&FileIntent {
                provider: "external-file-intent-source".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_2".to_string()),
                observed_at_ms: 120,
                operation: "read".to_string(),
                path: "/Users/test/.ssh/config".to_string(),
                source_command: "cat ~/.ssh/config".to_string(),
                sensitive: true,
                confidence: "low".to_string(),
            })
            .unwrap();

        let alerts = store.list_alerts().unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, "critical");
        assert_eq!(alerts[0].action, "block");
        assert_eq!(alerts[0].rule_id, "policy_sensitive_file_access");
        assert_eq!(alerts[0].session_id.as_deref(), Some("s1"));
        assert_eq!(alerts[0].path.as_deref(), Some("/Users/test/.ssh/config"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn explicit_policy_alerts_are_persisted() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-policy-alert-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"write outside"}"#,
                100,
            ))
            .unwrap();
        store
            .append_policy_alert(&PolicyAlert {
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_1".to_string()),
                severity: "high".to_string(),
                action: "block".to_string(),
                rule_id: "policy_write_outside_workspace".to_string(),
                message: "Blocked write outside workspace: /tmp/out.txt".to_string(),
                path: Some("/tmp/out.txt".to_string()),
                evidence: Some(json!({ "workspace": "/repo" })),
                observed_at_ms: 110,
            })
            .unwrap();

        let alerts = store.list_alerts().unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "policy_write_outside_workspace");
        assert_eq!(alerts[0].session_id.as_deref(), Some("s1"));
        assert!(alerts[0].evidence.as_deref().unwrap().contains("tool_1"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_alerts_include_request_tool_and_latest_feedback() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-alert-detail-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"inspect the deployment settings"}"#,
                100,
            ))
            .unwrap();
        store
            .append_hook_event(&AgentHookEvent {
                provider: "claude-code".to_string(),
                session_id: Some("s1".to_string()),
                hook_event_name: Some("PreToolUse".to_string()),
                cwd: Some("/repo".to_string()),
                transcript_path: None,
                tool_name: Some("Read".to_string()),
                tool_use_id: Some("tool_alert_1".to_string()),
                tool_input_command: None,
                tool_input_description: None,
                tool_response_stdout: None,
                tool_response_stderr: None,
                tool_response_interrupted: None,
                duration_ms: None,
                permission_mode: Some("default".to_string()),
                effort_level: None,
                observed_at_ms: 110,
                raw_json: r#"{"session_id":"s1","hook_event_name":"PreToolUse","cwd":"/repo","tool_name":"Read","tool_use_id":"tool_alert_1","tool_input":{"file_path":"/repo/deploy.json"}}"#.to_string(),
            })
            .unwrap();
        store
            .append_hook_event(&AgentHookEvent {
                provider: "claude-code".to_string(),
                session_id: Some("s1".to_string()),
                hook_event_name: Some("PostToolUse".to_string()),
                cwd: Some("/repo".to_string()),
                transcript_path: None,
                tool_name: Some("Read".to_string()),
                tool_use_id: Some("tool_alert_1".to_string()),
                tool_input_command: None,
                tool_input_description: None,
                tool_response_stdout: Some("contents".to_string()),
                tool_response_stderr: None,
                tool_response_interrupted: Some(false),
                duration_ms: Some(8),
                permission_mode: Some("default".to_string()),
                effort_level: None,
                observed_at_ms: 118,
                raw_json: r#"{"session_id":"s1","hook_event_name":"PostToolUse","cwd":"/repo","tool_name":"Read","tool_use_id":"tool_alert_1","tool_response":{"stdout":"contents"}}"#.to_string(),
            })
            .unwrap();
        store
            .append_policy_alert(&PolicyAlert {
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_alert_1".to_string()),
                severity: "high".to_string(),
                action: "block".to_string(),
                rule_id: "policy_sensitive_file_access".to_string(),
                message: "Blocked access to deployment settings".to_string(),
                path: Some("/repo/deploy.json".to_string()),
                evidence: Some(json!({ "reason": "sensitive" })),
                observed_at_ms: 120,
            })
            .unwrap();

        let dashboard = store.dashboard_state().unwrap();
        assert_eq!(
            dashboard["requests"][0]["original_user_prompt"],
            "inspect the deployment settings"
        );
        let post_event = dashboard["agentEvents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["type"] == "PostToolUse")
            .unwrap();
        assert_eq!(post_event["duration_ms"], 8);
        assert!(post_event.get("tool_response").is_none());
        assert!(dashboard["requests"][0].get("final_response").is_none());
        let alert = &dashboard["alerts"][0];
        assert_eq!(
            alert["original_user_prompt"],
            "inspect the deployment settings"
        );
        assert_eq!(alert["event_source"], "claude-code");
        assert_eq!(alert["event_type"], "PreToolUse");
        assert_eq!(alert["tool_name"], "Read");
        assert_eq!(alert["tool_use_id"], "tool_alert_1");
        assert_eq!(
            serde_json::from_str::<Value>(alert["tool_input"].as_str().unwrap()).unwrap()["path"],
            "/repo/deploy.json"
        );

        let alert_id = alert["alert_id"].as_i64().unwrap();
        store
            .record_human_feedback(
                Some(format!("alert:{alert_id}")),
                Some("tool_alert_1".to_string()),
                Some("s1".to_string()),
                Some("block".to_string()),
                "agree".to_string(),
                Some("confirmed".to_string()),
                Some("policy_sensitive_file_access".to_string()),
                Some("/repo/deploy.json".to_string()),
                None,
                130,
            )
            .unwrap();

        let dashboard = store.dashboard_state().unwrap();
        let alert = &dashboard["alerts"][0];
        assert_eq!(alert["human_verdict"], "agree");
        assert_eq!(alert["feedback_label"], "confirmed");
        assert_eq!(alert["feedback_created_at"], 130);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_snapshot_bounds_request_text_and_omits_final_response() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-dashboard-request-projection-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        let prompt = "p".repeat(2_048);
        let response_marker = "response-that-must-not-enter-dashboard-state";
        let response = format!("{response_marker}{}", "r".repeat(32 * 1_024));

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                &json!({
                    "session_id": "s1",
                    "hook_event_name": "UserPromptSubmit",
                    "cwd": "/repo",
                    "prompt": prompt,
                })
                .to_string(),
                100,
            ))
            .unwrap();
        store
            .append_hook_event(&hook_event(
                "Stop",
                &json!({
                    "session_id": "s1",
                    "hook_event_name": "Stop",
                    "cwd": "/repo",
                    "last_assistant_message": response,
                })
                .to_string(),
                110,
            ))
            .unwrap();

        let dashboard = store.dashboard_state().unwrap();
        let request = &dashboard["requests"][0];
        assert_eq!(
            request["original_user_prompt"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            1_024
        );
        assert!(request.get("final_response").is_none());
        assert!(!dashboard.to_string().contains(response_marker));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_snapshot_omits_transaction_events() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-dashboard-transaction-projection-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_transaction_event(&TransactionEventInput {
                operation_id: "op-1".to_string(),
                environment_kind: "container".to_string(),
                operation: "create".to_string(),
                phase: "succeeded".to_string(),
                source_run_id: None,
                target_run_id: Some("run-1".to_string()),
                parent_run_id: None,
                workspace: Some("/repo".to_string()),
                summary: "transaction payload must stay off the dashboard refresh path".to_string(),
                error_kind: None,
                error_message: None,
                metadata: Some(json!({"large": "metadata"})),
                occurred_at_ms: 100,
            })
            .unwrap();

        let dashboard = store.dashboard_state().unwrap();
        assert!(dashboard.get("transactionEvents").is_none());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn failed_database_append_rolls_back_partial_graph_rows() {
        let dir =
            std::env::temp_dir().join(format!("gensee-store-test-rollback-{}", std::process::id()));
        let store = EventStore::new(&dir).unwrap();

        let result = store.append_system_event(&SystemEvent {
            source: "test".to_string(),
            event_type: "exec".to_string(),
            event_kind: "process".to_string(),
            observed_at_ms: 1,
            pid: Some(1),
            ppid: Some(0),
            process_name: Some("sh".to_string()),
            executable_path: Some("/bin/sh".to_string()),
            file_path: None,
            command_line: Some("sh -c nope".to_string()),
            raw_json: "not-json".to_string(),
        });
        assert!(result.is_err());

        let db = store.sqlite_store().unwrap();
        assert!(db.get_session(SYSTEM_SESSION_ID).unwrap().is_none());
        assert!(db
            .latest_request_for_session(SYSTEM_SESSION_ID)
            .unwrap()
            .is_none());
        assert!(store.list_system_events().unwrap().is_empty());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unmatched_system_events_stay_on_system_request() {
        let dir =
            std::env::temp_dir().join(format!("gensee-store-test-system-{}", std::process::id()));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"watch this"}"#,
                100,
            ))
            .unwrap();
        store
            .append_system_event(&SystemEvent {
                source: "eslogger".to_string(),
                event_type: "exec".to_string(),
                event_kind: "process".to_string(),
                observed_at_ms: 130,
                pid: Some(42),
                ppid: Some(1),
                process_name: Some("sh".to_string()),
                executable_path: Some("/bin/sh".to_string()),
                file_path: None,
                command_line: Some("sh -c ls".to_string()),
                raw_json: r#"{"event":"exec","pid":42}"#.to_string(),
            })
            .unwrap();

        let db = store.sqlite_store().unwrap();
        let request = db.latest_request_for_session("s1").unwrap().unwrap();
        let system_events = db.system_events_for_request(request.request_id).unwrap();
        assert_eq!(system_events.len(), 0);
        assert_eq!(
            db.relations_for_request(request.request_id).unwrap().len(),
            0
        );

        let system_request = db
            .latest_request_for_session(SYSTEM_SESSION_ID)
            .unwrap()
            .unwrap();
        let system_events = db
            .system_events_for_request(system_request.request_id)
            .unwrap();
        assert_eq!(system_events.len(), 1);
        assert_eq!(system_events[0].pid, 42);
        assert_eq!(system_events[0].source, "eslogger");
        assert_eq!(system_events[0].event_type, "exec");
        assert_eq!(system_events[0].ts, 130);
        assert_eq!(
            db.relations_for_request(system_request.request_id)
                .unwrap()
                .len(),
            0
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unattributed_endpoint_security_events_do_not_create_legacy_unmatched_alerts() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-endpoint-global-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_system_event(&SystemEvent {
                source: "macos-endpoint-security".to_string(),
                event_type: "write".to_string(),
                event_kind: "file_mutation".to_string(),
                observed_at_ms: 130,
                pid: Some(42),
                ppid: Some(1),
                process_name: Some("unmanaged".to_string()),
                executable_path: Some("/usr/bin/unmanaged".to_string()),
                file_path: Some("/private/tmp/unmanaged.txt".to_string()),
                command_line: None,
                raw_json: r#"{"attribution":{"session_id":null}}"#.to_string(),
            })
            .unwrap();

        assert!(store
            .list_alerts()
            .unwrap()
            .iter()
            .all(|alert| alert.rule_id != "unmatched_system_effect"));
        let dashboard = store.dashboard_state().unwrap();
        assert_eq!(dashboard["systemEvents"].as_array().unwrap().len(), 0);
        assert_eq!(dashboard["summary"]["system_events_count"], 0);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_surfaces_endpoint_sequence_gap_alerts() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-endpoint-gap-dashboard-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        let db = store.sqlite_store().unwrap();
        insert_alert(
            &db,
            AlertInput {
                request_id: None,
                entity: None,
                severity: "high",
                action: "warn",
                rule_id: "endpoint_security_event_gap",
                message: "legacy prototype sequence gap",
                path: None,
                evidence: None,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as i64,
            },
        )
        .unwrap();
        drop(db);

        let dashboard = store.dashboard_state().unwrap();
        assert_eq!(dashboard["alerts"].as_array().unwrap().len(), 1);
        assert_eq!(dashboard["summary"]["alerts_count"], 1);
        assert_eq!(dashboard["summary"]["recent_high_alerts"], 1);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn system_events_attach_when_path_matches_file_intent() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-system-match-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"write this"}"#,
                100,
            ))
            .unwrap();
        store
            .append_file_intent(&FileIntent {
                provider: "bash-command-parser".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_1".to_string()),
                observed_at_ms: 110,
                operation: "write".to_string(),
                path: "/tmp/gensee-agent-fileop/test.txt".to_string(),
                source_command: "echo hi > /tmp/gensee-agent-fileop/test.txt".to_string(),
                sensitive: false,
                confidence: "low".to_string(),
            })
            .unwrap();
        store
            .append_system_event(&SystemEvent {
                source: "macos-eslogger".to_string(),
                event_type: "write".to_string(),
                event_kind: "file_mutation".to_string(),
                observed_at_ms: 120,
                pid: Some(42),
                ppid: Some(1),
                process_name: Some("sh".to_string()),
                executable_path: Some("/bin/sh".to_string()),
                file_path: Some("/private/tmp/gensee-agent-fileop/test.txt".to_string()),
                command_line: None,
                raw_json: r#"{"event":{"write":{"target":{"path":"/private/tmp/gensee-agent-fileop/test.txt"}}}}"#.to_string(),
            })
            .unwrap();

        let db = store.sqlite_store().unwrap();
        let request = db.latest_request_for_session("s1").unwrap().unwrap();
        let system_events = db.system_events_for_request(request.request_id).unwrap();
        assert_eq!(system_events.len(), 1);
        assert_eq!(system_events[0].event_type, "write");
        assert_eq!(system_events[0].pid, 42);

        let agent_events = db.agent_events_for_request(request.request_id).unwrap();
        assert_eq!(agent_events.len(), 1);
        assert_eq!(agent_events[0].event_type, "file_intent");
        assert_eq!(agent_events[0].tool_name.as_deref(), Some("Bash"));

        let relations = db.relations_for_request(request.request_id).unwrap();
        assert_eq!(relations.len(), 1);
        assert!(relations
            .iter()
            .any(|relation| relation.src_kind == "request"
                && relation.src_id == request.request_id
                && relation.dst_kind == "artifact"
                && relation.relation_type == "produced"));

        let agent_relations = db
            .relations_for_entity("agent_event", agent_events[0].event_id)
            .unwrap();
        assert!(agent_relations
            .iter()
            .any(|relation| relation.dst_kind == "system_event"
                && relation.dst_id == system_events[0].event_id
                && relation.relation_type == "caused"));
        assert!(agent_relations.iter().any(
            |relation| relation.dst_kind == "artifact" && relation.relation_type == "produced"
        ));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn endpoint_runtime_noise_stays_in_audit_stream_but_out_of_lineage() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-endpoint-lineage-filter-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        let endpoint_event = |event_type: &str,
                              event_kind: &str,
                              path: &str,
                              mode: u64,
                              modified: Option<bool>,
                              observed_at_ms: u64| {
            let mut raw = json!({
                "action": "notify",
                "file": { "path": path, "mode": mode },
                "attribution": { "session_id": "claude-session" }
            });
            if let Some(modified) = modified {
                raw["modified"] = json!(modified);
            }
            SystemEvent {
                source: "macos-endpoint-security".to_string(),
                event_type: event_type.to_string(),
                event_kind: event_kind.to_string(),
                observed_at_ms,
                pid: Some(5311),
                ppid: Some(5310),
                process_name: Some("claude".to_string()),
                executable_path: Some("/Applications/Claude.app/Contents/MacOS/Claude".to_string()),
                file_path: Some(path.to_string()),
                command_line: None,
                raw_json: raw.to_string(),
            }
        };

        let ignored = [
            endpoint_event(
                "open",
                "file_read",
                "/Library/Preferences/Logging/com.apple.diagnosticd.filter.plist",
                0o100644,
                None,
                100,
            ),
            endpoint_event(
                "unlink",
                "file_mutation",
                "/Users/test/.claude/sessions/5311.json",
                0o100600,
                None,
                101,
            ),
            endpoint_event(
                "unlink",
                "file_mutation",
                "/private/tmp/cc-socks/5311.sock",
                0o140600,
                None,
                102,
            ),
            endpoint_event(
                "close",
                "system",
                "/repo/merely-read.txt",
                0o100644,
                Some(false),
                103,
            ),
            endpoint_event(
                "readdir",
                "file_read",
                "/Users/test/.claude/skills",
                0o040755,
                None,
                104,
            ),
        ];
        for event in &ignored {
            store.append_system_event(event).unwrap();
            assert!(store
                .artifact_fact_for_file(event.file_path.as_deref().unwrap())
                .unwrap()
                .is_none());
        }

        store
            .append_system_event(&endpoint_event(
                "write",
                "file_mutation",
                "/repo/src/lib.rs",
                0o100644,
                None,
                105,
            ))
            .unwrap();
        assert!(store
            .artifact_fact_for_file("/repo/src/lib.rs")
            .unwrap()
            .is_some());

        let dashboard = store.dashboard_state().unwrap();
        assert_eq!(dashboard["systemEvents"].as_array().unwrap().len(), 6);
        assert_eq!(dashboard["summary"]["artifacts_count"], 1);
        assert_eq!(dashboard["artifacts"].as_array().unwrap().len(), 1);
        assert_eq!(dashboard["artifacts"][0]["uri"], "file:///repo/src/lib.rs");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_hides_legacy_endpoint_runtime_artifacts() {
        let legacy_system_read = json!({
            "uri": "file:///System/Library/dyld/dyld_shared_cache_arm64e",
            "_observation_source": "macos-endpoint-security",
            "_observation_event_type": "open",
            "_observation_event_kind": null,
            "_observation_modified": null,
        });
        let real_system_mutation = json!({
            "uri": "file:///System/Library/example.conf",
            "_observation_source": "macos-endpoint-security",
            "_observation_event_type": "write",
            "_observation_event_kind": "file_mutation",
            "_observation_modified": null,
        });
        let project_artifact = json!({
            "uri": "file:///repo/src/lib.rs",
            "_observation_source": "macos-endpoint-security",
            "_observation_event_type": "write",
            "_observation_event_kind": "file_mutation",
            "_observation_modified": null,
        });

        assert!(!dashboard_artifact_is_visible(&legacy_system_read));
        assert!(!dashboard_artifact_is_visible(&real_system_mutation));
        assert!(dashboard_artifact_is_visible(&project_artifact));
    }

    #[test]
    fn dashboard_usr_local_bin_filter_matches_rust_predicate() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        for (path, expected_visible) in [
            ("/usr/local/bin", false),
            ("/usr/local/bin/gensee", false),
            ("/usr/local/binaries/tool", true),
            ("/usr/local/bin-old/x", true),
        ] {
            let rust_visible = !lineage_path_is_system_dependency(path);
            let sql = format!("SELECT {}", dashboard_path_visibility_sql("?1"));
            let sql_visible: bool = connection
                .query_row(&sql, [path], |row| row.get(0))
                .unwrap();
            assert_eq!(rust_visible, expected_visible, "Rust visibility for {path}");
            assert_eq!(sql_visible, expected_visible, "SQL visibility for {path}");
        }
    }

    #[test]
    fn dashboard_sql_filters_noise_before_applying_lineage_limits() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-dashboard-filter-limits-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        let db = store.sqlite_store().unwrap();
        let conn = db.connection();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();

        conn.execute(
            "INSERT INTO artifacts (kind, uri, digest) VALUES ('file', 'file:///repo/source', '')",
            [],
        )
        .unwrap();
        let clean_source = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO artifacts (kind, uri, digest) VALUES ('file', 'file:///repo/destination', '')",
            [],
        )
        .unwrap();
        let clean_destination = conn.last_insert_rowid();
        for index in 0..300 {
            conn.execute(
                "INSERT INTO relations (
                    src_kind, src_id, dst_kind, dst_id, relation_type, confidence, created_at
                 ) VALUES ('artifact', ?1, 'artifact', ?2, ?3, 1.0, ?4)",
                rusqlite::params![
                    clean_source,
                    clean_destination,
                    format!("clean-{index}"),
                    index
                ],
            )
            .unwrap();
        }

        conn.execute(
            "INSERT INTO artifacts (kind, uri, digest) VALUES ('file', 'file:///usr/lib/noise-a', '')",
            [],
        )
        .unwrap();
        let noise_source = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO artifacts (kind, uri, digest) VALUES ('file', 'file:///usr/lib/noise-b', '')",
            [],
        )
        .unwrap();
        let noise_destination = conn.last_insert_rowid();
        for index in 0..5_199 {
            conn.execute(
                "INSERT INTO relations (
                    src_kind, src_id, dst_kind, dst_id, relation_type, confidence, created_at
                 ) VALUES ('artifact', ?1, 'artifact', ?2, ?3, 1.0, ?4)",
                rusqlite::params![
                    noise_source,
                    noise_destination,
                    format!("noise-{index}"),
                    1_000 + index
                ],
            )
            .unwrap();
        }

        for index in 0..100 {
            conn.execute(
                "INSERT INTO artifact_facts (
                    kind, uri, last_seen_at, last_modified_source, metadata
                 ) VALUES ('file', ?1, ?2, 'macos-endpoint-security', ?3)",
                rusqlite::params![
                    format!("file:///repo/artifact-{index}"),
                    index,
                    r#"{"source":"macos-endpoint-security"}"#
                ],
            )
            .unwrap();
        }
        for index in 0..500 {
            conn.execute(
                "INSERT INTO artifact_facts (
                    kind, uri, last_seen_at, last_modified_source, metadata
                 ) VALUES ('file', ?1, ?2, 'macos-endpoint-security', ?3)",
                rusqlite::params![
                    format!("file:///System/Library/noise-{index}"),
                    1_000 + index,
                    r#"{"source":"macos-endpoint-security"}"#
                ],
            )
            .unwrap();
        }
        conn.execute_batch("COMMIT").unwrap();
        drop(db);

        let dashboard = store.dashboard_state().unwrap();
        let artifacts = dashboard["artifacts"].as_array().unwrap();
        let relations = dashboard["relations"].as_array().unwrap();
        assert_eq!(artifacts.len(), 80);
        assert_eq!(dashboard["summary"]["artifacts_count"], 80);
        assert!(artifacts.iter().all(|artifact| artifact["uri"]
            .as_str()
            .unwrap()
            .starts_with("file:///repo/")));
        assert_eq!(relations.len(), 200);
        assert!(relations.iter().all(|relation| {
            relation["src_uri"] == "file:///repo/source"
                && relation["dst_uri"] == "file:///repo/destination"
        }));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn derived_monitoring_records_write_to_database_events() {
        let dir =
            std::env::temp_dir().join(format!("gensee-store-test-derived-{}", std::process::id()));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"watch derived"}"#,
                100,
            ))
            .unwrap();
        store
            .append_process_observation(&ProcessObservation {
                provider: "process-sampler".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_1".to_string()),
                observed_at_ms: 110,
                pid: 99,
                ppid: 1,
                binary: "bash".to_string(),
                command: "ls".to_string(),
            })
            .unwrap();
        store
            .append_file_intent(&FileIntent {
                provider: "bash-command-parser".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_1".to_string()),
                observed_at_ms: 115,
                operation: "read".to_string(),
                path: "/repo/Cargo.toml".to_string(),
                source_command: "cat Cargo.toml".to_string(),
                sensitive: false,
                confidence: "low".to_string(),
            })
            .unwrap();
        store
            .append_workspace_effect(&WorkspaceEffect {
                source: "fsevents".to_string(),
                session_id: Some("s1".to_string()),
                workspace: "/repo".to_string(),
                path: "/repo/src/main.rs".to_string(),
                effect_type: "write".to_string(),
                observed_at_ms: 120,
                attribution: "watcher".to_string(),
                confidence: "medium".to_string(),
            })
            .unwrap();

        let request_relations = {
            let db = store.sqlite_store().unwrap();
            let request = db.latest_request_for_session("s1").unwrap().unwrap();
            let agent_events = db.agent_events_for_request(request.request_id).unwrap();
            let system_events = db.system_events_for_request(request.request_id).unwrap();

            assert_eq!(agent_events.len(), 1);
            assert_eq!(agent_events[0].event_type, "file_intent");
            assert_eq!(agent_events[0].tool_name.as_deref(), Some("Bash"));
            assert_eq!(
                serde_json::from_str::<Value>(agent_events[0].tool_input.as_deref().unwrap())
                    .unwrap()["path"],
                "/repo/Cargo.toml"
            );
            assert_eq!(system_events.len(), 2);
            assert_eq!(system_events[0].event_type, "process_observation");
            assert_eq!(system_events[0].pid, 99);
            assert_eq!(system_events[1].event_type, "write");
            assert_eq!(system_events[1].cwd, "/repo");
            db.relations_for_request(request.request_id).unwrap()
        };
        assert_eq!(request_relations.len(), 2);
        assert!(request_relations
            .iter()
            .any(|relation| relation.src_kind == "artifact"
                && relation.dst_kind == "request"
                && relation.relation_type == "consumed_by"));
        assert!(request_relations
            .iter()
            .any(|relation| relation.src_kind == "request"
                && relation.dst_kind == "artifact"
                && relation.relation_type == "produced"));
        let fact = store
            .artifact_fact_for_file("/repo/src/main.rs")
            .unwrap()
            .expect("workspace effect should update artifact facts");
        assert_eq!(fact.last_modified_source.as_deref(), Some("fsevents"));
        assert!(fact.is_unmatched_modified);
        assert_eq!(fact.recent_unmatched_effect_count, 1);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn artifact_consumption_links_requests_into_lineage() {
        let dir =
            std::env::temp_dir().join(format!("gensee-store-test-lineage-{}", std::process::id()));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"create input"}"#,
                100,
            ))
            .unwrap();
        store
            .append_file_intent(&FileIntent {
                provider: "bash-command-parser".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_1".to_string()),
                observed_at_ms: 110,
                operation: "write".to_string(),
                path: "/repo/doc.txt".to_string(),
                source_command: "echo doc > /repo/doc.txt".to_string(),
                sensitive: false,
                confidence: "low".to_string(),
            })
            .unwrap();
        let request_a = {
            let db = store.sqlite_store().unwrap();
            db.latest_request_for_session("s1").unwrap().unwrap()
        };

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"summarize input"}"#,
                200,
            ))
            .unwrap();
        store
            .append_file_intent(&FileIntent {
                provider: "bash-command-parser".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_2".to_string()),
                observed_at_ms: 210,
                operation: "read".to_string(),
                path: "/repo/doc.txt".to_string(),
                source_command: "cat /repo/doc.txt".to_string(),
                sensitive: false,
                confidence: "low".to_string(),
            })
            .unwrap();

        let db = store.sqlite_store().unwrap();
        let request_b = db.latest_request_for_session("s1").unwrap().unwrap();
        let request_b_relations = db.relations_for_request(request_b.request_id).unwrap();

        assert!(request_b_relations
            .iter()
            .any(|relation| relation.src_kind == "artifact"
                && relation.dst_kind == "request"
                && relation.dst_id == request_b.request_id
                && relation.relation_type == "consumed_by"));
        assert!(request_b_relations
            .iter()
            .any(|relation| relation.src_kind == "request"
                && relation.src_id == request_a.request_id
                && relation.dst_kind == "request"
                && relation.dst_id == request_b.request_id
                && relation.relation_type == "derived_from"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn request_read_after_write_does_not_self_consume_artifact() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-self-consume-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"create and verify input"}"#,
                100,
            ))
            .unwrap();
        store
            .append_file_intent(&FileIntent {
                provider: "bash-command-parser".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_1".to_string()),
                observed_at_ms: 110,
                operation: "write".to_string(),
                path: "/repo/doc.txt".to_string(),
                source_command: "printf hello > /repo/doc.txt && cat /repo/doc.txt".to_string(),
                sensitive: false,
                confidence: "low".to_string(),
            })
            .unwrap();
        store
            .append_file_intent(&FileIntent {
                provider: "bash-command-parser".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_1".to_string()),
                observed_at_ms: 111,
                operation: "read".to_string(),
                path: "/repo/doc.txt".to_string(),
                source_command: "printf hello > /repo/doc.txt && cat /repo/doc.txt".to_string(),
                sensitive: false,
                confidence: "low".to_string(),
            })
            .unwrap();

        let db = store.sqlite_store().unwrap();
        let request = db.latest_request_for_session("s1").unwrap().unwrap();
        let request_relations = db.relations_for_request(request.request_id).unwrap();

        assert!(request_relations
            .iter()
            .any(|relation| relation.src_kind == "request"
                && relation.dst_kind == "artifact"
                && relation.relation_type == "produced"));
        assert!(!request_relations
            .iter()
            .any(|relation| relation.src_kind == "artifact"
                && relation.dst_kind == "request"
                && relation.relation_type == "consumed_by"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn native_file_tools_link_requests_into_lineage() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-native-lineage-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"write input"}"#,
                100,
            ))
            .unwrap();
        store
            .append_hook_event(&native_tool_event(
                "Write",
                "tool_write",
                r#"{"file_path":"/repo/doc.txt","content":"hello"}"#,
                110,
            ))
            .unwrap();
        let request_a = {
            let db = store.sqlite_store().unwrap();
            db.latest_request_for_session("s1").unwrap().unwrap()
        };

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"read input"}"#,
                200,
            ))
            .unwrap();
        store
            .append_hook_event(&native_tool_event(
                "Read",
                "tool_read",
                r#"{"file_path":"/repo/doc.txt"}"#,
                210,
            ))
            .unwrap();
        store
            .append_hook_event(&native_tool_event(
                "Write",
                "tool_summary",
                r#"{"file_path":"/repo/summary.txt","content":"summary"}"#,
                220,
            ))
            .unwrap();

        let db = store.sqlite_store().unwrap();
        let request_b = db.latest_request_for_session("s1").unwrap().unwrap();
        let request_b_relations = db.relations_for_request(request_b.request_id).unwrap();
        let agent_events = db.agent_events_for_request(request_b.request_id).unwrap();

        assert_eq!(agent_events[0].tool_name.as_deref(), Some("Read"));
        assert_eq!(
            serde_json::from_str::<Value>(agent_events[0].tool_input.as_deref().unwrap()).unwrap()
                ["path"],
            "/repo/doc.txt"
        );
        assert!(request_b_relations
            .iter()
            .any(|relation| relation.src_kind == "artifact"
                && relation.dst_kind == "request"
                && relation.dst_id == request_b.request_id
                && relation.relation_type == "consumed_by"));
        assert!(request_b_relations
            .iter()
            .any(|relation| relation.src_kind == "request"
                && relation.src_id == request_a.request_id
                && relation.dst_kind == "request"
                && relation.dst_id == request_b.request_id
                && relation.relation_type == "derived_from"));
        let input_artifact_id = request_b_relations
            .iter()
            .find(|relation| {
                relation.src_kind == "artifact"
                    && relation.dst_kind == "request"
                    && relation.dst_id == request_b.request_id
                    && relation.relation_type == "consumed_by"
            })
            .map(|relation| relation.src_id)
            .unwrap();
        let summary_artifact_id = request_b_relations
            .iter()
            .find(|relation| {
                relation.src_kind == "request"
                    && relation.src_id == request_b.request_id
                    && relation.dst_kind == "artifact"
                    && relation.relation_type == "produced"
            })
            .map(|relation| relation.dst_id)
            .unwrap();
        let input_relations = db
            .relations_for_entity("artifact", input_artifact_id)
            .unwrap();
        assert!(input_relations
            .iter()
            .any(|relation| relation.src_kind == "artifact"
                && relation.src_id == input_artifact_id
                && relation.dst_kind == "artifact"
                && relation.dst_id == summary_artifact_id
                && relation.relation_type == "derived_from"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn vscode_runtime_read_file_stores_path_and_lineage() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-vscode-read-lineage-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"read input"}"#,
                100,
            ))
            .unwrap();
        let mut read_event = native_tool_event(
            "read_file",
            "vscode_read",
            r#"{"filePath":"src/lib.rs","startLine":1,"endLine":20}"#,
            110,
        );
        read_event.provider = "vscode".to_string();
        store.append_hook_event(&read_event).unwrap();

        let db = store.sqlite_store().unwrap();
        let request = db.latest_request_for_session("s1").unwrap().unwrap();
        let agent_events = db.agent_events_for_request(request.request_id).unwrap();
        let tool_input =
            serde_json::from_str::<Value>(agent_events[0].tool_input.as_deref().unwrap()).unwrap();
        assert_eq!(tool_input["operation"], "read");
        assert_eq!(tool_input["path"], "/repo/src/lib.rs");

        let relations = db.relations_for_request(request.request_id).unwrap();
        assert!(relations.iter().any(|relation| {
            relation.src_kind == "artifact"
                && relation.dst_kind == "request"
                && relation.dst_id == request.request_id
                && relation.relation_type == "consumed_by"
        }));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn vscode_search_tools_store_only_safe_query_metadata() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-vscode-search-input-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"find code"}"#,
                100,
            ))
            .unwrap();
        for (index, tool_name) in ["file_search", "grep_search"].iter().enumerate() {
            let mut event = native_tool_event(
                tool_name,
                &format!("vscode_search_{index}"),
                r#"{"query":"macos support","includePattern":"**/*.rs","maxResults":200}"#,
                110 + index as u64,
            );
            event.provider = "vscode".to_string();
            store.append_hook_event(&event).unwrap();
        }

        let db = store.sqlite_store().unwrap();
        let request = db.latest_request_for_session("s1").unwrap().unwrap();
        let agent_events = db.agent_events_for_request(request.request_id).unwrap();
        assert_eq!(agent_events.len(), 2);
        for event in agent_events {
            let input =
                serde_json::from_str::<Value>(event.tool_input.as_deref().unwrap()).unwrap();
            assert_eq!(input["query"], "macos support");
            assert_eq!(input.as_object().unwrap().len(), 2);
            assert!(input.get("includePattern").is_none());
            assert!(input.get("maxResults").is_none());
        }

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mcp_file_tools_link_requests_into_lineage() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-mcp-lineage-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"write input"}"#,
                100,
            ))
            .unwrap();
        store
            .append_hook_event(&native_tool_event(
                "mcp__filesystem__write_file",
                "mcp_write",
                r#"{"path":"data/input.txt","content":"hello"}"#,
                110,
            ))
            .unwrap();
        let request_a = {
            let db = store.sqlite_store().unwrap();
            db.latest_request_for_session("s1").unwrap().unwrap()
        };

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"read input"}"#,
                200,
            ))
            .unwrap();
        store
            .append_hook_event(&native_tool_event(
                "mcp__filesystem__read_file",
                "mcp_read",
                r#"{"file_path":"data/input.txt"}"#,
                210,
            ))
            .unwrap();

        let db = store.sqlite_store().unwrap();
        let request_b = db.latest_request_for_session("s1").unwrap().unwrap();
        let agent_events = db.agent_events_for_request(request_b.request_id).unwrap();
        let request_b_relations = db.relations_for_request(request_b.request_id).unwrap();

        assert_eq!(
            serde_json::from_str::<Value>(agent_events[0].tool_input.as_deref().unwrap()).unwrap()
                ["path"],
            "/repo/data/input.txt"
        );
        assert!(request_b_relations.iter().any(|relation| {
            relation.src_kind == "artifact"
                && relation.dst_kind == "request"
                && relation.dst_id == request_b.request_id
                && relation.relation_type == "consumed_by"
        }));
        assert!(request_b_relations.iter().any(|relation| {
            relation.src_kind == "request"
                && relation.src_id == request_a.request_id
                && relation.dst_kind == "request"
                && relation.dst_id == request_b.request_id
                && relation.relation_type == "derived_from"
        }));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_patch_native_tool_links_all_changed_paths_into_lineage() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-apply-patch-lineage-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        let patch = r#"*** Begin Patch
*** Add File: src/new.rs
+fn new() {}
*** Update File: src/../lib.rs
@@
-old
+new
*** Delete File: src/old.rs
*** Update File: src/from.rs
*** Move to: src/to.rs
@@
-from
+to
*** End Patch"#;

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"apply patch"}"#,
                100,
            ))
            .unwrap();
        store
            .append_hook_event(&native_tool_event(
                "apply_patch",
                "patch_1",
                &json!({ "input": patch }).to_string(),
                110,
            ))
            .unwrap();

        let db = store.sqlite_store().unwrap();
        let request = db.latest_request_for_session("s1").unwrap().unwrap();
        let relations = db.relations_for_request(request.request_id).unwrap();
        let agent_events = db.agent_events_for_request(request.request_id).unwrap();
        let tool_input =
            serde_json::from_str::<Value>(agent_events[0].tool_input.as_deref().unwrap()).unwrap();

        assert_eq!(tool_input["changes"].as_array().unwrap().len(), 5);
        for (path, relation_type) in [
            ("/repo/src/new.rs", "produced"),
            ("/repo/lib.rs", "modified"),
            ("/repo/src/old.rs", "deleted"),
            ("/repo/src/from.rs", "deleted"),
            ("/repo/src/to.rs", "produced"),
        ] {
            let artifact = db
                .artifact_by_kind_uri_digest("file", &file_uri(path), "")
                .unwrap()
                .unwrap();
            assert!(
                relations.iter().any(|relation| {
                    relation.src_kind == "request"
                        && relation.src_id == request.request_id
                        && relation.dst_kind == "artifact"
                        && relation.dst_id == artifact.artifact_id
                        && relation.relation_type == relation_type
                }),
                "missing {relation_type} relation for {path}"
            );
        }

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn synthetic_producers_do_not_create_request_lineage() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-synthetic-lineage-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_workspace_effect(&WorkspaceEffect {
                source: "gensee-watch-fsevents".to_string(),
                session_id: Some("watch_1".to_string()),
                workspace: "/repo".to_string(),
                path: "/repo/watched.txt".to_string(),
                effect_type: "write".to_string(),
                observed_at_ms: 100,
                attribution: "workspace/fsevents time inference".to_string(),
                confidence: "medium".to_string(),
            })
            .unwrap();
        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"read watched file"}"#,
                200,
            ))
            .unwrap();
        store
            .append_hook_event(&native_tool_event(
                "Read",
                "tool_read",
                r#"{"file_path":"/repo/watched.txt"}"#,
                210,
            ))
            .unwrap();

        let db = store.sqlite_store().unwrap();
        let request = db.latest_request_for_session("s1").unwrap().unwrap();
        let relations = db.relations_for_request(request.request_id).unwrap();

        assert!(relations
            .iter()
            .any(|relation| relation.src_kind == "artifact"
                && relation.dst_kind == "request"
                && relation.dst_id == request.request_id
                && relation.relation_type == "consumed_by"));
        assert!(!relations
            .iter()
            .any(|relation| relation.relation_type == "derived_from"));

        fs::remove_dir_all(&dir).ok();
    }

    fn hook_event(hook_event_name: &str, raw_json: &str, observed_at_ms: u64) -> AgentHookEvent {
        AgentHookEvent {
            provider: "claude-code".to_string(),
            session_id: Some("s1".to_string()),
            hook_event_name: Some(hook_event_name.to_string()),
            cwd: Some("/repo".to_string()),
            transcript_path: None,
            tool_name: None,
            tool_use_id: None,
            tool_input_command: None,
            tool_input_description: None,
            tool_response_stdout: None,
            tool_response_stderr: None,
            tool_response_interrupted: None,
            duration_ms: None,
            permission_mode: None,
            effort_level: None,
            observed_at_ms,
            raw_json: raw_json.to_string(),
        }
    }

    fn native_tool_event(
        tool_name: &str,
        tool_use_id: &str,
        tool_input: &str,
        observed_at_ms: u64,
    ) -> AgentHookEvent {
        let raw_json = format!(
            r#"{{"session_id":"s1","hook_event_name":"PreToolUse","cwd":"/repo","tool_name":"{tool_name}","tool_use_id":"{tool_use_id}","tool_input":{tool_input}}}"#
        );
        AgentHookEvent {
            provider: "claude-code".to_string(),
            session_id: Some("s1".to_string()),
            hook_event_name: Some("PreToolUse".to_string()),
            cwd: Some("/repo".to_string()),
            transcript_path: None,
            tool_name: Some(tool_name.to_string()),
            tool_use_id: Some(tool_use_id.to_string()),
            tool_input_command: None,
            tool_input_description: None,
            tool_response_stdout: None,
            tool_response_stderr: None,
            tool_response_interrupted: None,
            duration_ms: None,
            permission_mode: None,
            effort_level: None,
            observed_at_ms,
            raw_json,
        }
    }
}
