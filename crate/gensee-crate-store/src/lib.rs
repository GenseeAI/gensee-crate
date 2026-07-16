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
    NewSession, NewSystemEvent, SqliteConfig, SqliteError, SqliteStore,
};
pub use gensee_crate_db::sqlite::{
    AlertRecord, ArtifactFactRecord, ArtifactObservationRecord, ArtifactRiskTagRecord,
    ChainVerification, HumanFeedbackRecord,
};
use gensee_crate_rules::policy::Policy;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
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
        let db = self.sqlite_store()?;
        db.insert_session(&NewSession {
            session_id: session.session_id.clone(),
            agent_id: session.agent_binary.clone(),
            first_event_at: to_i64(session.started_at_ms)?,
            last_event_at: session.ended_at_ms.map(to_i64).transpose()?,
            flagged: false,
        })
        .map_err(sqlite_error)?;
        append_jsonl(&self.sessions_path(), session, self.encryption_key.as_ref())
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

    pub fn list_sessions(&self) -> io::Result<Vec<AgentSession>> {
        read_jsonl(&self.sessions_path(), self.encryption_key.as_ref())
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

    pub fn dashboard_state(&self) -> io::Result<Value> {
        let db = self.sqlite_store()?;
        let conn = db.connection();
        let alerts = query_json_rows(
            conn,
            "SELECT alert_id, alerts.request_id, entity_kind, entity_id, severity,
                action, rule_id, message, path, evidence, created_at,
                requests.session_id
             FROM alerts
             LEFT JOIN requests ON requests.request_id = alerts.request_id
             ORDER BY created_at DESC, alert_id DESC
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
                }))
            },
        )?;
        let agent_events = query_json_rows(
            conn,
            "SELECT event_id, pid, agent_events.request_id, requests.session_id, ts,
                source, type, cwd, permission_mode, tool_name, tool_input, tool_use_id
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
                    "tool_use_id": row.get::<_, Option<String>>(11)?,
                }))
            },
        )?;
        let system_events = query_json_rows(
            conn,
            "SELECT event_id, pid, request_id, ts, source, type, cwd, args
             FROM system_events
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
            "SELECT session_id, agent_id, first_event_at, last_event_at, flagged
             FROM sessions
             ORDER BY COALESCE(last_event_at, first_event_at) DESC
             LIMIT 20",
            |row| {
                Ok(json!({
                    "session_id": row.get::<_, String>(0)?,
                    "agent_id": row.get::<_, String>(1)?,
                    "first_event_at": row.get::<_, i64>(2)?,
                    "last_event_at": row.get::<_, Option<i64>>(3)?,
                    "flagged": row.get::<_, i64>(4)?,
                }))
            },
        )?;
        let artifacts = query_json_rows(
            conn,
            "SELECT kind, uri, current_digest, last_seen_at, last_modified_at,
                last_modified_source, last_modified_session_id, risk_level,
                risk_rule_id, is_agent_authored, is_unmatched_modified,
                is_memory_artifact, is_persistent_target, is_control_plane
             FROM artifact_facts
             ORDER BY last_seen_at DESC
             LIMIT 80",
            |row| {
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
                }))
            },
        )?;
        let relations = query_json_rows(
            conn,
            "SELECT r.relation_type AS type, r.confidence AS confidence,
                sa.uri AS src_uri, da.uri AS dst_uri
             FROM relations r
             JOIN artifacts sa ON r.src_kind = 'artifact' AND r.src_id = sa.artifact_id
             JOIN artifacts da ON r.dst_kind = 'artifact' AND r.dst_id = da.artifact_id
             ORDER BY r.relation_id DESC
             LIMIT 200",
            |row| {
                Ok(json!({
                    "type": row.get::<_, String>(0)?,
                    "confidence": row.get::<_, f64>(1)?,
                    "src_uri": row.get::<_, String>(2)?,
                    "dst_uri": row.get::<_, String>(3)?,
                }))
            },
        )?;
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
        Ok(json!({
            "source": "gensee",
            "alerts": alerts,
            "agentEvents": agent_events,
            "systemEvents": system_events,
            "sessions": sessions,
            "artifacts": artifacts,
            "relations": relations,
            "humanFeedback": human_feedback,
            "hookEvents": self.list_hook_events()?,
            "workspaceEffects": self.list_workspace_effects()?,
            "jsonSessions": self.list_sessions()?,
        }))
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
        self.with_sqlite_transaction(|db| {
            let session_id = event.session_id.as_deref().unwrap_or(UNKNOWN_SESSION_ID);
            ensure_session(db, session_id, &event.provider, event.observed_at_ms)?;

            match event.hook_event_name.as_deref() {
                Some("UserPromptSubmit") => {
                    db.insert_request(&NewRequest {
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
                }
                Some("Stop") => {
                    let response = text_from_raw_json(&event.raw_json, &["last_assistant_message"]);
                    if let Some(request) = db
                        .latest_request_for_session(session_id)
                        .map_err(sqlite_error)?
                    {
                        db.set_request_response(request.request_id, response.as_deref())
                            .map_err(sqlite_error)?;
                    } else {
                        db.insert_request(&NewRequest {
                            session_id: session_id.to_string(),
                            original_user_prompt: None,
                            final_response: response,
                            events: Some(event.raw_json.clone()),
                            file_accessed_rate: 0.0,
                            network_rate: 0.0,
                        })
                        .map_err(sqlite_error)?;
                    }
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
            let request_id = match &matched_agent_event {
                Some(agent_event) => agent_event.request_id,
                None => system_request_id(db, event.observed_at_ms)?,
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
            let matched = matched_agent_event.is_some();
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
            record_system_event_artifacts(db, request_id, event_id, event, ts, matched)?;
            if !matched {
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
        first_event_at: to_i64(observed_at_ms)?,
        last_event_at: None,
        flagged: false,
    })
    .map_err(sqlite_error)
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
    let relation_type = system_artifact_relation_type(&event.event_type);
    let request_relation_type = request_artifact_relation_type(&event.event_type);
    for path in system_event_paths(event) {
        let artifact_id = upsert_file_artifact(
            db,
            &path,
            ts,
            Some(json!({
                "source": event.source,
                "system_event_type": event.event_type,
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

fn system_artifact_relation_type(event_type: &str) -> &'static str {
    match event_type {
        "open" | "lookup" | "access" | "stat" | "getattrlist" | "readlink" | "readdir"
        | "getextattr" | "listextattr" | "fsgetpath" => "read_by",
        "unlink" => "deleted",
        "setmode" | "setowner" | "setflags" | "setacl" | "setextattr" | "deleteextattr" => {
            "modified"
        }
        _ => "wrote",
    }
}

fn request_artifact_relation_type(event_type: &str) -> &'static str {
    match event_type {
        "open" | "lookup" | "access" | "stat" | "getattrlist" | "readlink" | "readdir"
        | "getextattr" | "listextattr" | "fsgetpath" => "consumed_by",
        "unlink" => "deleted",
        "setmode" | "setowner" | "setflags" | "setacl" | "setextattr" | "deleteextattr" => {
            "modified"
        }
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

fn tool_response_json(event: &AgentHookEvent) -> Option<String> {
    if event.tool_response_stdout.is_none()
        && event.tool_response_stderr.is_none()
        && event.tool_response_interrupted.is_none()
        && event.duration_ms.is_none()
    {
        return None;
    }

    Some(
        json!({
            "stdout": event.tool_response_stdout.as_deref(),
            "stderr": event.tool_response_stderr.as_deref(),
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
