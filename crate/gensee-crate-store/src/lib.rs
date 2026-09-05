use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use gensee_crate_core::{
    endpoint_security_path_is_known_build_output, extract_apply_patch_input, normalize_agent_path,
    parse_apply_patch_changes, parse_mcp_file_intents, parse_vscode_file_intents, AgentHookEvent,
    AgentSession, ExecutionOrigin, FileIntent, ProcessObservation, SystemEvent, WorkspaceEffect,
};
use gensee_crate_db::sqlite::{
    artifact_path_is_concrete, dashboard_artifact_is_visible as dashboard_artifact_path_is_visible,
    lineage_mode_is_non_file, lineage_path_is_harness_runtime_noise,
    lineage_path_is_system_dependency, open_store, AgentEventRecord,
    ArtifactVisibilityMigrationResult, NewAgentEvent, NewAlert, NewArtifact, NewArtifactFact,
    NewArtifactObservation, NewArtifactRiskTag, NewHumanFeedback, NewRelation, NewRequest,
    NewSession, NewSystemEvent, NewTransactionEvent, RetentionPruneResult, SqliteConfig,
    SqliteError, SqliteStore, TranscriptTokenStateRecord,
};
pub use gensee_crate_db::sqlite::{
    AlertRecord, ArtifactFactRecord, ArtifactObservationRecord, ArtifactRiskTagRecord,
    ChainVerification, HumanFeedbackRecord,
};
use gensee_crate_rules::policy::Policy;
use rusqlite::{functions::FunctionFlags, OptionalExtension};
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
use std::time::{Duration, Instant};

pub const DEFAULT_RETENTION_DAYS: u32 = 7;
pub const ENDPOINT_RETENTION_PRUNE_BATCH: u64 = 500;
const FALCO_RETENTION_PRUNE_BATCH: u64 = 500;
const FALCO_RETENTION_TIME_BUDGET: Duration = Duration::from_millis(50);
pub const ARTIFACT_VISIBILITY_MIGRATION_BATCH: u64 = 1_000;
pub const ARTIFACT_VISIBILITY_MAINTENANCE_INTERVAL_MS: u64 = 1_000;
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
const MAX_DASHBOARD_PROMPT_CHARS: usize = 1024;
const MAX_DASHBOARD_REQUEST_FILE_TOUCHES: usize = 32;
const MAX_DASHBOARD_FILE_TOUCH_CANDIDATES: usize = 128;
const MAX_DASHBOARD_IGNORED_FILE_TOUCH_EVENTS: usize = 5_000;
const MAX_DASHBOARD_IGNORED_FILE_TOUCH_PATHS: usize = 500;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSystemEvent {
    pub event_id: i64,
    pub source: String,
    pub event_type: String,
    pub observed_at_ms: u64,
    pub pid: Option<u32>,
    pub execution_origin: ExecutionOrigin,
    pub raw_json: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveToolCall {
    pub session_id: String,
    pub provider: String,
    pub tool_use_id: Option<String>,
    pub started_at_ms: u64,
    pub cwd: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveRequestContext {
    pub request_id: i64,
    pub original_user_prompt: Option<String>,
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

    /// Open a distinct SQLite connection to the same event-store root. Long-running
    /// maintenance uses this so it never holds an ingester's in-process mutex.
    pub fn independent_connection(&self) -> io::Result<Self> {
        Self::new(&self.root)
    }

    pub fn sessions_path(&self) -> PathBuf {
        self.root.join("sessions.jsonl")
    }

    pub fn database_path(&self) -> PathBuf {
        database_path_for_root(&self.root)
    }

    pub fn completion_signal_path(&self) -> PathBuf {
        self.root.join("completion.signal")
    }

    /// Wake local UI consumers after a request lifecycle completes. This file
    /// contains no prompt or tool data; its modification time is only a cheap
    /// edge-trigger so clients can fetch the encrypted request projection.
    pub fn signal_request_completion(&self, observed_at_ms: u64) -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(self.completion_signal_path())?;
        writeln!(file, "{observed_at_ms}")
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

    pub fn active_request_context(
        &self,
        session_id: &str,
    ) -> io::Result<Option<ActiveRequestContext>> {
        self.sqlite_store()?
            .latest_request_for_session(session_id)
            .map(|request| {
                request.map(|request| ActiveRequestContext {
                    request_id: request.request_id,
                    original_user_prompt: request.original_user_prompt,
                })
            })
            .map_err(sqlite_error)
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
        // Native kernel telemetry is already durable in SQLite and can be
        // pruned transactionally. Duplicating these high-volume streams into an
        // append-only JSONL file made retention ineffective and could consume
        // gigabytes during an event burst. Keep JSONL only for legacy sources.
        if matches!(
            event.source.as_str(),
            "macos-endpoint-security" | "linux-falco"
        ) {
            return Ok(());
        }
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

    pub fn list_native_system_events(
        &self,
        session_id: Option<&str>,
        path_contains: Option<&str>,
        min_observed_at_ms: i64,
        max_observed_at_ms: i64,
        limit: usize,
    ) -> io::Result<Vec<StoredSystemEvent>> {
        let db = self.sqlite_store()?;
        let rows = db
            .system_events_for_sources(
                &["macos-endpoint-security", "linux-falco"],
                session_id,
                path_contains,
                min_observed_at_ms,
                max_observed_at_ms,
                i64::try_from(limit).unwrap_or(i64::MAX),
            )
            .map_err(sqlite_error)?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let observed_at_ms = match u64::try_from(row.ts) {
                    Ok(timestamp) => timestamp,
                    Err(_) => {
                        eprintln!(
                            "gensee: skipping SQLite system event {} with negative timestamp {}",
                            row.event_id, row.ts
                        );
                        return None;
                    }
                };
                Some(StoredSystemEvent {
                    event_id: row.event_id,
                    source: row.source,
                    event_type: row.event_type,
                    observed_at_ms,
                    pid: u32::try_from(row.pid).ok().filter(|pid| *pid != 0),
                    execution_origin: ExecutionOrigin::from_label(&row.execution_origin),
                    raw_json: row.args.unwrap_or_else(|| "null".to_string()),
                })
            })
            .collect::<Vec<_>>())
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

    pub fn has_recent_mutating_file_intent(
        &self,
        path: &str,
        observed_at_ms: u64,
    ) -> io::Result<bool> {
        let db = self.sqlite_store()?;
        let ts = to_i64(observed_at_ms)?;
        db.request_for_mutating_file_intent_path(path, ts, SYSTEM_EVENT_CORRELATION_WINDOW_MS)
            .map(|event| event.is_some())
            .map_err(sqlite_error)
    }

    /// Resolve an exact, recent hook-declared file intent back to its tool
    /// call. Some desktop harness file tools perform the mutation in a helper
    /// outside the registered agent subtree; the exact path declaration is the
    /// strongest safe fallback for correlating the globally observed OS event.
    pub fn tool_call_for_recent_file_intent(
        &self,
        path: &str,
        observed_at_ms: u64,
        window_ms: u64,
    ) -> io::Result<Option<ActiveToolCall>> {
        let db = self.sqlite_store()?;
        let observed_at = to_i64(observed_at_ms)?;
        let window = to_i64(window_ms)?;
        db.connection()
            .query_row(
                "SELECT requests.session_id,
                        COALESCE(candidate.source, intent.source),
                        intent.tool_use_id, intent.ts,
                        COALESCE(NULLIF(candidate.cwd, ''), '')
                 FROM agent_events AS intent
                 JOIN requests ON requests.request_id = intent.request_id
                 LEFT JOIN agent_events AS candidate
                   ON candidate.request_id = intent.request_id
                  AND candidate.type IN ('PreToolUse', 'PermissionRequest')
                  AND (
                    (intent.tool_use_id IS NOT NULL
                     AND candidate.tool_use_id = intent.tool_use_id)
                    OR (intent.tool_use_id IS NULL
                        AND candidate.tool_use_id IS NULL)
                  )
                 WHERE intent.type = 'file_intent'
                   AND CASE WHEN json_valid(intent.tool_input)
                            THEN json_extract(intent.tool_input, '$.path')
                            ELSE NULL END = ?1
                   AND intent.ts <= ?2
                   AND intent.ts >= ?2 - ?3
                 ORDER BY intent.ts DESC, candidate.ts DESC, intent.event_id DESC
                 LIMIT 1",
                rusqlite::params![path, observed_at, window],
                |row| {
                    Ok(ActiveToolCall {
                        session_id: row.get(0)?,
                        provider: row.get(1)?,
                        tool_use_id: row.get(2)?,
                        started_at_ms: u64::try_from(row.get::<_, i64>(3)?).unwrap_or_default(),
                        cwd: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(SqliteError::Database)
            .map_err(sqlite_error)
    }

    /// Returns a hook tool call that started before the OS event, has not yet
    /// completed or been blocked, and is still inside a bounded correlation
    /// window. Endpoint Security findings must not be attached to an idle turn.
    pub fn active_tool_call(
        &self,
        session_id: &str,
        observed_at_ms: u64,
        window_ms: u64,
    ) -> io::Result<Option<ActiveToolCall>> {
        let db = self.sqlite_store()?;
        let observed_at = to_i64(observed_at_ms)?;
        let window = to_i64(window_ms)?;
        db.connection()
            .query_row(
                "SELECT requests.session_id, candidate.source, candidate.tool_use_id,
                        candidate.ts, candidate.cwd
                 FROM agent_events AS candidate
                 JOIN requests ON requests.request_id = candidate.request_id
                 WHERE requests.session_id = ?1
                   AND candidate.type IN ('PreToolUse', 'PermissionRequest')
                   AND candidate.ts <= ?2
                   AND candidate.ts >= ?2 - ?3
                   AND NOT EXISTS (
                     SELECT 1
                     FROM agent_events AS completion
                     WHERE completion.request_id = candidate.request_id
                       AND completion.type IN ('PostToolUse', 'PostToolUseFailure')
                       AND completion.ts >= candidate.ts
                       AND completion.ts <= ?2
                       AND (
                         (candidate.tool_use_id IS NOT NULL
                          AND completion.tool_use_id = candidate.tool_use_id)
                         OR (candidate.tool_use_id IS NULL
                             AND completion.tool_use_id IS NULL)
                       )
                   )
                   AND NOT EXISTS (
                     SELECT 1
                     FROM alerts
                     WHERE alerts.request_id = candidate.request_id
                       AND alerts.action = 'block'
                       AND alerts.created_at >= candidate.ts
                       AND alerts.created_at <= ?2
                       AND (
                         candidate.tool_use_id IS NULL
                         OR json_extract(alerts.evidence, '$.tool_use_id') = candidate.tool_use_id
                       )
                   )
                 ORDER BY candidate.ts DESC, candidate.event_id DESC
                 LIMIT 1",
                rusqlite::params![session_id, observed_at, window],
                |row| {
                    Ok(ActiveToolCall {
                        session_id: row.get(0)?,
                        provider: row.get(1)?,
                        tool_use_id: row.get(2)?,
                        started_at_ms: u64::try_from(row.get::<_, i64>(3)?).unwrap_or_default(),
                        cwd: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(SqliteError::Database)
            .map_err(sqlite_error)
    }

    /// Resolve the active hook tool call dynamically for a process root. The
    /// ChatGPT desktop app can run several concurrent Codex tasks beneath one
    /// long-lived Codex PID, so a root PID cannot be permanently assigned to a
    /// single session. Prefer the most recently-started still-open tool window.
    pub fn active_tool_call_for_root_pid(
        &self,
        root_pid: u32,
        observed_at_ms: u64,
        window_ms: u64,
    ) -> io::Result<Option<ActiveToolCall>> {
        self.active_tool_call_for_root_pid_at_path(root_pid, None, observed_at_ms, window_ms, 0)
    }

    /// Resolve an active tool window for a shared process root, preferring the
    /// request whose declared path or workspace contains the OS-observed path.
    /// This disambiguates concurrent Codex tasks hosted by one ChatGPT process.
    pub fn active_tool_call_for_root_pid_at_path(
        &self,
        root_pid: u32,
        path: Option<&str>,
        observed_at_ms: u64,
        window_ms: u64,
        completion_grace_ms: u64,
    ) -> io::Result<Option<ActiveToolCall>> {
        let db = self.sqlite_store()?;
        let observed_at = to_i64(observed_at_ms)?;
        let window = to_i64(window_ms)?;
        db.connection()
            .query_row(
                "SELECT requests.session_id, candidate.source, candidate.tool_use_id,
                        candidate.ts, candidate.cwd
                 FROM agent_events AS candidate
                 JOIN requests ON requests.request_id = candidate.request_id
                 JOIN sessions ON sessions.session_id = requests.session_id
                 WHERE sessions.root_pid = ?1
                   AND candidate.type IN ('PreToolUse', 'PermissionRequest')
                   AND candidate.ts <= ?2
                   AND candidate.ts >= ?2 - ?3
                   AND NOT EXISTS (
                     SELECT 1
                     FROM agent_events AS completion
                     WHERE completion.request_id = candidate.request_id
                       AND completion.type IN ('PostToolUse', 'PostToolUseFailure')
                       AND completion.ts >= candidate.ts
                       AND completion.ts <= ?2 - ?5
                       AND (
                         (candidate.tool_use_id IS NOT NULL
                          AND completion.tool_use_id = candidate.tool_use_id)
                         OR (candidate.tool_use_id IS NULL
                             AND completion.tool_use_id IS NULL)
                       )
                   )
                   AND NOT EXISTS (
                     SELECT 1
                     FROM alerts
                     WHERE alerts.request_id = candidate.request_id
                       AND alerts.action = 'block'
                       AND alerts.created_at >= candidate.ts
                       AND alerts.created_at <= ?2
                       AND (
                         candidate.tool_use_id IS NULL
                         OR json_extract(alerts.evidence, '$.tool_use_id') = candidate.tool_use_id
                       )
                   )
                 ORDER BY
                   CASE
                     WHEN ?4 IS NOT NULL
                      AND CASE WHEN json_valid(candidate.tool_input)
                               THEN json_extract(candidate.tool_input, '$.path')
                               ELSE NULL END = ?4
                       THEN 1000000
                     WHEN ?4 IS NOT NULL
                      AND (?4 = rtrim(candidate.cwd, '/')
                           OR ?4 LIKE rtrim(candidate.cwd, '/') || '/%')
                       THEN length(rtrim(candidate.cwd, '/'))
                     ELSE 0
                   END DESC,
                   candidate.ts DESC, candidate.event_id DESC
                 LIMIT 1",
                rusqlite::params![
                    i64::from(root_pid),
                    observed_at,
                    window,
                    path,
                    to_i64(completion_grace_ms)?
                ],
                |row| {
                    Ok(ActiveToolCall {
                        session_id: row.get(0)?,
                        provider: row.get(1)?,
                        tool_use_id: row.get(2)?,
                        started_at_ms: u64::try_from(row.get::<_, i64>(3)?).unwrap_or_default(),
                        cwd: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(SqliteError::Database)
            .map_err(sqlite_error)
    }

    /// Resolve an active tool window using the process root stored for an
    /// attributed session. Endpoint Security may report an actor-local root
    /// while still carrying a valid (possibly stale) session label. Looking up
    /// that session's registered root recovers the full shared-process group.
    pub fn active_tool_call_for_session_root(
        &self,
        session_id: &str,
        path: Option<&str>,
        observed_at_ms: u64,
        window_ms: u64,
        completion_grace_ms: u64,
    ) -> io::Result<Option<ActiveToolCall>> {
        let root_pid = {
            let db = self.sqlite_store()?;
            db.connection()
                .query_row(
                    "SELECT root_pid FROM sessions WHERE session_id = ?1 LIMIT 1",
                    rusqlite::params![session_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(SqliteError::Database)
                .map_err(sqlite_error)?
        };
        let Some(root_pid) = root_pid.and_then(|pid| u32::try_from(pid).ok()) else {
            return Ok(None);
        };
        self.active_tool_call_for_root_pid_at_path(
            root_pid,
            path,
            observed_at_ms,
            window_ms,
            completion_grace_ms,
        )
    }

    pub fn dashboard_state(&self) -> io::Result<Value> {
        // Dashboard refresh is outside the agent authorization path and is a
        // natural opportunity to advance one bounded visibility-rules batch.
        // Failure leaves the previous cached classification usable and will be
        // retried by a later refresh or lifecycle event.
        if let Err(error) = self.migrate_artifact_dashboard_visibility_if_due(
            current_unix_millis()?,
            ARTIFACT_VISIBILITY_MAINTENANCE_INTERVAL_MS,
        ) {
            eprintln!("gensee dashboard: artifact visibility maintenance failed: {error}");
        }
        let db = self.sqlite_store()?;
        let conn = db.connection();
        materialize_dashboard_visible_alerts(conn)?;
        let alerts = dashboard_alerts_from_relation(
            conn,
            DashboardAlertQuery {
                relation: "dashboard_visible_alerts",
                request_id: None,
                limit: Some(200),
                visible_alerts_cte: None,
                include_trigger_context: true,
                include_request_prompt: true,
                raw_event_count_expression: "1",
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
        let requests_sql =
            "WITH recent_requests AS MATERIALIZED (
               SELECT request_id, session_id,
                      substr(original_user_prompt, 1, 16384) AS original_user_prompt,
                      created_at, completed_at
               FROM requests
               ORDER BY COALESCE(completed_at, created_at, request_id) DESC, request_id DESC
               LIMIT 100
             ),
             event_rollups AS (
               SELECT agent_events.request_id,
                      COUNT(DISTINCT CASE
                        WHEN agent_events.type NOT IN ('PostToolUse', 'PostToolUseFailure')
                        THEN COALESCE(agent_events.tool_use_id, 'event-' || agent_events.event_id)
                      END) AS tool_call_count
               FROM agent_events
               JOIN recent_requests ON recent_requests.request_id = agent_events.request_id
               GROUP BY agent_events.request_id
             ),
             alert_rollups AS (
               SELECT visible_alerts.request_id,
                      COUNT(*) AS alert_count,
                      COUNT(DISTINCT visible_alerts.rule_id || '|' ||
                        COALESCE(visible_alerts.path, '') || '|' ||
                        lower(visible_alerts.action)) AS decision_count,
                      SUM(CASE WHEN lower(visible_alerts.severity) IN ('high', 'critical') THEN 1 ELSE 0 END) AS high_risk_alert_count,
                      CASE MAX(CASE lower(visible_alerts.severity)
                        WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                        WHEN 'low' THEN 2 ELSE 1 END)
                        WHEN 5 THEN 'critical' WHEN 4 THEN 'high' WHEN 3 THEN 'medium'
                        WHEN 2 THEN 'low' ELSE 'info' END AS strongest_severity,
                      CASE MAX(CASE lower(visible_alerts.action)
                        WHEN 'deny' THEN 5 WHEN 'block' THEN 4 WHEN 'ask' THEN 3
                        WHEN 'warn' THEN 2 ELSE 1 END)
                        WHEN 5 THEN 'deny' WHEN 4 THEN 'block' WHEN 3 THEN 'ask' WHEN 2 THEN 'warn'
                        ELSE 'allow' END AS strongest_action
               FROM dashboard_visible_alerts AS visible_alerts
               JOIN recent_requests ON recent_requests.request_id = visible_alerts.request_id
               GROUP BY visible_alerts.request_id
             )
             SELECT recent_requests.request_id, recent_requests.session_id,
                    recent_requests.original_user_prompt, recent_requests.created_at,
                    recent_requests.completed_at,
                    COALESCE(event_rollups.tool_call_count, 0),
                    COALESCE(alert_rollups.alert_count, 0),
                    COALESCE(alert_rollups.decision_count, 0),
                    COALESCE(alert_rollups.high_risk_alert_count, 0),
                    COALESCE(alert_rollups.strongest_severity, 'info'),
                    COALESCE(alert_rollups.strongest_action, 'allow')
             FROM recent_requests
             LEFT JOIN event_rollups ON event_rollups.request_id = recent_requests.request_id
             LEFT JOIN alert_rollups ON alert_rollups.request_id = recent_requests.request_id
             ORDER BY COALESCE(recent_requests.completed_at, recent_requests.created_at, recent_requests.request_id) DESC,
                      recent_requests.request_id DESC";
        let mut requests = query_json_rows(conn, requests_sql, |row| {
            Ok(json!({
                "request_id": row.get::<_, i64>(0)?,
                "session_id": row.get::<_, String>(1)?,
                "original_user_prompt": dashboard_request_prompt(
                    row.get::<_, Option<String>>(2)?.as_deref()
                ),
                "created_at": row.get::<_, Option<i64>>(3)?,
                "completed_at": row.get::<_, Option<i64>>(4)?,
                "tool_call_count": row.get::<_, i64>(5)?,
                "alert_count": row.get::<_, i64>(6)?,
                "decision_count": row.get::<_, i64>(7)?,
                "high_risk_alert_count": row.get::<_, i64>(8)?,
                "strongest_severity": row.get::<_, String>(9)?,
                "strongest_action": row.get::<_, String>(10)?,
                "file_touches": [],
                "summary_file_touch_paths": [],
                "summary_file_touches": [],
                "ignored_file_touch_paths": [],
            }))
        })?;
        let request_file_touches = dashboard_request_file_touches(conn)?;
        for request in &mut requests {
            let request_id = request["request_id"].as_i64().unwrap_or_default();
            let observed_touches = request_file_touches
                .get(&request_id)
                .cloned()
                .unwrap_or_default();
            let touches = merge_harness_declared_file_touches(
                observed_touches,
                dashboard_completed_native_file_touches(conn, request_id)?,
            );
            request["summary_file_touch_paths"] = json!(touches
                .iter()
                .filter_map(|touch| touch["path"].as_str())
                .collect::<Vec<_>>());
            request["summary_file_touches"] = json!(touches);
        }
        let artifact_query = "SELECT kind, uri, current_digest, last_seen_at,
                    last_modified_at, last_modified_source,
                    last_modified_session_id, risk_level, risk_rule_id,
                    is_agent_authored, is_unmatched_modified, is_memory_artifact,
                    is_persistent_target, is_control_plane,
                    recent_unmatched_effect_count, recent_cross_session_write_count
             FROM artifact_facts
             WHERE dashboard_visible = 1
             ORDER BY last_seen_at DESC
             LIMIT 80";
        let artifact_rows = query_json_rows(conn, artifact_query, |row| {
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
                "recent_unmatched_effect_count": row.get::<_, i64>(14)?,
                "recent_cross_session_write_count": row.get::<_, i64>(15)?,
            }))
        })?;
        let artifacts = artifact_rows;
        let visible_artifact_count = conn
            .query_row(
                "SELECT count FROM dashboard_artifact_count WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error_from_rusqlite)?;
        let relation_query = "WITH visible_artifacts AS MATERIALIZED (
                SELECT kind, uri, current_artifact_id AS artifact_id
                FROM artifact_facts
                WHERE dashboard_visible = 1 AND current_artifact_id IS NOT NULL
                ORDER BY last_seen_at DESC
                LIMIT 80
             )
             SELECT r.relation_type, r.confidence,
                    visible_source.uri, visible_destination.uri
             FROM visible_artifacts AS visible_source
             CROSS JOIN relations AS r INDEXED BY idx_relations_src
               ON r.src_kind = 'artifact' AND r.src_id = visible_source.artifact_id
             JOIN visible_artifacts AS visible_destination
               ON r.dst_kind = 'artifact'
              AND r.dst_id = visible_destination.artifact_id
             ORDER BY r.relation_id DESC
             LIMIT 200";
        let relations = query_json_rows(conn, relation_query, |row| {
            Ok(json!({
                "type": row.get::<_, String>(0)?,
                "confidence": row.get::<_, f64>(1)?,
                "src_uri": row.get::<_, String>(2)?,
                "dst_uri": row.get::<_, String>(3)?,
            }))
        })?;
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
        let dashboard_summary_sql = "SELECT
                (SELECT COUNT(*) FROM sessions),
                (SELECT COUNT(*) FROM requests),
                (SELECT COUNT(*) FROM agent_events),
                (SELECT COUNT(*) FROM dashboard_visible_alerts),
                (SELECT COUNT(*) FROM dashboard_visible_alerts
                  WHERE severity IN ('high', 'critical')
                    AND created_at >= (unixepoch('now') - 86400) * 1000),
                (SELECT COUNT(*) FROM artifact_facts),
                (SELECT COUNT(*) FROM dashboard_visible_alerts WHERE severity = 'critical'),
                (SELECT COUNT(*) FROM dashboard_visible_alerts WHERE severity = 'high'),
                (SELECT COUNT(*) FROM dashboard_visible_alerts WHERE severity = 'medium'),
                (SELECT COUNT(*) FROM dashboard_visible_alerts WHERE severity = 'low'),
                (SELECT COUNT(*) FROM dashboard_visible_alerts WHERE severity = 'info')";
        let mut dashboard_summary = query_json_rows(conn, dashboard_summary_sql, |row| {
            Ok(json!({
                "sessions_count": row.get::<_, i64>(0)?,
                "requests_count": row.get::<_, i64>(1)?,
                "agent_events_count": row.get::<_, i64>(2)?,
                "alerts_count": row.get::<_, i64>(3)?,
                "recent_high_alerts": row.get::<_, i64>(4)?,
                "artifacts_count": row.get::<_, i64>(5)?,
                "critical_alerts_count": row.get::<_, i64>(6)?,
                "high_alerts_count": row.get::<_, i64>(7)?,
                "medium_alerts_count": row.get::<_, i64>(8)?,
                "low_alerts_count": row.get::<_, i64>(9)?,
                "info_alerts_count": row.get::<_, i64>(10)?,
            }))
        })?
        .into_iter()
        .next()
        .unwrap_or_else(|| json!({}));
        dashboard_summary["artifacts_count"] = json!(visible_artifact_count);
        let daily_activity_sql =
            "WITH daily_requests AS (
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
                FROM dashboard_visible_alerts AS visible_alerts
                WHERE date(created_at / 1000, 'unixepoch', 'localtime') >= date('now', 'localtime', '-371 days')
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
             ORDER BY days.day";
        let daily_activity = query_json_rows(conn, daily_activity_sql, |row| {
            Ok(json!({
                "date": row.get::<_, String>(0)?,
                "requests": row.get::<_, i64>(1)?,
                "tool_calls": row.get::<_, i64>(2)?,
                "alerts": row.get::<_, i64>(3)?,
                "tokens": row.get::<_, i64>(4)?,
            }))
        })?;
        let recent_activity_sql =
            "WITH hourly_sessions AS (
                SELECT (first_event_at / 3600000) * 3600000 AS bucket_start,
                       COUNT(*) AS count
                FROM sessions
                WHERE first_event_at >= (unixepoch('now') - 90000) * 1000
                GROUP BY bucket_start
             ),
             hourly_events AS (
                SELECT (ts / 3600000) * 3600000 AS bucket_start,
                       COUNT(*) AS count
                FROM agent_events
                WHERE ts >= (unixepoch('now') - 90000) * 1000
                GROUP BY bucket_start
             ),
             hourly_alerts AS (
                SELECT (created_at / 3600000) * 3600000 AS bucket_start,
                       COUNT(*) AS count
                FROM dashboard_visible_alerts
                WHERE created_at >= (unixepoch('now') - 90000) * 1000
                GROUP BY bucket_start
             ),
             hourly_buckets AS (
                SELECT bucket_start FROM hourly_sessions
                UNION SELECT bucket_start FROM hourly_events
                UNION SELECT bucket_start FROM hourly_alerts
             ),
             daily_sessions AS (
                SELECT unixepoch(date(first_event_at / 1000, 'unixepoch', 'localtime'), 'utc') * 1000 AS bucket_start,
                       COUNT(*) AS count
                FROM sessions
                WHERE date(first_event_at / 1000, 'unixepoch', 'localtime') >= date('now', 'localtime', '-6 days')
                GROUP BY bucket_start
             ),
             daily_events AS (
                SELECT unixepoch(date(ts / 1000, 'unixepoch', 'localtime'), 'utc') * 1000 AS bucket_start,
                       COUNT(*) AS count
                FROM agent_events
                WHERE date(ts / 1000, 'unixepoch', 'localtime') >= date('now', 'localtime', '-6 days')
                GROUP BY bucket_start
             ),
             daily_alerts AS (
                SELECT unixepoch(date(created_at / 1000, 'unixepoch', 'localtime'), 'utc') * 1000 AS bucket_start,
                       COUNT(*) AS count
                FROM dashboard_visible_alerts
                WHERE date(created_at / 1000, 'unixepoch', 'localtime') >= date('now', 'localtime', '-6 days')
                GROUP BY bucket_start
             ),
             daily_buckets AS (
                SELECT bucket_start FROM daily_sessions
                UNION SELECT bucket_start FROM daily_events
                UNION SELECT bucket_start FROM daily_alerts
             )
             SELECT 'hour', hourly_buckets.bucket_start,
                    COALESCE(hourly_sessions.count, 0),
                    COALESCE(hourly_events.count, 0),
                    COALESCE(hourly_alerts.count, 0)
             FROM hourly_buckets
             LEFT JOIN hourly_sessions USING (bucket_start)
             LEFT JOIN hourly_events USING (bucket_start)
             LEFT JOIN hourly_alerts USING (bucket_start)
             UNION ALL
             SELECT 'day', daily_buckets.bucket_start,
                    COALESCE(daily_sessions.count, 0),
                    COALESCE(daily_events.count, 0),
                    COALESCE(daily_alerts.count, 0)
             FROM daily_buckets
             LEFT JOIN daily_sessions USING (bucket_start)
             LEFT JOIN daily_events USING (bucket_start)
             LEFT JOIN daily_alerts USING (bucket_start)
             ORDER BY 1, 2";
        let recent_activity = query_json_rows(conn, recent_activity_sql, |row| {
            Ok(json!({
                "interval": row.get::<_, String>(0)?,
                "bucket_start": row.get::<_, i64>(1)?,
                "sessions": row.get::<_, i64>(2)?,
                "agent_events": row.get::<_, i64>(3)?,
                "alerts": row.get::<_, i64>(4)?,
            }))
        })?;
        let json_sessions = self.list_sessions()?;
        Ok(json!({
            "source": "gensee",
            "summary": dashboard_summary,
            "alerts": alerts,
            "agentEvents": agent_events,
            "sessions": sessions,
            "requests": requests,
            "artifacts": artifacts,
            "relations": relations,
            "humanFeedback": human_feedback,
            "dailyActivity": daily_activity,
            "recentActivity": recent_activity,
            "jsonSessions": json_sessions,
        }))
    }

    /// Return complete, request-scoped evidence for Work Review. The periodic
    /// dashboard payload intentionally bounds its global event arrays; detail
    /// views must not infer that an older request had no tools merely because
    /// its events fell outside those windows.
    pub fn dashboard_request(&self, request_id: i64) -> io::Result<Value> {
        let db = self.sqlite_store()?;
        let conn = db.connection();

        let mut request = conn
            .query_row(
                "SELECT request_id, session_id, substr(original_user_prompt, 1, 16384), created_at, completed_at
                 FROM requests
                 WHERE request_id = ?1",
                [request_id],
                |row| {
                    Ok(json!({
                        "request_id": row.get::<_, i64>(0)?,
                        "session_id": row.get::<_, String>(1)?,
                        "original_user_prompt": dashboard_request_prompt(
                            row.get::<_, Option<String>>(2)?.as_deref()
                        ),
                        "created_at": row.get::<_, Option<i64>>(3)?,
                        "completed_at": row.get::<_, Option<i64>>(4)?,
                    }))
                },
            )
            .optional()
            .map_err(sqlite_error_from_rusqlite)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("request {request_id} was not found"),
                )
            })?;

        request["file_touches"] = Value::Array(merge_harness_declared_file_touches(
            dashboard_file_touches(conn, request_id)?,
            dashboard_completed_native_file_touches(conn, request_id)?,
        ));
        let ignored_file_touches = dashboard_ignored_file_touch_paths(conn, request_id)?;
        request["ignored_file_touch_paths"] = json!(ignored_file_touches.paths);
        request["ignored_file_touch_events_omitted"] =
            json!(ignored_file_touches.omitted_event_count);
        request["ignored_file_touch_paths_truncated"] = json!(ignored_file_touches.paths_truncated);

        let agent_events = query_json_rows_with_i64(
            conn,
            "SELECT event_id, pid, request_id, ts, source, type, cwd,
                    permission_mode, tool_name, tool_input, tool_response, tool_use_id
             FROM agent_events
             WHERE request_id = ?1
             ORDER BY ts, event_id",
            request_id,
            |row| {
                Ok(json!({
                    "event_id": row.get::<_, i64>(0)?,
                    "pid": row.get::<_, i64>(1)?,
                    "request_id": row.get::<_, i64>(2)?,
                    "ts": row.get::<_, i64>(3)?,
                    "source": row.get::<_, String>(4)?,
                    "type": row.get::<_, String>(5)?,
                    "cwd": row.get::<_, String>(6)?,
                    "permission_mode": row.get::<_, Option<String>>(7)?,
                    "tool_name": row.get::<_, Option<String>>(8)?,
                    "tool_input": row.get::<_, Option<String>>(9)?,
                    "tool_response": row.get::<_, Option<String>>(10)?,
                    "duration_ms": row.get::<_, Option<String>>(10)?
                        .and_then(|response| serde_json::from_str::<Value>(&response).ok())
                        .and_then(|response| response.get("duration_ms").and_then(Value::as_i64)),
                    "tool_use_id": row.get::<_, Option<String>>(11)?,
                }))
            },
        )?;

        let alerts = dashboard_alerts(conn, Some(request_id), None)?;
        let raw_alert_count = alerts
            .iter()
            .map(|alert| alert["raw_event_count"].as_i64().unwrap_or(1))
            .sum::<i64>();

        Ok(json!({
            "request": request,
            "agentEvents": agent_events,
            "alerts": alerts,
            "rawAlertCount": raw_alert_count,
        }))
    }

    pub fn completed_request_ids_after(
        &self,
        after_request_id: i64,
        limit: i64,
    ) -> io::Result<Vec<i64>> {
        let db = self.sqlite_store()?;
        let mut statement = db
            .connection()
            .prepare(
                "SELECT request_id
                 FROM requests
                 WHERE request_id > ?1 AND completed_at IS NOT NULL
                 ORDER BY request_id
                 LIMIT ?2",
            )
            .map_err(sqlite_error_from_rusqlite)?;
        let rows = statement
            .query_map([after_request_id, limit.clamp(1, 200)], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(sqlite_error_from_rusqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error_from_rusqlite)
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
        let visible_alerts_cte = dashboard_visible_alerts_cte();
        let valid: i64 = conn
            .query_row("SELECT date(?1) = ?1", [day], |row| row.get(0))
            .map_err(sqlite_error_from_rusqlite)?;
        if valid != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dashboard day is not a valid calendar date",
            ));
        }

        let totals_sql = format!(
            "WITH {visible_alerts_cte}
             SELECT
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
               (SELECT COUNT(*) FROM visible_alerts
                 WHERE date(created_at / 1000, 'unixepoch', 'localtime') = ?1),
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
                        OR lower(COALESCE(tool_name, '')) LIKE '%fetch%'))"
        );
        let totals = conn
            .query_row(&totals_sql, [day], |row| {
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
            })
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
        let alerts_by_action_sql = format!(
            "WITH {visible_alerts_cte}
             SELECT action, COUNT(*) FROM visible_alerts
             WHERE date(created_at / 1000, 'unixepoch', 'localtime') = ?1
             GROUP BY action ORDER BY COUNT(*) DESC, action"
        );
        let alerts_by_action = grouped(&alerts_by_action_sql)?;
        let alerts_by_severity_sql = format!(
            "WITH {visible_alerts_cte}
             SELECT severity, COUNT(*) FROM visible_alerts
             WHERE date(created_at / 1000, 'unixepoch', 'localtime') = ?1
             GROUP BY severity ORDER BY COUNT(*) DESC, severity"
        );
        let alerts_by_severity = grouped(&alerts_by_severity_sql)?;

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

    /// Inserts an Endpoint Security alert unless the same logical operation
    /// was already persisted inside `window_ms`. The caller's key includes the
    /// session, exact `(pid,pidversion)`, path, operation, and rule, providing a
    /// durable second deduplication layer across app/ingester restarts.
    pub fn append_endpoint_policy_alert(
        &self,
        alert: &PolicyAlert,
        dedupe_key: &str,
        window_ms: u64,
    ) -> io::Result<bool> {
        let policy = Policy::load_current();
        let tuned = policy.tuned_alert_values(&alert.rule_id, &alert.severity, &alert.action);
        if !policy
            .document()
            .endpoint_security
            .minimum_recorded_severity
            .includes(&tuned.severity)
        {
            return Ok(false);
        }
        self.with_sqlite_transaction(|db| {
            let session_id = alert.session_id.as_deref().unwrap_or(UNKNOWN_SESSION_ID);
            ensure_session(db, session_id, "policy", alert.observed_at_ms)?;
            let request_id = latest_or_create_request(db, session_id)?;
            let created_at = to_i64(alert.observed_at_ms)?;
            let window = to_i64(window_ms)?;
            let duplicate = db
                .connection()
                .query_row(
                    "SELECT 1
                     FROM alerts
                     WHERE rule_id = ?1
                       AND json_extract(evidence, '$.endpoint_dedupe_key') = ?2
                       AND ABS(created_at - ?3) <= ?4
                     LIMIT 1",
                    rusqlite::params![alert.rule_id, dedupe_key, created_at, window],
                    |_| Ok(()),
                )
                .optional()
                .map_err(SqliteError::Database)
                .map_err(sqlite_error)?
                .is_some();
            if duplicate {
                return Ok(false);
            }

            let evidence = merge_alert_evidence(
                add_alert_evidence_field(
                    alert.evidence.clone(),
                    "endpoint_dedupe_key",
                    Value::String(dedupe_key.to_string()),
                ),
                alert.tool_use_id.as_deref(),
            );
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
                    evidence,
                    created_at,
                },
            )?;
            Ok(true)
        })
    }

    pub fn prune_endpoint_retention(
        &self,
        now_ms: u64,
        raw_retention_hours: u64,
        max_raw_events: u64,
        low_severity_retention_hours: Option<u64>,
    ) -> io::Result<RetentionPruneResult> {
        const HOUR_MS: u64 = 60 * 60 * 1_000;
        let raw_cutoff = now_ms.saturating_sub(raw_retention_hours.saturating_mul(HOUR_MS));
        let low_cutoff = low_severity_retention_hours
            .map(|hours| now_ms.saturating_sub(hours.saturating_mul(HOUR_MS)))
            .map(to_i64)
            .transpose()?;
        self.sqlite_store()?
            .prune_endpoint_retention(
                to_i64(raw_cutoff)?,
                i64::try_from(max_raw_events).unwrap_or(i64::MAX),
                low_cutoff,
                ENDPOINT_RETENTION_PRUNE_BATCH as i64,
                to_i64(now_ms)?,
            )
            .map_err(sqlite_error)
    }

    /// Run one bounded retention batch at most once per interval across all
    /// hook/ingest processes sharing this event store.
    pub fn prune_endpoint_retention_if_due(
        &self,
        now_ms: u64,
        interval_ms: u64,
        raw_retention_hours: u64,
        max_raw_events: u64,
        low_severity_retention_hours: Option<u64>,
    ) -> io::Result<Option<RetentionPruneResult>> {
        let db = self.sqlite_store()?;
        if !db
            .claim_maintenance("endpoint-retention", to_i64(now_ms)?, to_i64(interval_ms)?)
            .map_err(sqlite_error)?
        {
            return Ok(None);
        }
        drop(db);
        self.prune_endpoint_retention(
            now_ms,
            raw_retention_hours,
            max_raw_events,
            low_severity_retention_hours,
        )
        .map(Some)
    }

    /// Drain expired or over-cap Falco rows on a collector-specific cadence.
    /// Multiple bounded transactions may run within a short time budget so a
    /// burst can catch up without monopolizing the shared SQLite connection.
    pub fn prune_falco_retention_if_due(
        &self,
        now_ms: u64,
        interval_ms: u64,
        raw_retention_hours: u64,
        max_raw_events: u64,
    ) -> io::Result<Option<u64>> {
        let db = self.sqlite_store()?;
        if !db
            .claim_maintenance("falco-retention", to_i64(now_ms)?, to_i64(interval_ms)?)
            .map_err(sqlite_error)?
        {
            return Ok(None);
        }
        drop(db);
        self.prune_falco_retention_with_budget(
            now_ms,
            raw_retention_hours,
            max_raw_events,
            FALCO_RETENTION_PRUNE_BATCH,
            FALCO_RETENTION_TIME_BUDGET,
        )
        .map(Some)
    }

    fn prune_falco_retention_with_budget(
        &self,
        now_ms: u64,
        raw_retention_hours: u64,
        max_raw_events: u64,
        batch_limit: u64,
        time_budget: Duration,
    ) -> io::Result<u64> {
        const HOUR_MS: u64 = 60 * 60 * 1_000;
        if batch_limit == 0 {
            return Ok(0);
        }
        let raw_cutoff = now_ms.saturating_sub(raw_retention_hours.saturating_mul(HOUR_MS));
        let started = Instant::now();
        let mut total = 0_u64;
        loop {
            let pruned = self
                .sqlite_store()?
                .prune_system_event_source_retention(
                    "linux-falco",
                    to_i64(raw_cutoff)?,
                    i64::try_from(max_raw_events).unwrap_or(i64::MAX),
                    i64::try_from(batch_limit).unwrap_or(i64::MAX),
                )
                .map_err(sqlite_error)?;
            total = total.saturating_add(pruned);
            if pruned < batch_limit || started.elapsed() >= time_budget {
                break;
            }
        }
        Ok(total)
    }

    /// Advance one bounded artifact-visibility rules batch at most once per
    /// interval across all processes sharing this store. Current stores avoid
    /// claiming the maintenance key, so normal dashboard polling remains
    /// read-only after a migration finishes.
    pub fn migrate_artifact_dashboard_visibility_if_due(
        &self,
        now_ms: u64,
        interval_ms: u64,
    ) -> io::Result<Option<ArtifactVisibilityMigrationResult>> {
        let db = self.sqlite_store()?;
        if db
            .dashboard_artifact_visibility_rules_are_current()
            .map_err(sqlite_error)?
        {
            return Ok(None);
        }
        if !db
            .claim_maintenance(
                "dashboard-artifact-visibility",
                to_i64(now_ms)?,
                to_i64(interval_ms)?,
            )
            .map_err(sqlite_error)?
        {
            return Ok(None);
        }
        db.migrate_artifact_dashboard_visibility_rules_batch(ARTIFACT_VISIBILITY_MIGRATION_BATCH)
            .map(Some)
            .map_err(sqlite_error)
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
        if !artifact_path_is_concrete(&observation.path) {
            return Ok(());
        }
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
                execution_origin: "unattributed".to_string(),
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
            let attributed_session_id = system_event_session_id(event);
            let request_id = if let Some(session_id) = attributed_session_id.as_deref() {
                ensure_session(db, session_id, &event.source, event.observed_at_ms)?;
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
                    execution_origin: event.execution_origin.as_str().to_string(),
                })
                .map_err(sqlite_error)?;
            let process_tree_matched = attributed_session_id.is_some();
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
                        "matched_by": "system_event_session_attribution",
                        "session_id": attributed_session_id,
                        "system_event_type": event.event_type,
                    })),
                    ts,
                )?;
            }
            record_system_event_artifacts(db, request_id, event_id, event, ts, matched)?;
            if !matched
                && !matches!(
                    event.source.as_str(),
                    "macos-endpoint-security" | "linux-falco" | "claude-cowork-local-audit"
                )
            {
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
                    execution_origin: "unattributed".to_string(),
                })
                .map_err(sqlite_error)?;
            let Some(artifact_id) = upsert_file_artifact(
                db,
                &effect.path,
                ts,
                Some(json!({
                    "source": effect.source,
                    "confidence": effect.confidence,
                    "attribution": effect.attribution,
                })),
            )?
            else {
                return Ok(());
            };
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
    let policy = Policy::load_current();
    let tuned = policy.tuned_alert_values(input.rule_id, input.severity, input.action);
    if !policy
        .document()
        .endpoint_security
        .minimum_recorded_severity
        .includes(&tuned.severity)
    {
        return Ok(());
    }
    let mut evidence = input.evidence;
    if let Some(severity) = tuned.pre_review_severity {
        evidence =
            add_alert_evidence_field(evidence, "pre_review_severity", Value::String(severity));
    }
    if let Some(action) = tuned.pre_review_action {
        evidence = add_alert_evidence_field(evidence, "pre_review_action", Value::String(action));
    }
    db.insert_alert(&NewAlert {
        request_id: input.request_id,
        entity_kind: input.entity.map(|entity| entity.kind.to_string()),
        entity_id: input.entity.map(|entity| entity.id),
        severity: tuned.severity,
        action: tuned.action,
        rule_id: input.rule_id.to_string(),
        message: input.message.to_string(),
        path: input.path.map(str::to_string),
        evidence: evidence.map(|value| value.to_string()),
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

fn add_alert_evidence_field(evidence: Option<Value>, key: &str, value: Value) -> Option<Value> {
    match evidence {
        Some(Value::Object(mut map)) => {
            map.insert(key.to_string(), value);
            Some(Value::Object(map))
        }
        Some(details) => {
            let mut map = serde_json::Map::new();
            map.insert(key.to_string(), value);
            map.insert("details".to_string(), details);
            Some(Value::Object(map))
        }
        None => {
            let mut map = serde_json::Map::new();
            map.insert(key.to_string(), value);
            Some(Value::Object(map))
        }
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
        dashboard_visible: dashboard_artifact_path_is_visible(
            update.path,
            update
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("source"))
                .and_then(Value::as_str),
            None,
            false,
        ),
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
    let Some(artifact_id) = upsert_file_artifact(
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
    )?
    else {
        return Ok(());
    };

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
        let Some(artifact_id) = upsert_file_artifact(
            db,
            &tool.path,
            ts,
            Some(json!({
                "operation": tool.operation,
                "source": event.provider,
                "tool_name": event.tool_name,
                "tool_use_id": event.tool_use_id,
            })),
        )?
        else {
            continue;
        };

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
        let Some(artifact_id) = upsert_file_artifact(
            db,
            &path,
            ts,
            Some(json!({
                "source": event.source,
                "system_event_type": event.event_type,
                "system_event_kind": event.event_kind,
                "modified": modified,
            })),
        )?
        else {
            continue;
        };
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

fn dashboard_file_touches(conn: &rusqlite::Connection, request_id: i64) -> io::Result<Vec<Value>> {
    let touches = query_json_rows_with_i64(
        conn,
        "SELECT CASE
                    WHEN artifacts.uri LIKE 'file://%' THEN substr(artifacts.uri, 8)
                    WHEN artifacts.uri LIKE 'file:%' THEN substr(artifacts.uri, 6)
                    ELSE artifacts.uri
                END AS path,
                EXISTS (
                    SELECT 1
                    FROM relations AS declared_relation
                    JOIN agent_events AS declaring_event
                      ON declaring_event.event_id = declared_relation.src_id
                    WHERE declared_relation.src_kind = 'agent_event'
                      AND declared_relation.dst_kind = 'artifact'
                      AND declared_relation.dst_id = artifacts.artifact_id
                      AND declared_relation.relation_type IN
                          ('produced', 'modified', 'deleted')
                      AND declaring_event.request_id = ?1
                ) AS intended_and_verified,
                MAX(system_events.ts) AS last_observed_at,
                artifact_facts.risk_level,
                artifact_facts.risk_rule_id,
                COALESCE(artifact_facts.is_memory_artifact, 0),
                COALESCE(artifact_facts.is_persistent_target, 0),
                COALESCE(artifact_facts.is_control_plane, 0)
         FROM relations AS request_relation INDEXED BY idx_relations_src
         JOIN artifacts ON artifacts.artifact_id = request_relation.dst_id
         JOIN relations AS observed_relation INDEXED BY idx_relations_dst
           ON observed_relation.src_kind = 'system_event'
          AND observed_relation.dst_kind = 'artifact'
          AND observed_relation.dst_id = artifacts.artifact_id
          AND observed_relation.relation_type IN ('wrote', 'modified', 'deleted')
         JOIN system_events
           ON system_events.event_id = observed_relation.src_id
          AND system_events.request_id = ?1
          AND system_events.source = 'macos-endpoint-security'
         LEFT JOIN artifact_facts
           ON artifact_facts.current_artifact_id = artifacts.artifact_id
         WHERE request_relation.src_kind = 'request'
           AND request_relation.src_id = ?1
           AND request_relation.dst_kind = 'artifact'
           AND request_relation.relation_type IN ('produced', 'modified', 'deleted')
         GROUP BY artifacts.artifact_id, artifacts.uri
         ORDER BY path",
        request_id,
        |row| {
            Ok(json!({
                "path": row.get::<_, String>(0)?,
                "intended_and_verified": row.get::<_, i64>(1)? != 0,
                "last_observed_at": row.get::<_, i64>(2)?,
                "risk_level": row.get::<_, Option<String>>(3)?,
                "risk_rule_id": row.get::<_, Option<String>>(4)?,
                "is_memory_artifact": row.get::<_, i64>(5)?,
                "is_persistent_target": row.get::<_, i64>(6)?,
                "is_control_plane": row.get::<_, i64>(7)?,
            }))
        },
    )?;
    Ok(touches
        .into_iter()
        .filter(|touch| {
            touch["path"]
                .as_str()
                .is_some_and(|path| !dashboard_file_touch_is_background(path))
        })
        .collect())
}

/// Completed native file tools are useful developer evidence even when the
/// desktop harness performs the write outside its registered subprocess tree.
/// Keep that claim distinct from independent Endpoint Security verification.
fn dashboard_completed_native_file_touches(
    conn: &rusqlite::Connection,
    request_id: i64,
) -> io::Result<Vec<Value>> {
    let rows = query_json_rows_with_i64(
        conn,
        "WITH completed_tools AS (
           SELECT started.tool_input, started.cwd, completed.ts
           FROM agent_events AS started
           JOIN agent_events AS completed
             ON completed.request_id = started.request_id
            AND completed.type = 'PostToolUse'
            AND completed.tool_use_id = started.tool_use_id
           WHERE started.request_id = ?1
             AND started.type = 'PreToolUse'
             AND json_valid(started.tool_input)
         ),
         completed_file_intents AS (
           SELECT intent.tool_input AS tool_input,
                  COALESCE(started.cwd, '') AS cwd,
                  completed.ts AS ts
           FROM agent_events AS intent
           JOIN agent_events AS completed
             ON completed.request_id = intent.request_id
            AND completed.type = 'PostToolUse'
            AND completed.tool_use_id = intent.tool_use_id
           LEFT JOIN agent_events AS started
             ON started.request_id = intent.request_id
            AND started.type = 'PreToolUse'
            AND started.tool_use_id = intent.tool_use_id
           WHERE intent.request_id = ?1
             AND intent.type = 'file_intent'
             AND json_valid(intent.tool_input)
         ),
         declared_paths(path, cwd, completed_at) AS (
           SELECT json_extract(tool_input, '$.path'), cwd, ts
           FROM completed_tools
           WHERE json_type(tool_input, '$.path') = 'text'
             AND lower(COALESCE(json_extract(tool_input, '$.operation'), ''))
                 NOT IN ('read', 'open', 'access')
           UNION ALL
           SELECT json_extract(change.value, '$.path'), completed.cwd, completed.ts
           FROM completed_tools AS completed,
                json_each(completed.tool_input, '$.changes') AS change
           WHERE json_type(change.value, '$.path') = 'text'
             AND lower(COALESCE(json_extract(change.value, '$.operation'), ''))
                 NOT IN ('read', 'open', 'access')
           UNION ALL
           SELECT json_extract(tool_input, '$.path'), cwd, ts
           FROM completed_file_intents
           WHERE json_type(tool_input, '$.path') = 'text'
             AND lower(COALESCE(json_extract(tool_input, '$.operation'), ''))
                 NOT IN ('read', 'open', 'access', 'stat', 'list')
         )
         SELECT path, cwd, MAX(completed_at)
         FROM declared_paths
         WHERE path IS NOT NULL AND path != ''
         GROUP BY path, cwd",
        request_id,
        |row| {
            let raw_path = row.get::<_, String>(0)?;
            let cwd = row.get::<_, String>(1)?;
            let path = normalize_agent_path(&raw_path, &cwd);
            Ok(json!({
                "path": path,
                "intended_and_verified": false,
                "declared_by_harness": true,
                "os_verified": false,
                "last_observed_at": row.get::<_, i64>(2)?,
                "risk_level": Value::Null,
                "risk_rule_id": Value::Null,
                "is_memory_artifact": 0,
                "is_persistent_target": 0,
                "is_control_plane": 0,
            }))
        },
    )?;
    Ok(rows
        .into_iter()
        .filter(|touch| {
            touch["path"].as_str().is_some_and(|path| {
                artifact_path_is_concrete(path) && !dashboard_file_touch_is_background(path)
            })
        })
        .collect())
}

fn merge_harness_declared_file_touches(
    mut observed: Vec<Value>,
    declared: Vec<Value>,
) -> Vec<Value> {
    for touch in &mut observed {
        let declared_by_harness = touch["intended_and_verified"].as_bool().unwrap_or(false);
        touch["declared_by_harness"] = json!(declared_by_harness);
        touch["os_verified"] = json!(true);
    }
    for declared_touch in declared {
        let Some(path) = declared_touch["path"].as_str() else {
            continue;
        };
        if let Some(existing) = observed
            .iter_mut()
            .find(|touch| touch["path"].as_str() == Some(path))
        {
            existing["declared_by_harness"] = json!(true);
            existing["intended_and_verified"] = json!(true);
        } else {
            observed.push(declared_touch);
        }
    }
    observed.sort_by(|left, right| {
        dashboard_file_touch_priority(left)
            .cmp(&dashboard_file_touch_priority(right))
            .then_with(|| {
                left["path"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["path"].as_str().unwrap_or_default())
            })
    });
    observed.truncate(MAX_DASHBOARD_REQUEST_FILE_TOUCHES);
    observed
}

fn dashboard_file_touch_priority(touch: &Value) -> u8 {
    let os_verified = touch["os_verified"].as_bool().unwrap_or(false);
    let declared_by_harness = touch["declared_by_harness"].as_bool().unwrap_or(false);
    if os_verified && !declared_by_harness {
        return 0;
    }
    if [
        "is_control_plane",
        "is_memory_artifact",
        "is_persistent_target",
    ]
    .iter()
    .any(|key| dashboard_json_flag(&touch[*key]))
    {
        return 1;
    }
    2
}

fn dashboard_json_flag(value: &Value) -> bool {
    value
        .as_bool()
        .unwrap_or_else(|| value.as_i64().is_some_and(|number| number != 0))
}

/// Return a small path-only projection for the Work Review request list. The
/// complete intended/verified classification remains request-scoped, but file
/// search and large-task detection must not depend on the global event window.
fn dashboard_request_file_touches(
    conn: &rusqlite::Connection,
) -> io::Result<HashMap<i64, Vec<Value>>> {
    conn.create_scalar_function(
        "gensee_dashboard_file_touch_is_background",
        1,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let path = context.get::<String>(0)?;
            Ok(i64::from(dashboard_file_touch_is_background(&path)))
        },
    )
    .map_err(sqlite_error_from_rusqlite)?;
    let sql = format!(
        "WITH recent_requests AS MATERIALIZED (
            SELECT request_id
            FROM requests
            ORDER BY COALESCE(completed_at, created_at, request_id) DESC, request_id DESC
            LIMIT 100
         ),
         request_artifacts AS MATERIALIZED (
            SELECT request_relation.src_id AS request_id,
                   artifacts.artifact_id,
                   CASE
                     WHEN artifacts.uri LIKE 'file://%' THEN substr(artifacts.uri, 8)
                     WHEN artifacts.uri LIKE 'file:%' THEN substr(artifacts.uri, 6)
                     ELSE artifacts.uri
                   END AS path
            FROM recent_requests
            JOIN relations AS request_relation INDEXED BY idx_relations_src
              ON request_relation.src_kind = 'request'
             AND request_relation.src_id = recent_requests.request_id
             AND request_relation.dst_kind = 'artifact'
             AND request_relation.relation_type IN ('produced', 'modified', 'deleted')
            JOIN artifacts ON artifacts.artifact_id = request_relation.dst_id
            WHERE gensee_dashboard_file_touch_is_background(
                    CASE
                      WHEN artifacts.uri LIKE 'file://%' THEN substr(artifacts.uri, 8)
                      WHEN artifacts.uri LIKE 'file:%' THEN substr(artifacts.uri, 6)
                      ELSE artifacts.uri
                    END
                  ) = 0
            GROUP BY request_relation.src_id, artifacts.artifact_id, artifacts.uri
         ),
         raw_touches AS (
            SELECT request_artifacts.request_id,
                   request_artifacts.path,
                   EXISTS (
                     SELECT 1
                     FROM relations AS declared_relation
                     JOIN agent_events AS declaring_event
                       ON declaring_event.event_id = declared_relation.src_id
                     WHERE declared_relation.src_kind = 'agent_event'
                       AND declared_relation.dst_kind = 'artifact'
                       AND declared_relation.dst_id = request_artifacts.artifact_id
                       AND declared_relation.relation_type IN ('produced', 'modified', 'deleted')
                       AND declaring_event.request_id = request_artifacts.request_id
                   ) AS intended_and_verified,
                   MAX(system_events.ts) AS last_observed_at,
                   artifact_facts.risk_level,
                   artifact_facts.risk_rule_id,
                   COALESCE(artifact_facts.is_memory_artifact, 0) AS is_memory_artifact,
                   COALESCE(artifact_facts.is_persistent_target, 0) AS is_persistent_target,
                   COALESCE(artifact_facts.is_control_plane, 0) AS is_control_plane
            FROM request_artifacts
            JOIN relations AS observed_relation INDEXED BY idx_relations_dst
              ON observed_relation.src_kind = 'system_event'
             AND observed_relation.dst_kind = 'artifact'
             AND observed_relation.dst_id = request_artifacts.artifact_id
             AND observed_relation.relation_type IN ('wrote', 'modified', 'deleted')
            JOIN system_events
              ON system_events.event_id = observed_relation.src_id
             AND system_events.request_id = request_artifacts.request_id
             AND system_events.source = 'macos-endpoint-security'
            LEFT JOIN artifact_facts
              ON artifact_facts.current_artifact_id = request_artifacts.artifact_id
            GROUP BY request_artifacts.request_id, request_artifacts.artifact_id,
                     request_artifacts.path
         ),
         candidate_touches AS (
            SELECT request_id, path, intended_and_verified, last_observed_at,
                   risk_level, risk_rule_id, is_memory_artifact,
                   is_persistent_target, is_control_plane,
                   ROW_NUMBER() OVER (
                     PARTITION BY request_id
                     ORDER BY
                       CASE
                         WHEN intended_and_verified = 0 THEN 0
                         WHEN is_control_plane != 0
                           OR is_memory_artifact != 0
                           OR is_persistent_target != 0 THEN 1
                         ELSE 2
                       END,
                       path
                   ) AS touch_rank
            FROM raw_touches
         )
         SELECT request_id, path, intended_and_verified, last_observed_at,
                risk_level, risk_rule_id, is_memory_artifact,
                is_persistent_target, is_control_plane
         FROM candidate_touches
         WHERE touch_rank <= {MAX_DASHBOARD_FILE_TOUCH_CANDIDATES}
         ORDER BY request_id, touch_rank, path"
    );
    let mut statement = conn.prepare(&sql).map_err(sqlite_error_from_rusqlite)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })
        .map_err(sqlite_error_from_rusqlite)?;
    let mut touches: HashMap<i64, Vec<Value>> = HashMap::new();
    for row in rows {
        let (
            request_id,
            path,
            intended_and_verified,
            last_observed_at,
            risk_level,
            risk_rule_id,
            is_memory_artifact,
            is_persistent_target,
            is_control_plane,
        ) = row.map_err(sqlite_error_from_rusqlite)?;
        let request_touches = touches.entry(request_id).or_default();
        if request_touches.len() < MAX_DASHBOARD_REQUEST_FILE_TOUCHES
            && !request_touches.iter().any(|touch| touch["path"] == path)
        {
            request_touches.push(json!({
                "path": path,
                "intended_and_verified": intended_and_verified,
                "last_observed_at": last_observed_at,
                "risk_level": risk_level,
                "risk_rule_id": risk_rule_id,
                "is_memory_artifact": is_memory_artifact,
                "is_persistent_target": is_persistent_target,
                "is_control_plane": is_control_plane,
            }));
        }
    }
    Ok(touches)
}

fn dashboard_file_touch_is_background(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lineage_path_is_harness_runtime_noise(path)
        || lower.starts_with("/tmp/")
        || lower.starts_with("/private/tmp/")
        || lower.contains("/library/caches/")
        || lower.contains("/library/httpstorages/")
        || [
            ".pytest_cache",
            "__pycache__",
            ".mypy_cache",
            ".ruff_cache",
            ".tox",
            "htmlcov",
            ".nyc_output",
            ".next",
            ".turbo",
            ".vite",
            ".gradle",
        ]
        .iter()
        .any(|directory| {
            lower.contains(&format!("/{directory}/")) || lower.ends_with(&format!("/{directory}"))
        })
}

struct DashboardIgnoredFileTouches {
    paths: Vec<String>,
    omitted_event_count: usize,
    paths_truncated: bool,
}

fn dashboard_ignored_file_touch_paths(
    conn: &rusqlite::Connection,
    request_id: i64,
) -> io::Result<DashboardIgnoredFileTouches> {
    dashboard_ignored_file_touch_paths_with_limits(
        conn,
        request_id,
        MAX_DASHBOARD_IGNORED_FILE_TOUCH_EVENTS,
        MAX_DASHBOARD_IGNORED_FILE_TOUCH_PATHS,
    )
}

fn dashboard_ignored_file_touch_paths_with_limits(
    conn: &rusqlite::Connection,
    request_id: i64,
    event_limit: usize,
    path_limit: usize,
) -> io::Result<DashboardIgnoredFileTouches> {
    let total_event_count = conn
        .query_row(
            "SELECT COUNT(*) FROM system_events
             WHERE request_id = ?1 AND source = 'macos-endpoint-security'",
            [request_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error_from_rusqlite)
        .and_then(|count| {
            usize::try_from(count).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "negative system event count")
            })
        })?;
    let mut statement = conn
        .prepare(
            "SELECT pid, ts, source, type, args
             FROM system_events
             WHERE request_id = ?1 AND source = 'macos-endpoint-security'
             ORDER BY ts, event_id
             LIMIT ?2",
        )
        .map_err(sqlite_error_from_rusqlite)?;
    let rows = statement
        .query_map(
            rusqlite::params![request_id, i64::try_from(event_limit).unwrap_or(i64::MAX)],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .map_err(sqlite_error_from_rusqlite)?;
    let mut ignored = BTreeSet::new();
    let mut paths_truncated = false;
    'events: for row in rows {
        let (pid, ts, source, event_type, args) = row.map_err(sqlite_error_from_rusqlite)?;
        let Some(raw_json) = args.as_deref() else {
            continue;
        };
        let Ok(raw_event) = serde_json::from_str::<Value>(raw_json) else {
            continue;
        };
        if !dashboard_endpoint_event_is_file_mutation(&event_type, &raw_event) {
            continue;
        }

        let executable_path = raw_event
            .pointer("/actor/executable_path")
            .and_then(Value::as_str)
            .map(str::to_string);
        let file_path = raw_event
            .pointer("/file/path")
            .and_then(Value::as_str)
            .map(str::to_string);
        let process_name = executable_path
            .as_deref()
            .and_then(|path| path.rsplit('/').next())
            .map(str::to_string);
        let event = SystemEvent {
            source,
            event_type,
            event_kind: "file_mutation".to_string(),
            execution_origin: Default::default(),
            observed_at_ms: u64::try_from(ts).unwrap_or_default(),
            pid: u32::try_from(pid).ok(),
            ppid: raw_event
                .pointer("/actor/ppid")
                .and_then(Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok()),
            process_name,
            executable_path,
            file_path,
            command_line: None,
            raw_json: raw_json.to_string(),
        };
        for path in system_event_paths(&event) {
            if artifact_path_is_concrete(&path)
                && (dashboard_file_touch_is_background(&path)
                    || !should_materialize_system_artifact(&event, &path, Some(&raw_event)))
            {
                if !ignored.contains(&path) && ignored.len() >= path_limit {
                    paths_truncated = true;
                    break 'events;
                }
                ignored.insert(path);
            }
        }
    }
    Ok(DashboardIgnoredFileTouches {
        paths: ignored.into_iter().collect(),
        omitted_event_count: total_event_count.saturating_sub(event_limit),
        paths_truncated,
    })
}

fn dashboard_endpoint_event_is_file_mutation(event_type: &str, raw_event: &Value) -> bool {
    if event_type.starts_with("auth_")
        || raw_event.get("action").and_then(Value::as_str) == Some("auth")
    {
        return false;
    }
    match event_type {
        "create" | "write" | "rename" | "unlink" | "truncate" => true,
        "close" => raw_event.get("modified").and_then(Value::as_bool) == Some(true),
        "open" => raw_event
            .get("open_flags")
            .and_then(Value::as_i64)
            .is_some_and(|flags| flags & 2 != 0),
        _ => false,
    }
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
) -> io::Result<Option<i64>> {
    if !artifact_path_is_concrete(path) {
        return Ok(None);
    }
    db.insert_artifact(&NewArtifact {
        kind: "file".to_string(),
        uri: file_uri(path),
        digest: None,
        created_at: Some(ts),
        updated_at: Some(ts),
        metadata: metadata.map(|value| value.to_string()),
    })
    .map(Some)
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

fn system_event_session_id(event: &SystemEvent) -> Option<String> {
    let value = serde_json::from_str::<Value>(&event.raw_json).ok()?;
    let session_id = match event.source.as_str() {
        "linux" | "linux-falco" => value.get("session_id").and_then(Value::as_str),
        "macos-endpoint-security" => value
            .get("attribution")
            .and_then(|value| value.get("session_id"))
            .and_then(Value::as_str),
        "claude-cowork-local-audit" => value
            .get("attribution")
            .and_then(|value| value.get("session_id"))
            .and_then(Value::as_str),
        _ => None,
    };
    session_id
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
    if event.source == "claude-cowork-local-audit" {
        return matches!(
            cowork_tool_operation(event),
            Some("read" | "write" | "edit")
        );
    }
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

    if lineage_path_is_harness_runtime_noise(path)
        || lineage_path_is_system_dependency(path)
        || endpoint_system_event_is_known_build_output(event, path, raw_event)
    {
        return false;
    }
    true
}

fn endpoint_system_event_is_known_build_output(
    event: &SystemEvent,
    path: &str,
    raw_event: Option<&Value>,
) -> bool {
    if event.source != "macos-endpoint-security" {
        return false;
    }
    let workspace_root = raw_event
        .and_then(|value| value.pointer("/attribution/workspace_root"))
        .and_then(Value::as_str)
        .or_else(|| {
            raw_event
                .and_then(|value| value.get("cwd"))
                .and_then(Value::as_str)
        });
    endpoint_security_path_is_known_build_output(
        event.executable_path.as_deref(),
        path,
        workspace_root,
    )
}

fn dashboard_alert_base_visibility_sql(alias: &str) -> String {
    let path = format!("COALESCE({alias}.path, '')");
    let lower_path = format!("lower({path})");
    format!(
        "NOT ({alias}.rule_id = 'unmatched_system_effect'
              AND {alias}.evidence LIKE '%\"source\":\"macos-endpoint-security\"%')
         AND NOT ({alias}.rule_id = 'hook_bypass_file_mutation' AND (
              {path} GLOB '/dev/*'
              OR {lower_path} LIKE '%/library/application support/codex/%'
              OR {lower_path} LIKE '%/library/application support/claude/%'
              OR {lower_path} LIKE '%/crashpad/%'
              OR {lower_path} LIKE '%/diagnosticreports/%'
              OR {lower_path} LIKE '%/crash reports/%'
              OR {lower_path} LIKE '%/.codex/sessions/%.jsonl'
              OR {lower_path} LIKE '%/.claude/projects/%.jsonl'
         ))"
    )
}

fn dashboard_visible_alerts_cte() -> String {
    dashboard_visible_alerts_cte_with_scope(None)
}

fn dashboard_visible_alerts_cte_for_request() -> String {
    dashboard_visible_alerts_cte_with_scope(Some("AND alerts.request_id = ?1"))
}

fn dashboard_visible_alerts_cte_with_scope(request_scope: Option<&str>) -> String {
    let base_visibility = dashboard_alert_base_visibility_sql("alerts");
    let request_scope = request_scope.unwrap_or_default();
    format!(
        "ranked_dashboard_alerts AS MATERIALIZED (
            SELECT alerts.*,
                   LAG(alerts.created_at) OVER (
                       PARTITION BY alerts.rule_id,
                                    alerts.request_id,
                                    COALESCE(alerts.path, ''),
                                    COALESCE(json_extract(alerts.evidence, '$.actor.pid'), -1),
                                    COALESCE(json_extract(alerts.evidence, '$.actor.pidversion'), -1)
                       ORDER BY alerts.created_at, alerts.alert_id
                   ) AS previous_related_alert_at
            FROM alerts
            WHERE {base_visibility}
              {request_scope}
         ),
         visible_alerts AS MATERIALIZED (
            SELECT *
            FROM ranked_dashboard_alerts
            WHERE rule_id != 'hook_bypass_file_mutation'
               OR previous_related_alert_at IS NULL
               OR created_at - previous_related_alert_at > 10000
         )"
    )
}

fn materialize_dashboard_visible_alerts(conn: &rusqlite::Connection) -> io::Result<()> {
    let visible_alerts_cte = dashboard_visible_alerts_cte();
    conn.execute_batch(&format!(
        "DROP TABLE IF EXISTS temp.dashboard_visible_alerts;
         CREATE TEMP TABLE dashboard_visible_alerts AS
         WITH {visible_alerts_cte}
         SELECT * FROM visible_alerts;
         CREATE INDEX temp.dashboard_visible_alerts_request
           ON dashboard_visible_alerts(request_id);
         CREATE INDEX temp.dashboard_visible_alerts_severity
           ON dashboard_visible_alerts(severity, created_at);
         CREATE INDEX temp.dashboard_visible_alerts_created_at
           ON dashboard_visible_alerts(created_at);"
    ))
    .map_err(sqlite_error_from_rusqlite)
}

fn dashboard_alerts(
    conn: &rusqlite::Connection,
    request_id: Option<i64>,
    limit: Option<usize>,
) -> io::Result<Vec<Value>> {
    match request_id {
        Some(_) => {
            // Request review displays one actionable finding per rule, path,
            // and action. Group before resolving trigger-event context so a
            // noisy low-level stream does not repeat the same prompt, tool
            // input, and evidence thousands of times in the JSON payload.
            let visible_alerts_cte = dashboard_visible_alerts_cte_for_request();
            let grouped_alerts_cte = format!(
                "{visible_alerts_cte},
                 ranked_request_alerts AS MATERIALIZED (
                    SELECT visible_alerts.*,
                           COUNT(*) OVER (
                               PARTITION BY rule_id, COALESCE(path, ''), lower(action)
                           ) AS raw_event_count,
                           ROW_NUMBER() OVER (
                               PARTITION BY rule_id, COALESCE(path, ''), lower(action)
                               ORDER BY CASE severity
                                          WHEN 'critical' THEN 4
                                          WHEN 'high' THEN 3
                                          WHEN 'medium' THEN 2
                                          WHEN 'low' THEN 1
                                          ELSE 0
                                        END DESC,
                                        created_at DESC,
                                        alert_id DESC
                           ) AS representative_rank
                    FROM visible_alerts
                 ),
                 request_alerts AS MATERIALIZED (
                    SELECT *
                    FROM ranked_request_alerts
                    WHERE representative_rank = 1
                 )"
            );
            let mut alerts = dashboard_alerts_from_relation(
                conn,
                DashboardAlertQuery {
                    relation: "request_alerts",
                    request_id,
                    limit,
                    visible_alerts_cte: Some(&grouped_alerts_cte),
                    include_trigger_context: false,
                    include_request_prompt: false,
                    raw_event_count_expression: "alerts.raw_event_count",
                },
            )?;
            enrich_dashboard_alert_context(conn, request_id.unwrap(), &mut alerts)?;
            Ok(alerts)
        }
        None => {
            let visible_alerts_cte = dashboard_visible_alerts_cte();
            dashboard_alerts_from_relation(
                conn,
                DashboardAlertQuery {
                    relation: "visible_alerts",
                    request_id: None,
                    limit,
                    visible_alerts_cte: Some(&visible_alerts_cte),
                    include_trigger_context: true,
                    include_request_prompt: true,
                    raw_event_count_expression: "1",
                },
            )
        }
    }
}

struct DashboardAlertQuery<'a> {
    relation: &'a str,
    request_id: Option<i64>,
    limit: Option<usize>,
    visible_alerts_cte: Option<&'a str>,
    include_trigger_context: bool,
    include_request_prompt: bool,
    raw_event_count_expression: &'a str,
}

fn dashboard_alerts_from_relation(
    conn: &rusqlite::Connection,
    query: DashboardAlertQuery<'_>,
) -> io::Result<Vec<Value>> {
    let DashboardAlertQuery {
        relation: alert_relation,
        request_id,
        limit,
        visible_alerts_cte,
        include_trigger_context,
        include_request_prompt,
        raw_event_count_expression,
    } = query;
    let where_clause = request_id
        .map(|_| "WHERE alerts.request_id = ?1")
        .unwrap_or_default();
    let limit_clause = limit
        .map(|value| format!("LIMIT {value}"))
        .unwrap_or_default();
    let with_clause = visible_alerts_cte
        .map(|cte| format!("WITH {cte}"))
        .unwrap_or_default();
    let request_prompt_expression = if include_request_prompt {
        "substr(requests.original_user_prompt, 1, 16384)"
    } else {
        "NULL"
    };
    let (trigger_event_columns, trigger_event_join) = if include_trigger_context {
        (
            "trigger_event.source, trigger_event.type, trigger_event.tool_name,
             trigger_event.tool_input, trigger_event.tool_use_id",
            "LEFT JOIN agent_events AS trigger_event
           ON trigger_event.event_id = COALESCE(
             CASE WHEN alerts.entity_kind = 'agent_event' THEN alerts.entity_id END,
             (
               SELECT candidate.event_id FROM agent_events AS candidate
               WHERE candidate.request_id = alerts.request_id
                 AND candidate.tool_use_id = json_extract(alerts.evidence, '$.tool_use_id')
               ORDER BY candidate.type = 'PreToolUse' DESC,
                        candidate.ts DESC, candidate.event_id DESC
               LIMIT 1
             ),
             (
               SELECT candidate.event_id FROM agent_events AS candidate
               WHERE candidate.request_id = alerts.request_id
                 AND candidate.type = 'PreToolUse'
                 AND candidate.ts <= alerts.created_at
               ORDER BY candidate.ts DESC, candidate.event_id DESC
               LIMIT 1
             ),
             (
               SELECT candidate.event_id FROM agent_events AS candidate
               WHERE candidate.request_id = alerts.request_id
                 AND candidate.ts <= alerts.created_at
               ORDER BY candidate.ts DESC, candidate.event_id DESC
               LIMIT 1
             )
           )",
        )
    } else {
        ("NULL, NULL, NULL, NULL, NULL", "")
    };
    let sql = format!(
        "{with_clause}
         SELECT alerts.alert_id, alerts.request_id, alerts.entity_kind, alerts.entity_id,
                alerts.severity, alerts.action, alerts.rule_id, alerts.message,
                alerts.path, alerts.evidence, alerts.created_at,
                requests.session_id, {request_prompt_expression},
                {trigger_event_columns},
                feedback.human_verdict, feedback.label, feedback.created_at,
                {raw_event_count_expression}
         FROM {alert_relation} AS alerts
         LEFT JOIN requests ON requests.request_id = alerts.request_id
         {trigger_event_join}
         LEFT JOIN human_feedback AS feedback
           ON feedback.feedback_id = (
             SELECT candidate_feedback.feedback_id
             FROM human_feedback AS candidate_feedback
             WHERE candidate_feedback.event_key = 'alert:' || alerts.alert_id
             ORDER BY candidate_feedback.created_at DESC,
                      candidate_feedback.feedback_id DESC
             LIMIT 1
           )
         {where_clause}
         ORDER BY alerts.created_at DESC, alerts.alert_id DESC
         {limit_clause}"
    );
    let mapper = |row: &rusqlite::Row<'_>| {
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
            "original_user_prompt": dashboard_request_prompt(
                row.get::<_, Option<String>>(12)?.as_deref()
            ),
            "event_source": row.get::<_, Option<String>>(13)?,
            "event_type": row.get::<_, Option<String>>(14)?,
            "tool_name": row.get::<_, Option<String>>(15)?,
            "tool_input": row.get::<_, Option<String>>(16)?,
            "tool_use_id": row.get::<_, Option<String>>(17)?,
            "human_verdict": row.get::<_, Option<String>>(18)?,
            "feedback_label": row.get::<_, Option<String>>(19)?,
            "feedback_created_at": row.get::<_, Option<i64>>(20)?,
            "raw_event_count": row.get::<_, i64>(21)?,
        }))
    };
    match request_id {
        Some(request_id) => query_json_rows_with_i64(conn, &sql, request_id, mapper),
        None => query_json_rows(conn, &sql, mapper),
    }
}

#[derive(Clone)]
struct DashboardAgentEventContext {
    event_id: i64,
    ts: i64,
    source: String,
    event_type: String,
    tool_name: Option<String>,
    tool_input: Option<String>,
    tool_use_id: Option<String>,
}

fn enrich_dashboard_alert_context(
    conn: &rusqlite::Connection,
    request_id: i64,
    alerts: &mut [Value],
) -> io::Result<()> {
    let mut statement = conn
        .prepare(
            "SELECT event_id, ts, source, type, tool_name, tool_input, tool_use_id
             FROM agent_events
             WHERE request_id = ?1
             ORDER BY ts, event_id",
        )
        .map_err(sqlite_error_from_rusqlite)?;
    let rows = statement
        .query_map([request_id], |row| {
            Ok(DashboardAgentEventContext {
                event_id: row.get(0)?,
                ts: row.get(1)?,
                source: row.get(2)?,
                event_type: row.get(3)?,
                tool_name: row.get(4)?,
                tool_input: row.get(5)?,
                tool_use_id: row.get(6)?,
            })
        })
        .map_err(sqlite_error_from_rusqlite)?;
    let events = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error_from_rusqlite)?;
    let pre_tool_events = events
        .iter()
        .filter(|event| event.event_type == "PreToolUse")
        .cloned()
        .collect::<Vec<_>>();
    let by_id = events
        .iter()
        .map(|event| (event.event_id, event.clone()))
        .collect::<HashMap<_, _>>();
    let mut by_tool_use_id = HashMap::<String, DashboardAgentEventContext>::new();
    for event in &events {
        let Some(tool_use_id) = event.tool_use_id.as_ref() else {
            continue;
        };
        let replace = by_tool_use_id.get(tool_use_id).is_none_or(|existing| {
            let event_is_pre = event.event_type == "PreToolUse";
            let existing_is_pre = existing.event_type == "PreToolUse";
            (event_is_pre, event.ts, event.event_id)
                > (existing_is_pre, existing.ts, existing.event_id)
        });
        if replace {
            by_tool_use_id.insert(tool_use_id.clone(), event.clone());
        }
    }

    for alert in alerts {
        let created_at = alert["created_at"].as_i64().unwrap_or(i64::MAX);
        let entity_event = (alert["entity_kind"].as_str() == Some("agent_event"))
            .then(|| alert["entity_id"].as_i64())
            .flatten()
            .and_then(|event_id| by_id.get(&event_id));
        let evidence_tool_use_id = alert["evidence"]
            .as_str()
            .and_then(|evidence| serde_json::from_str::<Value>(evidence).ok())
            .and_then(|evidence| {
                evidence
                    .get("tool_use_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        let tool_event = evidence_tool_use_id
            .as_ref()
            .and_then(|tool_use_id| by_tool_use_id.get(tool_use_id));
        let latest_pre_tool = latest_dashboard_event_at_or_before(&pre_tool_events, created_at);
        let latest_event = latest_dashboard_event_at_or_before(&events, created_at);
        let Some(context) = entity_event
            .or(tool_event)
            .or(latest_pre_tool)
            .or(latest_event)
        else {
            continue;
        };
        alert["event_source"] = json!(context.source);
        alert["event_type"] = json!(context.event_type);
        alert["tool_name"] = json!(context.tool_name);
        alert["tool_input"] = json!(context.tool_input);
        alert["tool_use_id"] = json!(context.tool_use_id);
    }
    Ok(())
}

fn latest_dashboard_event_at_or_before(
    events: &[DashboardAgentEventContext],
    timestamp: i64,
) -> Option<&DashboardAgentEventContext> {
    let index = events.partition_point(|event| (event.ts, event.event_id) <= (timestamp, i64::MAX));
    index.checked_sub(1).and_then(|index| events.get(index))
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
    if event.source == "claude-cowork-local-audit" {
        return match cowork_tool_operation(event) {
            Some("read") => "read_by",
            Some("edit") => "modified",
            _ => "wrote",
        };
    }
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
    if event.source == "claude-cowork-local-audit" {
        return match cowork_tool_operation(event) {
            Some("read") => "consumed_by",
            Some("edit") => "modified",
            _ => "produced",
        };
    }
    if event.event_kind == "file_read" {
        return "consumed_by";
    }
    if event.event_type == "open" && event.event_kind == "file_mutation" {
        return "modified";
    }
    request_artifact_relation_type(&event.event_type)
}

fn cowork_tool_operation(event: &SystemEvent) -> Option<&str> {
    if event.source != "claude-cowork-local-audit" {
        return None;
    }
    serde_json::from_str::<Value>(&event.raw_json)
        .ok()?
        .get("tool_operation")?
        .as_str()
        .map(|operation| match operation {
            "read" => "read",
            "write" => "write",
            "edit" => "edit",
            "shell" => "shell",
            _ => "unknown",
        })
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
    let tools = native_file_tools(event);
    match tools.as_slice() {
        [] => {
            if event.tool_input_command.is_some() || event.tool_input_description.is_some() {
                return store_tool_input(json!({
                    "tool_use_id": event.tool_use_id.as_deref(),
                    "command": event.tool_input_command.as_deref(),
                    "description": event.tool_input_description.as_deref(),
                }));
            }
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

fn dashboard_request_prompt(value: Option<&str>) -> Option<String> {
    let mut prompt = value?.to_string();
    const OPEN: &str = "<in-app-browser-context";
    const CLOSE: &str = "</in-app-browser-context>";

    while let Some(start) = find_ascii_case_insensitive(&prompt, OPEN) {
        let Some(relative_end) = find_ascii_case_insensitive(&prompt[start..], CLOSE) else {
            prompt.truncate(start);
            break;
        };
        let end = start + relative_end + CLOSE.len();
        prompt.replace_range(start..end, "");
    }

    const REQUEST_MARKER: &str = "## My request:";
    if let Some(marker) = find_ascii_case_insensitive(&prompt, REQUEST_MARKER) {
        prompt = prompt[marker + REQUEST_MARKER.len()..].to_string();
    }

    let prompt = prompt.trim();
    if prompt.is_empty() {
        return None;
    }
    let bounded = prompt
        .chars()
        .take(MAX_DASHBOARD_PROMPT_CHARS)
        .collect::<String>();
    Some(bounded)
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
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

fn current_unix_millis() -> io::Result<u64> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| io::Error::other(format!("system clock is before Unix epoch: {error}")))?
        .as_millis();
    u64::try_from(millis)
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

fn query_json_rows_with_i64<F>(
    conn: &rusqlite::Connection,
    sql: &str,
    parameter: i64,
    mut mapper: F,
) -> io::Result<Vec<Value>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<Value>,
{
    let mut stmt = conn
        .prepare(sql)
        .map_err(|error| sqlite_error(SqliteError::Database(error)))?;
    let rows = stmt
        .query_map([parameter], |row| mapper(row))
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
    let (pairs, remainder) = raw.as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for [high_byte, low_byte] in pairs {
        let high = hex_value(*high_byte)?;
        let low = hex_value(*low_byte)?;
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
    fn completion_signal_is_private_and_contains_only_the_timestamp() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-completion-signal-{}",
            std::process::id()
        ));
        fs::remove_dir_all(&dir).ok();
        let store = EventStore::new(&dir).unwrap();

        store.signal_request_completion(1_234).unwrap();

        let signal_path = store.completion_signal_path();
        assert_eq!(fs::read_to_string(&signal_path).unwrap(), "1234\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&signal_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn completed_request_ids_are_incremental_and_require_completion() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-completed-request-ids-{}",
            std::process::id()
        ));
        fs::remove_dir_all(&dir).ok();
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"test completion"}"#,
                100,
            ))
            .unwrap();

        assert!(store.completed_request_ids_after(0, 50).unwrap().is_empty());

        store
            .append_hook_event(&hook_event(
                "Stop",
                r#"{"session_id":"s1","hook_event_name":"Stop","last_assistant_message":"done"}"#,
                200,
            ))
            .unwrap();
        let completed = store.completed_request_ids_after(0, 50).unwrap();
        assert_eq!(completed.len(), 1);
        assert!(store
            .completed_request_ids_after(completed[0], 50)
            .unwrap()
            .is_empty());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn artifact_visibility_migration_is_bounded_and_cross_process_throttled() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-visibility-maintenance-test-{}",
            std::process::id()
        ));
        fs::remove_dir_all(&dir).ok();
        let store = EventStore::new(&dir).unwrap();
        {
            let db = store.sqlite_store().unwrap();
            let transaction = db.connection().unchecked_transaction().unwrap();
            {
                let mut insert = transaction
                    .prepare(
                        "INSERT INTO artifact_facts(
                            kind, uri, last_seen_at, metadata, dashboard_visible
                         ) VALUES ('file', ?1, 1,
                                   '{\"source\":\"macos-endpoint-security\"}', 1)",
                    )
                    .unwrap();
                for index in 0..=ARTIFACT_VISIBILITY_MIGRATION_BATCH {
                    insert
                        .execute([format!("file:///System/Library/noise-{index:04}")])
                        .unwrap();
                }
            }
            transaction.commit().unwrap();
        }

        let first = store
            .migrate_artifact_dashboard_visibility_if_due(1_000, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(first.scanned, ARTIFACT_VISIBILITY_MIGRATION_BATCH);
        assert_eq!(first.updated, ARTIFACT_VISIBILITY_MIGRATION_BATCH);
        assert!(!first.complete);
        assert!(store
            .migrate_artifact_dashboard_visibility_if_due(1_000, 1_000)
            .unwrap()
            .is_none());

        let final_batch = store
            .migrate_artifact_dashboard_visibility_if_due(2_000, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(final_batch.scanned, 1);
        assert_eq!(final_batch.updated, 1);
        assert!(final_batch.complete);
        assert!(store
            .migrate_artifact_dashboard_visibility_if_due(3_000, 1_000)
            .unwrap()
            .is_none());

        let db = store.sqlite_store().unwrap();
        let visible = db
            .connection()
            .query_row(
                "SELECT count FROM dashboard_artifact_count WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(visible, 0);
        assert!(db
            .dashboard_artifact_visibility_rules_are_current()
            .unwrap());
        drop(db);
        drop(store);
        fs::remove_dir_all(&dir).ok();
    }

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
        let hour_bucket = (now / 3_600_000) * 3_600_000;
        let recent_hour = dashboard["recentActivity"]
            .as_array()
            .unwrap()
            .iter()
            .find(|bucket| {
                bucket["interval"] == "hour" && bucket["bucket_start"].as_u64() == Some(hour_bucket)
            })
            .unwrap();
        assert_eq!(recent_hour["sessions"], 1);
        assert_eq!(recent_hour["agent_events"], 1);
        assert_eq!(recent_hour["alerts"], 1);
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
    fn dashboard_request_returns_complete_request_scoped_events() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let dir = std::env::temp_dir().join(format!(
            "gensee-dashboard-request-test-{}-{now}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"Review this request"}"#,
                now,
            ))
            .unwrap();
        let mut tool = hook_event(
            "PreToolUse",
            r#"{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Read","tool_use_id":"read-1"}"#,
            now + 1,
        );
        tool.tool_name = Some("Read".to_string());
        tool.tool_use_id = Some("read-1".to_string());
        store.append_hook_event(&tool).unwrap();
        store
            .append_policy_alert(&PolicyAlert {
                session_id: Some("s1".to_string()),
                tool_use_id: None,
                severity: "high".to_string(),
                action: "warn".to_string(),
                rule_id: "request_rollup_test".to_string(),
                message: "Review the preceding read".to_string(),
                path: None,
                evidence: None,
                observed_at_ms: now + 2,
            })
            .unwrap();
        for offset in 3..=4 {
            store
                .append_policy_alert(&PolicyAlert {
                    session_id: Some("s1".to_string()),
                    tool_use_id: None,
                    severity: "high".to_string(),
                    action: "warn".to_string(),
                    rule_id: "request_rollup_test".to_string(),
                    message: "Review the preceding read".to_string(),
                    path: None,
                    evidence: None,
                    observed_at_ms: now + offset,
                })
                .unwrap();
        }
        store
            .append_hook_event(&hook_event(
                "Stop",
                r#"{"session_id":"s1","hook_event_name":"Stop","last_assistant_message":"done"}"#,
                now + 5,
            ))
            .unwrap();

        let dashboard = store.dashboard_state().unwrap();
        assert_eq!(dashboard["requests"][0]["tool_call_count"], 1);
        assert_eq!(dashboard["requests"][0]["alert_count"], 3);
        assert_eq!(dashboard["requests"][0]["high_risk_alert_count"], 3);
        assert_eq!(dashboard["requests"][0]["strongest_severity"], "high");
        let request_id = dashboard["requests"][0]["request_id"].as_i64().unwrap();
        let detail = store.dashboard_request(request_id).unwrap();
        assert_eq!(detail["request"]["request_id"], request_id);
        assert_eq!(
            detail["request"]["original_user_prompt"],
            "Review this request"
        );
        assert_eq!(detail["agentEvents"].as_array().unwrap().len(), 1);
        assert_eq!(detail["agentEvents"][0]["type"], "PreToolUse");
        assert_eq!(detail["alerts"].as_array().unwrap().len(), 1);
        assert_eq!(detail["rawAlertCount"], 3);
        assert_eq!(detail["alerts"][0]["raw_event_count"], 3);
        assert!(detail["alerts"][0]["original_user_prompt"].is_null());
        assert_eq!(detail["alerts"][0]["tool_name"], "Read");
        assert!(detail["agentEvents"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["request_id"] == request_id));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_rollups_count_permission_only_calls_and_preserve_deny() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let dir = std::env::temp_dir().join(format!(
            "gensee-dashboard-permission-rollup-test-{}-{now}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"Do the task"}"#,
                now,
            ))
            .unwrap();
        let mut permission = hook_event(
            "PermissionRequest",
            r#"{"session_id":"s1","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_use_id":"denied-1"}"#,
            now + 1,
        );
        permission.tool_name = Some("Bash".to_string());
        permission.tool_use_id = Some("denied-1".to_string());
        store.append_hook_event(&permission).unwrap();
        let mut post_only = hook_event(
            "PostToolUseFailure",
            r#"{"session_id":"s1","hook_event_name":"PostToolUseFailure","tool_name":"Read","tool_use_id":"post-only"}"#,
            now + 2,
        );
        post_only.tool_name = Some("Read".to_string());
        post_only.tool_use_id = Some("post-only".to_string());
        store.append_hook_event(&post_only).unwrap();
        store
            .append_policy_alert(&PolicyAlert {
                session_id: Some("s1".to_string()),
                tool_use_id: Some("denied-1".to_string()),
                severity: "high".to_string(),
                action: "block".to_string(),
                rule_id: "permission_denied".to_string(),
                message: "Denied before execution".to_string(),
                path: None,
                evidence: None,
                observed_at_ms: now + 3,
            })
            .unwrap();
        // Existing stores constrain active policy actions to `block`, but the
        // dashboard must preserve imported/forward-compatible `deny` values
        // rather than silently relabeling them as block.
        {
            let db = store.sqlite_store().unwrap();
            db.connection()
                .pragma_update(None, "ignore_check_constraints", "ON")
                .unwrap();
            db.connection()
                .execute(
                    "UPDATE alerts SET action = 'deny' WHERE rule_id = 'permission_denied'",
                    [],
                )
                .unwrap();
        }
        store
            .append_hook_event(&hook_event(
                "Stop",
                r#"{"session_id":"s1","hook_event_name":"Stop","last_assistant_message":"done"}"#,
                now + 4,
            ))
            .unwrap();

        let dashboard = store.dashboard_state().unwrap();
        assert_eq!(dashboard["requests"][0]["tool_call_count"], 1);
        assert_eq!(dashboard["requests"][0]["strongest_action"], "deny");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_request_reports_endpoint_file_touch_evidence() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let dir = std::env::temp_dir().join(format!(
            "gensee-dashboard-file-touch-test-{}-{now}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"Edit the app"}"#,
                now,
            ))
            .unwrap();
        store
            .append_file_intent(&FileIntent {
                provider: "codex".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("edit-1".to_string()),
                observed_at_ms: now + 1,
                operation: "write".to_string(),
                path: "/repo/App.swift".to_string(),
                source_command: "apply_patch".to_string(),
                sensitive: false,
                confidence: "high".to_string(),
            })
            .unwrap();

        let endpoint_event = |path: &str, observed_at_ms: u64| SystemEvent {
            source: "macos-endpoint-security".to_string(),
            event_type: "write".to_string(),
            event_kind: "file_mutation".to_string(),
            execution_origin: Default::default(),
            observed_at_ms,
            pid: Some(42),
            ppid: Some(1),
            process_name: Some("codex".to_string()),
            executable_path: Some("/Applications/Codex.app/Contents/MacOS/Codex".to_string()),
            file_path: Some(path.to_string()),
            command_line: None,
            raw_json: json!({
                "action": "notify",
                "event_type": "write",
                "observed_at_ms": observed_at_ms,
                "actor": {
                    "pid": 42,
                    "ppid": 1,
                    "executable_path": "/Applications/Codex.app/Contents/MacOS/Codex"
                },
                "file": { "path": path, "mode": 0o100644 },
                "attribution": { "session_id": "s1", "workspace_root": "/repo" }
            })
            .to_string(),
        };
        store
            .append_system_event(&endpoint_event("/repo/App.swift", now + 2))
            .unwrap();
        store
            .append_system_event(&endpoint_event("/repo/Outside.swift", now + 3))
            .unwrap();
        store
            .append_system_event(&endpoint_event("/dev/null", now + 4))
            .unwrap();
        store
            .append_system_event(&endpoint_event(
                "/Users/test/.codex/state_5.sqlite",
                now + 5,
            ))
            .unwrap();
        store
            .append_system_event(&endpoint_event("/Users/test/.gensee/gensee.db", now + 6))
            .unwrap();
        store
            .append_hook_event(&hook_event(
                "Stop",
                r#"{"session_id":"s1","hook_event_name":"Stop","last_assistant_message":"done"}"#,
                now + 7,
            ))
            .unwrap();

        let dashboard = store.dashboard_state().unwrap();
        let request = &dashboard["requests"][0];
        // The periodic overview is deliberately lightweight. Complete
        // Endpoint Security evidence is loaded only for the selected request.
        assert!(request["file_touches"].as_array().unwrap().is_empty());
        assert_eq!(
            request["summary_file_touch_paths"],
            json!(["/repo/Outside.swift", "/repo/App.swift"])
        );
        let summary_touches = request["summary_file_touches"].as_array().unwrap();
        assert_eq!(summary_touches.len(), 2);
        assert!(summary_touches.iter().any(|touch| {
            touch["path"] == "/repo/App.swift"
                && touch["intended_and_verified"] == true
                && touch["last_observed_at"].as_i64().is_some()
        }));
        assert!(summary_touches.iter().any(|touch| {
            touch["path"] == "/repo/Outside.swift"
                && touch["intended_and_verified"] == false
                && touch["last_observed_at"].as_i64().is_some()
        }));
        let request_id = request["request_id"].as_i64().unwrap();
        let detail = store.dashboard_request(request_id).unwrap();
        let touches = detail["request"]["file_touches"].as_array().unwrap();
        assert_eq!(touches.len(), 2);
        assert!(touches.iter().any(|touch| {
            touch["path"] == "/repo/App.swift" && touch["intended_and_verified"] == true
        }));
        assert!(touches.iter().any(|touch| {
            touch["path"] == "/repo/Outside.swift" && touch["intended_and_verified"] == false
        }));
        assert_eq!(
            detail["request"]["ignored_file_touch_paths"],
            json!([
                "/Users/test/.codex/state_5.sqlite",
                "/Users/test/.gensee/gensee.db",
                "/dev/null"
            ])
        );
        assert_eq!(detail["request"]["ignored_file_touch_events_omitted"], 0);
        assert_eq!(
            detail["request"]["ignored_file_touch_paths_truncated"],
            false
        );
        assert!(detail.get("systemEvents").is_none());
        let db = store.sqlite_store().unwrap();
        let bounded = dashboard_ignored_file_touch_paths_with_limits(
            db.connection(),
            request_id,
            2,
            MAX_DASHBOARD_IGNORED_FILE_TOUCH_PATHS,
        )
        .unwrap();
        assert_eq!(bounded.omitted_event_count, 3);
        assert!(!bounded.paths_truncated);
        let path_bounded = dashboard_ignored_file_touch_paths_with_limits(
            db.connection(),
            request_id,
            MAX_DASHBOARD_IGNORED_FILE_TOUCH_EVENTS,
            2,
        )
        .unwrap();
        assert_eq!(path_bounded.paths.len(), 2);
        assert!(path_bounded.paths_truncated);
        drop(db);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_reports_completed_native_file_tools_without_endpoint_security_evidence() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let dir = std::env::temp_dir().join(format!(
            "gensee-dashboard-native-file-touch-test-{}-{now}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"Edit the source"}"#,
                now,
            ))
            .unwrap();

        let started = native_tool_event(
            "apply_patch",
            "patch-1",
            r#"{"patch":"*** Begin Patch\n*** Update File: Sources/App.swift\n@@\n-old\n+new\n*** End Patch"}"#,
            now + 1,
        );
        store.append_hook_event(&started).unwrap();
        store
            .append_file_intent(&FileIntent {
                provider: "bash-command-parser".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("patch-1".to_string()),
                observed_at_ms: now + 1,
                operation: "write".to_string(),
                path: "/repo/Generated.swift".to_string(),
                source_command: "generated output".to_string(),
                sensitive: false,
                confidence: "high".to_string(),
            })
            .unwrap();

        let mut completed = native_tool_event(
            "apply_patch",
            "patch-1",
            r#"{"patch":"*** Begin Patch\n*** Update File: Sources/App.swift\n@@\n-old\n+new\n*** End Patch"}"#,
            now + 2,
        );
        completed.hook_event_name = Some("PostToolUse".to_string());
        completed.raw_json = r#"{"session_id":"s1","hook_event_name":"PostToolUse","cwd":"/repo","tool_name":"apply_patch","tool_use_id":"patch-1","tool_input":{"patch":"*** Begin Patch\n*** Update File: Sources/App.swift\n@@\n-old\n+new\n*** End Patch"}}"#.to_string();
        store.append_hook_event(&completed).unwrap();
        store
            .append_hook_event(&hook_event(
                "Stop",
                r#"{"session_id":"s1","hook_event_name":"Stop","cwd":"/repo","last_assistant_message":"done"}"#,
                now + 3,
            ))
            .unwrap();

        let dashboard = store.dashboard_state().unwrap();
        let request = &dashboard["requests"][0];
        assert_eq!(
            request["summary_file_touch_paths"],
            json!(["/repo/Generated.swift", "/repo/Sources/App.swift"])
        );
        for summary_touch in request["summary_file_touches"].as_array().unwrap() {
            assert_eq!(summary_touch["declared_by_harness"], true);
            assert_eq!(summary_touch["os_verified"], false);
            assert_eq!(summary_touch["intended_and_verified"], false);
        }

        let request_id = request["request_id"].as_i64().unwrap();
        let detail = store.dashboard_request(request_id).unwrap();
        let detail_touches = detail["request"]["file_touches"].as_array().unwrap();
        assert_eq!(detail_touches.len(), 2);
        assert!(detail_touches
            .iter()
            .any(|touch| touch["path"] == "/repo/Generated.swift"));
        assert!(detail_touches
            .iter()
            .any(|touch| touch["path"] == "/repo/Sources/App.swift"));
        for detail_touch in detail_touches {
            assert_eq!(detail_touch["declared_by_harness"], true);
            assert_eq!(detail_touch["os_verified"], false);
            assert_eq!(detail_touch["intended_and_verified"], false);
        }

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_file_touches_hide_temporary_and_application_cache_paths() {
        for path in [
            "/private/tmp/render-output.svg",
            "/tmp/agent-scratch.txt",
            "/Users/test/Library/Caches/tool/cache.db",
            "/Users/test/Library/HTTPStorages/tool/httpstorages.sqlite",
            "/Users/test/.gensee/gensee.db",
            "/repo/.pytest_cache/v/cache/nodeids",
            "/repo/src/__pycache__/module.cpython-313.pyc",
            "/repo/.mypy_cache/3.13/module.meta.json",
            "/repo/.ruff_cache/0.12/content",
            "/repo/.tox/py313/log/py313-0.log",
            "/repo/htmlcov/index.html",
            "/repo/.nyc_output/processinfo/index.json",
            "/repo/.next/cache/webpack/client.pack",
            "/repo/.turbo/turbo-build.log",
            "/repo/.vite/deps/chunk.js",
            "/repo/.gradle/8.10/fileHashes/fileHashes.bin",
        ] {
            assert!(dashboard_file_touch_is_background(path), "{path}");
        }
        assert!(!dashboard_file_touch_is_background(
            "/Users/test/project/Sources/App.swift"
        ));
        assert!(!dashboard_file_touch_is_background(
            "/Users/test/project/src/build.rs"
        ));
        for path in [
            "/repo/src/build/config.ts",
            "/repo/internal/build/generated.go",
            "/repo/packages/dist/index.ts",
            "/repo/app/coverage/report.py",
        ] {
            assert!(
                !dashboard_file_touch_is_background(path),
                "ordinary source directory must remain visible: {path}"
            );
        }
    }

    #[test]
    fn dashboard_file_touch_cap_prioritizes_undeclared_and_sensitive_paths() {
        let mut observed = (0..(MAX_DASHBOARD_REQUEST_FILE_TOUCHES + 8))
            .map(|index| {
                json!({
                    "path": format!("/repo/normal-{index:02}.txt"),
                    "intended_and_verified": true,
                    "is_memory_artifact": 0,
                    "is_persistent_target": 0,
                    "is_control_plane": 0,
                })
            })
            .collect::<Vec<_>>();
        observed.push(json!({
            "path": "/repo/zz-undeclared.txt",
            "intended_and_verified": false,
            "is_memory_artifact": 0,
            "is_persistent_target": 0,
            "is_control_plane": 0,
        }));
        observed.push(json!({
            "path": "/repo/zz-sensitive.txt",
            "intended_and_verified": true,
            "is_memory_artifact": 1,
            "is_persistent_target": 0,
            "is_control_plane": 1,
        }));

        let touches = merge_harness_declared_file_touches(observed, Vec::new());

        assert_eq!(touches.len(), MAX_DASHBOARD_REQUEST_FILE_TOUCHES);
        assert_eq!(touches[0]["path"], "/repo/zz-undeclared.txt");
        assert_eq!(touches[1]["path"], "/repo/zz-sensitive.txt");
    }

    #[test]
    fn dashboard_summary_prioritizes_project_paths_before_background_candidate_cap() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let dir = std::env::temp_dir().join(format!(
            "gensee-dashboard-file-touch-priority-test-{}-{now}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"Edit the source"}"#,
                now,
            ))
            .unwrap();
        let endpoint_event = |path: String, observed_at_ms: u64| {
            SystemEvent {
            source: "macos-endpoint-security".to_string(),
            event_type: "write".to_string(),
            event_kind: "file_mutation".to_string(),
            execution_origin: Default::default(),
            observed_at_ms,
            pid: Some(42),
            ppid: Some(1),
            process_name: Some("codex".to_string()),
            executable_path: Some("/Applications/Codex.app/Contents/MacOS/Codex".to_string()),
            file_path: Some(path.clone()),
            command_line: None,
            raw_json: json!({
                "action": "notify",
                "event_type": "write",
                "observed_at_ms": observed_at_ms,
                "actor": {"pid": 42, "ppid": 1, "executable_path": "/Applications/Codex.app/Contents/MacOS/Codex"},
                "file": {"path": path, "mode": 0o100644},
                "attribution": {"session_id": "s1", "workspace_root": "/repo"}
            })
            .to_string(),
        }
        };
        for index in 0..(MAX_DASHBOARD_FILE_TOUCH_CANDIDATES + 20) {
            store
                .append_system_event(&endpoint_event(
                    format!("/Users/test/.codex/state_{index:04}.sqlite"),
                    now + 1 + u64::try_from(index).unwrap(),
                ))
                .unwrap();
        }
        let source_path = "/repo/Sources/App.swift";
        store
            .append_system_event(&endpoint_event(
                source_path.to_string(),
                now + 1 + u64::try_from(MAX_DASHBOARD_FILE_TOUCH_CANDIDATES + 20).unwrap(),
            ))
            .unwrap();
        store
            .append_hook_event(&hook_event(
                "Stop",
                r#"{"session_id":"s1","hook_event_name":"Stop","last_assistant_message":"done"}"#,
                now + 200,
            ))
            .unwrap();

        let dashboard = store.dashboard_state().unwrap();
        assert_eq!(
            dashboard["requests"][0]["summary_file_touch_paths"],
            json!([source_path])
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_prompt_strips_ambient_browser_context_before_bounding() {
        let prompt = concat!(
            "<IN-APP-BROWSER-CONTEXT source=\"ambient-ui-state\">\n",
            "This block is automatically supplied ambient UI state.\n",
            "</IN-APP-BROWSER-CONTEXT>\n\n",
            "## MY REQUEST:\n",
            "Fix the request timeline"
        );
        assert_eq!(
            dashboard_request_prompt(Some(prompt)).as_deref(),
            Some("Fix the request timeline")
        );
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
            execution_origin: Default::default(),
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
    fn dashboard_hides_legacy_endpoint_noise_and_duplicate_bursts() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-dashboard-endpoint-alert-filter-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"build"}"#,
                100,
            ))
            .unwrap();

        let endpoint_alert = |path: &str, observed_at_ms: u64| PolicyAlert {
            session_id: Some("s1".to_string()),
            tool_use_id: None,
            severity: "medium".to_string(),
            action: "warn".to_string(),
            rule_id: "hook_bypass_file_mutation".to_string(),
            message: "legacy endpoint mutation".to_string(),
            path: Some(path.to_string()),
            evidence: Some(json!({
                "source": "macos-endpoint-security",
                "actor": { "pid": 42, "pidversion": 7 }
            })),
            observed_at_ms,
        };
        store
            .append_policy_alert(&endpoint_alert(
                "/Users/test/Library/Application Support/Codex/Crashpad/new/report.dmp",
                1_000,
            ))
            .unwrap();
        for timestamp in [2_000, 2_001, 2_002] {
            store
                .append_policy_alert(&endpoint_alert("/repo/out.txt", timestamp))
                .unwrap();
        }
        store
            .append_policy_alert(&endpoint_alert("/repo/target/exfil.env", 3_000))
            .unwrap();

        assert_eq!(store.list_alerts().unwrap().len(), 5);
        let dashboard = store.dashboard_state().unwrap();
        assert_eq!(dashboard["summary"]["alerts_count"], 2);
        assert_eq!(dashboard["summary"]["medium_alerts_count"], 2);
        let severity_total = ["critical", "high", "medium", "low", "info"]
            .into_iter()
            .map(|severity| {
                dashboard["summary"][format!("{severity}_alerts_count")]
                    .as_i64()
                    .unwrap()
            })
            .sum::<i64>();
        assert_eq!(severity_total, dashboard["summary"]["alerts_count"]);
        let alert_paths = dashboard["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|alert| alert["path"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(alert_paths.len(), 2);
        assert!(alert_paths.contains(&"/repo/out.txt"));
        assert!(alert_paths.contains(&"/repo/target/exfil.env"));

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
            execution_origin: Default::default(),
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
                execution_origin: Default::default(),
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
    fn attributed_linux_system_events_attach_to_the_tclone_request() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-linux-attribution-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_system_event(&SystemEvent {
                source: "linux-falco".to_string(),
                event_type: "connect".to_string(),
                event_kind: "NetworkConnect".to_string(),
                execution_origin: Default::default(),
                observed_at_ms: 130,
                pid: Some(42),
                ppid: Some(1),
                process_name: Some("curl".to_string()),
                executable_path: Some("/usr/bin/curl".to_string()),
                file_path: None,
                command_line: Some("curl https://packages.example.test".to_string()),
                raw_json: r#"{"session_id":"run_test","event":"connect"}"#.to_string(),
            })
            .unwrap();

        let db = store.sqlite_store().unwrap();
        let request = db.latest_request_for_session("run_test").unwrap().unwrap();
        let system_events = db.system_events_for_request(request.request_id).unwrap();
        assert_eq!(system_events.len(), 1);
        assert_eq!(system_events[0].source, "linux-falco");
        assert_eq!(system_events[0].event_type, "connect");
        assert!(store.list_system_events().unwrap().is_empty());
        assert_eq!(
            db.relations_for_request(request.request_id).unwrap().len(),
            1
        );
        assert!(db
            .latest_request_for_session(SYSTEM_SESSION_ID)
            .unwrap()
            .is_none());
        drop(db);
        let native_events = store
            .list_native_system_events(None, None, i64::MIN, i64::MAX, 100)
            .unwrap();
        assert_eq!(native_events.len(), 1);
        assert_eq!(native_events[0].source, "linux-falco");
        assert_eq!(native_events[0].event_type, "connect");
        assert_eq!(native_events[0].observed_at_ms, 130);
        assert_eq!(native_events[0].pid, Some(42));
        assert_eq!(
            native_events[0].raw_json,
            r#"{"session_id":"run_test","event":"connect"}"#
        );
        assert!(store
            .list_alerts()
            .unwrap()
            .iter()
            .all(|alert| alert.rule_id != "unmatched_system_effect"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cowork_audit_events_attach_to_session_with_typed_artifact_relations() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-cowork-attribution-{}",
            std::process::id()
        ));
        fs::remove_dir_all(&dir).ok();
        let store = EventStore::new(&dir).unwrap();
        for (tool_name, tool_operation, event_kind, path) in [
            ("Read", "read", "file_read", "/repo/input.txt"),
            ("Write", "write", "file_mutation", "/repo/output.txt"),
        ] {
            store
                .append_system_event(&SystemEvent {
                    source: "claude-cowork-local-audit".to_string(),
                    event_type: "cowork_tool_boundary".to_string(),
                    event_kind: event_kind.to_string(),
                    execution_origin: ExecutionOrigin::HostNative,
                    observed_at_ms: 130,
                    pid: None,
                    ppid: None,
                    process_name: Some("Claude Cowork".to_string()),
                    executable_path: None,
                    file_path: Some(path.to_string()),
                    command_line: None,
                    raw_json: json!({
                        "attribution": { "session_id": "cowork-session" },
                        "tool_name": tool_name,
                        "tool_operation": tool_operation,
                        "file_path": path,
                    })
                    .to_string(),
                })
                .unwrap();
        }

        let db = store.sqlite_store().unwrap();
        let request = db
            .latest_request_for_session("cowork-session")
            .unwrap()
            .unwrap();
        let events = db.system_events_for_request(request.request_id).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .all(|event| event.execution_origin == "host-native"));
        let relations = db.relations_for_request(request.request_id).unwrap();
        assert!(relations
            .iter()
            .any(|relation| relation.relation_type == "consumed_by"));
        assert!(relations
            .iter()
            .any(|relation| relation.relation_type == "produced"));
        drop(db);
        assert!(store
            .list_alerts()
            .unwrap()
            .iter()
            .all(|alert| alert.rule_id != "unmatched_system_effect"));

        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn native_system_event_listing_skips_negative_timestamps() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-native-negative-ts-{}",
            std::process::id()
        ));
        fs::remove_dir_all(&dir).ok();
        let store = EventStore::new(&dir).unwrap();
        for observed_at_ms in [130, 140] {
            store
                .append_system_event(&SystemEvent {
                    source: "linux-falco".to_string(),
                    event_type: "execve".to_string(),
                    event_kind: "ProcessExec".to_string(),
                    execution_origin: Default::default(),
                    observed_at_ms,
                    pid: Some(42),
                    ppid: Some(1),
                    process_name: Some("sh".to_string()),
                    executable_path: Some("/bin/sh".to_string()),
                    file_path: None,
                    command_line: Some("sh -c true".to_string()),
                    raw_json: format!(r#"{{"event_id":"event-{observed_at_ms}"}}"#),
                })
                .unwrap();
        }
        store
            .sqlite_store()
            .unwrap()
            .connection()
            .execute("UPDATE system_events SET ts = -1 WHERE ts = 130", [])
            .unwrap();

        let events = store
            .list_native_system_events(None, None, i64::MIN, i64::MAX, 100)
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].observed_at_ms, 140);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn falco_retention_drains_multiple_batches_within_budget() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-falco-retention-budget-{}",
            std::process::id()
        ));
        fs::remove_dir_all(&dir).ok();
        let store = EventStore::new(&dir).unwrap();
        for observed_at_ms in 1..=8 {
            store
                .append_system_event(&SystemEvent {
                    source: "linux-falco".to_string(),
                    event_type: "execve".to_string(),
                    event_kind: "ProcessExec".to_string(),
                    execution_origin: Default::default(),
                    observed_at_ms,
                    pid: Some(42),
                    ppid: Some(1),
                    process_name: Some("sh".to_string()),
                    executable_path: Some("/bin/sh".to_string()),
                    file_path: None,
                    command_line: Some("sh -c true".to_string()),
                    raw_json: format!(r#"{{"event_id":"event-{observed_at_ms}"}}"#),
                })
                .unwrap();
        }

        let pruned = store
            .prune_falco_retention_with_budget(100, 1, 2, 3, Duration::from_secs(1))
            .unwrap();
        let events = store
            .list_native_system_events(None, None, i64::MIN, i64::MAX, 100)
            .unwrap();

        assert_eq!(pruned, 6);
        assert_eq!(events.len(), 2);
        assert_eq!(
            events
                .into_iter()
                .map(|event| event.observed_at_ms)
                .collect::<Vec<_>>(),
            vec![7, 8]
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn falco_retention_ages_replayed_events_from_ingestion_time() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-falco-historical-retention-{}",
            std::process::id()
        ));
        fs::remove_dir_all(&dir).ok();
        let store = EventStore::new(&dir).unwrap();
        store
            .append_system_event(&SystemEvent {
                source: "linux-falco".to_string(),
                event_type: "execve".to_string(),
                event_kind: "ProcessExec".to_string(),
                execution_origin: Default::default(),
                observed_at_ms: 1,
                pid: Some(42),
                ppid: Some(1),
                process_name: Some("sh".to_string()),
                executable_path: Some("/bin/sh".to_string()),
                file_path: None,
                command_line: Some("sh -c true".to_string()),
                raw_json: r#"{"gensee":{"ingested_at_ms":10000}}"#.to_string(),
            })
            .unwrap();

        let pruned = store
            .prune_falco_retention_with_budget(10_000, 0, 100, 100, Duration::from_secs(1))
            .unwrap();

        assert_eq!(pruned, 0);
        assert_eq!(
            store
                .list_native_system_events(None, None, i64::MIN, i64::MAX, 100)
                .unwrap()
                .len(),
            1
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn unattributed_falco_events_are_capture_only() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-falco-capture-only-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_system_event(&SystemEvent {
                source: "linux-falco".to_string(),
                event_type: "openat".to_string(),
                event_kind: "FileWrite".to_string(),
                execution_origin: Default::default(),
                observed_at_ms: 130,
                pid: Some(42),
                ppid: Some(1),
                process_name: Some("sh".to_string()),
                executable_path: Some("/bin/sh".to_string()),
                file_path: Some("/workspace/result.txt".to_string()),
                command_line: Some("sh -c echo".to_string()),
                raw_json: r#"{"event":"openat"}"#.to_string(),
            })
            .unwrap();

        assert!(store.list_system_events().unwrap().is_empty());
        let db = store.sqlite_store().unwrap();
        let request = db
            .latest_request_for_session(SYSTEM_SESSION_ID)
            .unwrap()
            .unwrap();
        assert_eq!(
            db.system_events_for_request(request.request_id)
                .unwrap()
                .len(),
            1
        );
        drop(db);
        assert!(store
            .list_alerts()
            .unwrap()
            .iter()
            .all(|alert| alert.rule_id != "unmatched_system_effect"));

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
                execution_origin: Default::default(),
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
        assert!(dashboard.get("systemEvents").is_none());
        assert!(dashboard["summary"].get("system_events_count").is_none());

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
        assert_eq!(dashboard["summary"]["high_alerts_count"], 1);

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
                execution_origin: Default::default(),
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
                "attribution": {
                    "session_id": "claude-session",
                    "workspace_root": "/repo"
                }
            });
            if let Some(modified) = modified {
                raw["modified"] = json!(modified);
            }
            SystemEvent {
                source: "macos-endpoint-security".to_string(),
                event_type: event_type.to_string(),
                event_kind: event_kind.to_string(),
                execution_origin: Default::default(),
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

        store
            .append_system_event(&endpoint_event(
                "write",
                "file_mutation",
                "/repo/target/exfil.env",
                0o100600,
                None,
                106,
            ))
            .unwrap();
        assert!(store
            .artifact_fact_for_file("/repo/target/exfil.env")
            .unwrap()
            .is_some());

        let mut build_output = endpoint_event(
            "write",
            "file_mutation",
            "/repo/target/debug/output.o",
            0o100644,
            None,
            107,
        );
        build_output.process_name = Some("rustc".to_string());
        build_output.executable_path =
            Some("/Users/test/.rustup/toolchains/stable/bin/rustc".to_string());
        store.append_system_event(&build_output).unwrap();
        assert!(store
            .artifact_fact_for_file("/repo/target/debug/output.o")
            .unwrap()
            .is_none());

        let dashboard = store.dashboard_state().unwrap();
        assert!(dashboard.get("systemEvents").is_none());
        assert_eq!(dashboard["summary"]["artifacts_count"], 2);
        let artifact_paths = dashboard["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|artifact| artifact["uri"].as_str())
            .collect::<Vec<_>>();
        assert!(artifact_paths.contains(&"file:///repo/src/lib.rs"));
        assert!(artifact_paths.contains(&"file:///repo/target/exfil.env"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_hides_legacy_endpoint_runtime_artifacts() {
        assert!(!dashboard_artifact_path_is_visible(
            "/System/Library/dyld/dyld_shared_cache_arm64e",
            Some("macos-endpoint-security"),
            None,
            false,
        ));
        assert!(!dashboard_artifact_path_is_visible(
            "/System/Library/example.conf",
            Some("macos-endpoint-security"),
            None,
            false,
        ));
        assert!(dashboard_artifact_path_is_visible(
            "/repo/src/lib.rs",
            Some("macos-endpoint-security"),
            None,
            false,
        ));
    }

    #[test]
    fn artifact_visibility_preserves_bracket_routes_and_hides_globs() {
        for (path, expected_visible) in [
            ("/repo/src/lib.rs", true),
            ("/repo/*.sh", false),
            ("/repo/file?.md", false),
            ("/repo/{one,two}.json", false),
            ("/repo/app/[slug]/page.tsx", true),
            ("/repo/pages/[id].tsx", true),
            ("/repo/app/[[...slug]]/page.tsx", true),
        ] {
            assert_eq!(
                dashboard_artifact_path_is_visible(path, Some("bash-command-parser"), None, false,),
                expected_visible,
                "visibility for {path}",
            );
        }
    }

    #[test]
    fn dashboard_hides_endpoint_system_dependencies() {
        for (path, expected_visible) in [
            ("/usr/local/bin", false),
            ("/usr/local/bin/gensee", false),
            ("/usr/local/binaries/tool", true),
            ("/usr/local/bin-old/x", true),
        ] {
            assert_eq!(
                dashboard_artifact_path_is_visible(
                    path,
                    Some("macos-endpoint-security"),
                    None,
                    false,
                ),
                expected_visible,
                "visibility for {path}",
            );
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
        conn.execute(
            "INSERT INTO artifact_facts (
                kind, uri, current_artifact_id, last_seen_at, last_modified_source,
                metadata, dashboard_visible
             ) VALUES ('file', 'file:///repo/source', ?1, 10000, 'agent', '{}', 1)",
            [clean_source],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO artifact_facts (
                kind, uri, current_artifact_id, last_seen_at, last_modified_source,
                metadata, dashboard_visible
             ) VALUES ('file', 'file:///repo/destination', ?1, 9999, 'agent', '{}', 1)",
            [clean_destination],
        )
        .unwrap();
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
                    kind, uri, last_seen_at, last_modified_source, metadata,
                    dashboard_visible
                 ) VALUES ('file', ?1, ?2, 'macos-endpoint-security', ?3, 1)",
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
                    kind, uri, last_seen_at, last_modified_source, metadata,
                    dashboard_visible
                 ) VALUES ('file', ?1, ?2, 'macos-endpoint-security', ?3, 0)",
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
        assert_eq!(dashboard["summary"]["artifacts_count"], 102);
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
    fn wildcard_file_intents_do_not_materialize_artifacts() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-wildcard-artifacts-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo","prompt":"inspect scripts"}"#,
                100,
            ))
            .unwrap();
        for (index, path) in ["/repo/*.sh", "/repo/file?.md", "/repo/{one,two}.json"]
            .into_iter()
            .enumerate()
        {
            store
                .append_file_intent(&FileIntent {
                    provider: "bash-command-parser".to_string(),
                    session_id: Some("s1".to_string()),
                    tool_use_id: Some(format!("tool_{index}")),
                    observed_at_ms: 110 + index as u64,
                    operation: "read".to_string(),
                    path: path.to_string(),
                    source_command: format!("cat {path}"),
                    sensitive: false,
                    confidence: "low".to_string(),
                })
                .unwrap();
            assert!(store.artifact_fact_for_file(path).unwrap().is_none());
        }

        let dashboard = store.dashboard_state().unwrap();
        assert_eq!(dashboard["summary"]["artifacts_count"], 0);
        assert!(dashboard["artifacts"].as_array().unwrap().is_empty());

        store
            .append_file_intent(&FileIntent {
                provider: "bash-command-parser".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_route".to_string()),
                observed_at_ms: 119,
                operation: "read".to_string(),
                path: "/repo/app/[slug]/page.tsx".to_string(),
                source_command: "cat /repo/app/[slug]/page.tsx".to_string(),
                sensitive: false,
                confidence: "low".to_string(),
            })
            .unwrap();
        assert!(store
            .artifact_fact_for_file("/repo/app/[slug]/page.tsx")
            .unwrap()
            .is_some());

        store
            .append_file_intent(&FileIntent {
                provider: "bash-command-parser".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool_concrete".to_string()),
                observed_at_ms: 120,
                operation: "read".to_string(),
                path: "/repo/build.sh".to_string(),
                source_command: "cat /repo/build.sh".to_string(),
                sensitive: false,
                confidence: "low".to_string(),
            })
            .unwrap();
        let dashboard = store.dashboard_state().unwrap();
        assert_eq!(dashboard["summary"]["artifacts_count"], 2);
        let paths = dashboard["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|artifact| artifact["uri"].as_str())
            .collect::<Vec<_>>();
        assert!(paths.contains(&"file:///repo/build.sh"));
        assert!(paths.contains(&"file:///repo/app/[slug]/page.tsx"));

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
        let mut patch_event = native_tool_event(
            "apply_patch",
            "patch_1",
            &json!({ "input": patch }).to_string(),
            110,
        );
        // Codex also promotes the patch text into the generic command field.
        // Native file-tool normalization must win so the changed paths remain
        // available for intent/Endpoint Security correlation.
        patch_event.tool_input_command = Some(patch.to_string());
        store.append_hook_event(&patch_event).unwrap();

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

    #[test]
    fn endpoint_active_tool_window_opens_closes_and_expires() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-endpoint-tool-window-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"write it"}"#,
                100,
            ))
            .unwrap();
        store
            .append_hook_event(&native_tool_event(
                "Bash",
                "tool-active",
                r#"{"command":"printf hi > out.txt"}"#,
                200,
            ))
            .unwrap();

        let active = store.active_tool_call("s1", 250, 1_000).unwrap().unwrap();
        assert_eq!(active.session_id, "s1");
        assert_eq!(active.provider, "claude-code");
        assert_eq!(active.tool_use_id.as_deref(), Some("tool-active"));
        assert_eq!(active.cwd, "/repo");
        assert!(store
            .active_tool_call("s1", 1_201, 1_000)
            .unwrap()
            .is_none());

        let mut completed = native_tool_event("Bash", "tool-active", "{}", 300);
        completed.hook_event_name = Some("PostToolUse".to_string());
        completed.raw_json = r#"{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Bash","tool_use_id":"tool-active"}"#.to_string();
        store.append_hook_event(&completed).unwrap();
        assert!(store.active_tool_call("s1", 350, 1_000).unwrap().is_none());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn endpoint_active_tool_window_resolves_shared_root_pid_by_live_tool() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-endpoint-shared-root-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        for (session_id, started_at_ms) in [("s1", 100), ("s2", 110)] {
            store
                .append_session(&AgentSession {
                    session_id: session_id.to_string(),
                    agent_binary: "codex".to_string(),
                    root_pid: 1234,
                    cwd: "/repo".to_string(),
                    repo_path: Some("/repo".to_string()),
                    mode: Some("hook".to_string()),
                    workspace_mode: None,
                    original_workspace: None,
                    staged_workspace: None,
                    sandbox_profile: None,
                    sandbox_profile_path: None,
                    started_at_ms,
                    ended_at_ms: None,
                    exit_code: None,
                })
                .unwrap();
        }

        store
            .append_hook_event(&hook_event(
                "UserPromptSubmit",
                r#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"one"}"#,
                120,
            ))
            .unwrap();
        let mut prompt_s2 = hook_event(
            "UserPromptSubmit",
            r#"{"session_id":"s2","hook_event_name":"UserPromptSubmit","prompt":"two"}"#,
            130,
        );
        prompt_s2.session_id = Some("s2".to_string());
        store.append_hook_event(&prompt_s2).unwrap();

        store
            .append_hook_event(&native_tool_event(
                "Bash",
                "tool-s1",
                r#"{"command":"one"}"#,
                200,
            ))
            .unwrap();
        let mut tool_s2 = native_tool_event("Bash", "tool-s2", r#"{"command":"two"}"#, 300);
        tool_s2.session_id = Some("s2".to_string());
        tool_s2.cwd = Some("/repo/other".to_string());
        tool_s2.raw_json = r#"{"session_id":"s2","hook_event_name":"PreToolUse","cwd":"/repo/other","tool_name":"Bash","tool_use_id":"tool-s2","tool_input":{"command":"two"}}"#.to_string();
        store.append_hook_event(&tool_s2).unwrap();
        store
            .append_file_intent(&FileIntent {
                provider: "native-file-tool".to_string(),
                session_id: Some("s1".to_string()),
                tool_use_id: Some("tool-s1".to_string()),
                observed_at_ms: 320,
                operation: "write".to_string(),
                path: "/repo/current/file.rs".to_string(),
                source_command: "apply_patch write /repo/current/file.rs".to_string(),
                sensitive: false,
                confidence: "high".to_string(),
            })
            .unwrap();

        let exact_intent = store
            .tool_call_for_recent_file_intent("/repo/current/file.rs", 350, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(exact_intent.session_id, "s1");
        assert_eq!(exact_intent.tool_use_id.as_deref(), Some("tool-s1"));

        let active = store
            .active_tool_call_for_root_pid(1234, 350, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(active.session_id, "s2");
        assert_eq!(active.tool_use_id.as_deref(), Some("tool-s2"));
        let workspace_match = store
            .active_tool_call_for_root_pid_at_path(
                1234,
                Some("/repo/current/file.rs"),
                350,
                1_000,
                0,
            )
            .unwrap()
            .unwrap();
        assert_eq!(workspace_match.session_id, "s1");
        let recovered_from_stale_label = store
            .active_tool_call_for_session_root("s1", None, 350, 1_000, 0)
            .unwrap()
            .unwrap();
        assert_eq!(recovered_from_stale_label.session_id, "s2");

        let mut completed_s2 = tool_s2;
        completed_s2.hook_event_name = Some("PostToolUse".to_string());
        completed_s2.observed_at_ms = 360;
        completed_s2.raw_json = r#"{"session_id":"s2","hook_event_name":"PostToolUse","tool_name":"Bash","tool_use_id":"tool-s2"}"#.to_string();
        store.append_hook_event(&completed_s2).unwrap();
        let completion_grace = store
            .active_tool_call_for_root_pid_at_path(
                1234,
                Some("/repo/other/file.rs"),
                370,
                1_000,
                2_000,
            )
            .unwrap()
            .unwrap();
        assert_eq!(completion_grace.session_id, "s2");
        let fallback = store
            .active_tool_call_for_root_pid(1234, 370, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(fallback.session_id, "s1");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn endpoint_alert_deduplication_survives_pipeline_restarts() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-store-test-endpoint-alert-dedupe-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        let alert = PolicyAlert {
            session_id: Some("s1".to_string()),
            tool_use_id: Some("tool-1".to_string()),
            severity: "medium".to_string(),
            action: "warn".to_string(),
            rule_id: "hook_bypass_file_mutation".to_string(),
            message: "unreported mutation".to_string(),
            path: Some("/repo/out.txt".to_string()),
            evidence: Some(json!({"source": "macos-endpoint-security"})),
            observed_at_ms: 1_000,
        };
        let key = "s1:42:7:/repo/out.txt:mutation";
        assert!(store
            .append_endpoint_policy_alert(&alert, key, 10_000)
            .unwrap());
        assert!(!store
            .append_endpoint_policy_alert(
                &PolicyAlert {
                    observed_at_ms: 2_000,
                    ..alert.clone()
                },
                key,
                10_000
            )
            .unwrap());
        assert!(store
            .append_endpoint_policy_alert(
                &PolicyAlert {
                    observed_at_ms: 12_001,
                    ..alert
                },
                key,
                10_000
            )
            .unwrap());
        assert_eq!(store.list_alerts().unwrap().len(), 2);

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
