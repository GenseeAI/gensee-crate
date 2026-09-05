use crate::cowork::{classify_cowork_event, CoworkEventContext};
use gensee_crate_core::{endpoint_security_path_is_known_build_output, AgentSession, SystemEvent};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io;

pub const ENDPOINT_SECURITY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessKey {
    pub pid: u32,
    pub pidversion: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EndpointSecurityProcess {
    pub pid: u32,
    #[serde(default)]
    pub pidversion: u32,
    #[serde(default)]
    pub ppid: Option<u32>,
    #[serde(default)]
    pub parent_pidversion: Option<u32>,
    #[serde(default)]
    pub responsible_pid: Option<u32>,
    #[serde(default)]
    pub responsible_pidversion: Option<u32>,
    #[serde(default)]
    pub executable_path: Option<String>,
    #[serde(default)]
    pub signing_id: Option<String>,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub platform_binary: bool,
    #[serde(default)]
    pub is_es_client: bool,
    #[serde(default)]
    pub codesigning_flags: u32,
    #[serde(default)]
    pub start_time_ms: Option<u64>,
}

impl EndpointSecurityProcess {
    pub fn key(&self) -> ProcessKey {
        ProcessKey {
            pid: self.pid,
            pidversion: self.pidversion,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EndpointSecurityFile {
    pub path: String,
    #[serde(default)]
    pub path_truncated: bool,
    #[serde(default)]
    pub device: Option<u64>,
    #[serde(default)]
    pub inode: Option<u64>,
    #[serde(default)]
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EndpointSecurityAttribution {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub root_pid: Option<u32>,
    #[serde(default)]
    pub depth: Option<u32>,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub matched_by: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EndpointSecurityDecision {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub cache: bool,
    #[serde(default)]
    pub latency_us: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSecurityEvent {
    pub schema_version: u32,
    pub event_id: String,
    pub boot_id: String,
    pub observed_at_ms: u64,
    pub event_type: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub message_version: u32,
    #[serde(default)]
    pub seq_num: Option<u64>,
    #[serde(default)]
    pub global_seq_num: Option<u64>,
    #[serde(default)]
    pub dropped_events: u64,
    pub actor: EndpointSecurityProcess,
    #[serde(default)]
    pub target: Option<EndpointSecurityProcess>,
    #[serde(default)]
    pub file: Option<EndpointSecurityFile>,
    #[serde(default)]
    pub destination: Option<EndpointSecurityFile>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub open_flags: Option<i32>,
    #[serde(default)]
    pub exit_status: Option<i32>,
    #[serde(default)]
    pub modified: Option<bool>,
    #[serde(default)]
    pub attribution: EndpointSecurityAttribution,
    #[serde(default)]
    pub decision: EndpointSecurityDecision,
    #[serde(default)]
    pub cowork: Option<CoworkEventContext>,
}

fn default_action() -> String {
    "notify".to_string()
}

impl EndpointSecurityEvent {
    pub fn parse(line: &str) -> io::Result<Self> {
        let event: Self = serde_json::from_str(line).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Endpoint Security event: {error}"),
            )
        })?;
        event.validate()?;
        Ok(event)
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.schema_version != ENDPOINT_SECURITY_SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported Endpoint Security schema version {}",
                    self.schema_version
                ),
            ));
        }
        if self.event_id.trim().is_empty()
            || self.boot_id.trim().is_empty()
            || self.event_type.trim().is_empty()
            || self.actor.pid == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Endpoint Security event is missing identity fields",
            ));
        }
        Ok(())
    }

    pub fn primary_path(&self) -> Option<&str> {
        if self.event_type == "rename" {
            self.destination
                .as_ref()
                .map(|file| file.path.as_str())
                .or_else(|| self.file.as_ref().map(|file| file.path.as_str()))
        } else {
            self.file.as_ref().map(|file| file.path.as_str())
        }
    }

    pub fn is_read_open(&self) -> bool {
        // Endpoint Security reports kernel FREAD/FWRITE flags, not O_* flags.
        self.event_type == "open" && self.open_flags.is_some_and(|flags| flags & 1 != 0)
    }

    pub fn is_write_open(&self) -> bool {
        self.event_type == "open" && self.open_flags.is_some_and(|flags| flags & 2 != 0)
    }

    pub fn into_system_event(self) -> io::Result<SystemEvent> {
        let cowork_visibility = classify_cowork_event(&self);
        let mut raw_value = serde_json::to_value(&self).map_err(io::Error::other)?;
        raw_value["cowork_visibility"] =
            serde_json::to_value(&cowork_visibility).map_err(io::Error::other)?;
        let raw_json = serde_json::to_string(&raw_value).map_err(io::Error::other)?;
        let event_kind = if self.action == "auth" {
            "authorization"
        } else {
            match self.event_type.as_str() {
                "exec" | "fork" | "exit" => "process",
                "open" if self.is_write_open() => "file_mutation",
                "open" | "readdir" | "mmap" if self.is_read_open() || self.event_type != "open" => {
                    "file_read"
                }
                "create" | "write" | "rename" | "unlink" | "truncate" => "file_mutation",
                "close" if self.modified == Some(true) => "file_mutation",
                _ => "system",
            }
        };
        let normalized_type = if self.action == "auth" {
            format!("auth_{}", self.event_type)
        } else {
            self.event_type.clone()
        };
        let process_name = self
            .actor
            .executable_path
            .as_deref()
            .and_then(|path| path.rsplit('/').next())
            .map(str::to_string);
        let command_line = (!self.arguments.is_empty()).then(|| self.arguments.join(" "));
        Ok(SystemEvent {
            source: "macos-endpoint-security".to_string(),
            event_type: normalized_type,
            event_kind: event_kind.to_string(),
            observed_at_ms: self.observed_at_ms,
            pid: Some(self.actor.pid),
            ppid: self.actor.ppid,
            process_name,
            executable_path: self.actor.executable_path.clone(),
            file_path: self.primary_path().map(str::to_string),
            command_line,
            raw_json,
        }
        .with_execution_origin(cowork_visibility.execution_origin))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSecurityFinding {
    pub rule_id: &'static str,
    pub severity: &'static str,
    pub message: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EndpointAlertKey {
    session_id: String,
    process: ProcessKey,
    path: String,
    operation: &'static str,
}

/// Reduces the kernel's open/write/close stream to user-facing logical file
/// operations. This is deliberately in-memory as a first-stage coalescer; the
/// event store applies a second durable deduplication check across restarts.
pub struct EndpointSecurityAlertPipeline {
    recent_operations: HashMap<EndpointAlertKey, u64>,
    coalescing_window_ms: u64,
}

impl Default for EndpointSecurityAlertPipeline {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl EndpointSecurityAlertPipeline {
    pub fn new(coalescing_window_ms: u64) -> Self {
        Self {
            recent_operations: HashMap::new(),
            coalescing_window_ms,
        }
    }

    /// Returns the normalized operation and reporting path when this event is
    /// eligible to produce one new finding. Raw telemetry is stored regardless.
    pub fn logical_operation(
        &mut self,
        event: &EndpointSecurityEvent,
        session_id: &str,
        workspace_root: Option<&str>,
    ) -> Option<(&'static str, String)> {
        if endpoint_security_event_is_bookkeeping(event, workspace_root) {
            return None;
        }
        let operation = endpoint_security_logical_operation(event)?;
        let path = endpoint_security_reporting_path(event)?.to_string();
        let key = EndpointAlertKey {
            session_id: session_id.to_string(),
            process: event.actor.key(),
            path: path.clone(),
            operation,
        };
        let observed_at_ms = event.observed_at_ms;
        self.recent_operations.retain(|_, last_seen| {
            observed_at_ms.saturating_sub(*last_seen) <= self.coalescing_window_ms
        });
        if self.recent_operations.get(&key).is_some_and(|last_seen| {
            observed_at_ms.abs_diff(*last_seen) <= self.coalescing_window_ms
        }) {
            return None;
        }
        self.recent_operations.insert(key, observed_at_ms);
        Some((operation, path))
    }
}

pub fn endpoint_security_logical_operation(event: &EndpointSecurityEvent) -> Option<&'static str> {
    match event.event_type.as_str() {
        "open" if event.is_write_open() => Some("mutation"),
        "open" | "readdir" | "mmap" => Some("read"),
        "create" | "write" | "truncate" => Some("mutation"),
        "close" if event.modified == Some(true) => Some("mutation"),
        "rename" => Some("rename"),
        "unlink" => Some("delete"),
        _ => None,
    }
}

pub fn endpoint_security_reporting_path(event: &EndpointSecurityEvent) -> Option<&str> {
    if event.event_type == "rename" {
        event
            .destination
            .as_ref()
            .map(|file| file.path.as_str())
            .or_else(|| event.primary_path())
    } else {
        event.primary_path()
    }
}

/// Known harness/runtime bookkeeping is useful as raw telemetry but is not a
/// security finding. Build-output suppression requires both a fixed top-level
/// root under the active workspace and a known build process; directory names
/// or filename extensions alone are never enough.
pub fn endpoint_security_event_is_bookkeeping(
    event: &EndpointSecurityEvent,
    workspace_root: Option<&str>,
) -> bool {
    let executable = event
        .actor
        .executable_path
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if executable.contains("crashpad_handler")
        || executable.contains("crashreporter")
        || executable.ends_with("/reportcrash")
    {
        return true;
    }

    let Some(path) = endpoint_security_reporting_path(event) else {
        return false;
    };
    let normalized = path.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    if matches!(lower.as_str(), "/dev/null" | "/dev/zero" | "/dev/tty") {
        return true;
    }
    if lower.contains("/library/application support/codex/")
        || lower.contains("/library/application support/claude/")
        || lower.contains("/crashpad/")
        || lower.contains("/diagnosticreports/")
        || lower.contains("/crash reports/")
    {
        return true;
    }
    if (lower.contains("/.codex/sessions/") || lower.contains("/.claude/projects/"))
        && lower.ends_with(".jsonl")
    {
        return true;
    }
    if endpoint_security_event_is_known_build_output(event, &lower, workspace_root) {
        return true;
    }
    let sqlite_sidecar =
        lower.ends_with("-wal") || lower.ends_with("-shm") || lower.ends_with("-journal");
    sqlite_sidecar
        && (lower.contains("/.codex/")
            || lower.contains("/.claude/")
            || lower.contains("/library/application support/cursor/")
            || lower.contains("/library/application support/code/"))
}

fn endpoint_security_event_is_known_build_output(
    event: &EndpointSecurityEvent,
    normalized_lower_path: &str,
    workspace_root: Option<&str>,
) -> bool {
    endpoint_security_path_is_known_build_output(
        event.actor.executable_path.as_deref(),
        normalized_lower_path,
        workspace_root,
    )
}

#[derive(Debug, Clone)]
struct GraphNode {
    parent: Option<ProcessKey>,
    session_id: Option<String>,
    root_pid: Option<u32>,
    depth: Option<u32>,
}

/// Event-driven process graph keyed by Apple's reboot-scoped `(pid,pidversion)`
/// identity. PID-only roots are used only to bootstrap sessions recorded by
/// `gensee run`; all descendants use exact Endpoint Security identities.
pub struct EndpointSecurityIngestor {
    nodes: HashMap<ProcessKey, GraphNode>,
    active_roots: HashMap<u32, String>,
    exited: HashSet<ProcessKey>,
    last_global_seq: Option<u64>,
    fanout_reported: HashSet<String>,
}

impl EndpointSecurityIngestor {
    pub fn new(sessions: &[AgentSession]) -> Self {
        let active_roots = sessions
            .iter()
            .filter(|session| session.is_active() && session.root_pid != 0)
            .map(|session| (session.root_pid, session.session_id.clone()))
            .collect();
        Self {
            nodes: HashMap::new(),
            active_roots,
            exited: HashSet::new(),
            last_global_seq: None,
            fanout_reported: HashSet::new(),
        }
    }

    pub fn register_session_root(&mut self, pid: u32, session_id: impl Into<String>) {
        if pid != 0 {
            self.active_roots.insert(pid, session_id.into());
        }
    }

    pub fn ingest(
        &mut self,
        mut event: EndpointSecurityEvent,
    ) -> (EndpointSecurityEvent, Vec<EndpointSecurityFinding>) {
        if let Some(current) = event.global_seq_num {
            self.last_global_seq = Some(
                self.last_global_seq
                    .map_or(current, |last| last.max(current)),
            );
        }

        if let Some(session_id) = event.attribution.session_id.clone() {
            let root_pid = event.attribution.root_pid;
            if event.attribution.depth == Some(0) {
                self.active_roots
                    .insert(event.actor.pid, session_id.clone());
            }
            self.nodes.insert(
                event.actor.key(),
                GraphNode {
                    parent: match (event.actor.ppid, event.actor.parent_pidversion) {
                        (Some(pid), Some(pidversion)) => Some(ProcessKey { pid, pidversion }),
                        _ => None,
                    },
                    session_id: Some(session_id),
                    root_pid,
                    depth: event.attribution.depth,
                },
            );
        } else {
            self.ensure_actor(&event.actor);
        }
        self.attribute(&mut event);
        self.observe_transition(&event);
        let findings = self.findings(&event);
        (event, findings)
    }

    fn ensure_actor(&mut self, process: &EndpointSecurityProcess) {
        let key = process.key();
        if self.nodes.contains_key(&key) {
            return;
        }
        let direct_session = self.active_roots.get(&process.pid).cloned();
        let parent = match (process.ppid, process.parent_pidversion) {
            (Some(pid), Some(pidversion)) => Some(ProcessKey { pid, pidversion }),
            _ => None,
        };
        let inherited = parent.and_then(|parent_key| self.nodes.get(&parent_key).cloned());
        self.nodes.insert(
            key,
            GraphNode {
                parent,
                session_id: direct_session
                    .clone()
                    .or_else(|| inherited.as_ref()?.session_id.clone()),
                root_pid: direct_session
                    .as_ref()
                    .map(|_| process.pid)
                    .or_else(|| inherited.as_ref()?.root_pid),
                depth: direct_session
                    .as_ref()
                    .map(|_| 0)
                    .or_else(|| inherited.as_ref()?.depth.map(|depth| depth + 1)),
            },
        );
    }

    fn attribute(&self, event: &mut EndpointSecurityEvent) {
        let key = event.actor.key();
        if let Some(node) = self.nodes.get(&key) {
            if node.session_id.is_some() {
                event.attribution.session_id = node.session_id.clone();
                event.attribution.root_pid = node.root_pid;
                event.attribution.depth = node.depth;
                event.attribution.confidence = Some(1.0);
                event.attribution.matched_by = Some("endpoint_security_process_tree".to_string());
            }
        }
    }

    fn observe_transition(&mut self, event: &EndpointSecurityEvent) {
        match event.event_type.as_str() {
            "fork" => {
                if let Some(child) = &event.target {
                    let actor = self.nodes.get(&event.actor.key()).cloned();
                    self.nodes.insert(
                        child.key(),
                        GraphNode {
                            parent: Some(event.actor.key()),
                            session_id: actor.as_ref().and_then(|node| node.session_id.clone()),
                            root_pid: actor.as_ref().and_then(|node| node.root_pid),
                            depth: actor
                                .as_ref()
                                .and_then(|node| node.depth.map(|depth| depth + 1)),
                        },
                    );
                }
            }
            "exec" => {
                if let Some(target) = &event.target {
                    let actor = self.nodes.get(&event.actor.key()).cloned();
                    self.nodes.insert(
                        target.key(),
                        GraphNode {
                            parent: actor.as_ref().and_then(|node| node.parent),
                            session_id: actor.as_ref().and_then(|node| node.session_id.clone()),
                            root_pid: actor.as_ref().and_then(|node| node.root_pid),
                            depth: actor.as_ref().and_then(|node| node.depth),
                        },
                    );
                }
            }
            "exit" => {
                let key = event.actor.key();
                self.exited.insert(key);
                if let Some(node) = self.nodes.remove(&key) {
                    if node.depth == Some(0) || node.root_pid == Some(event.actor.pid) {
                        self.active_roots.remove(&event.actor.pid);
                        if let Some(session_id) = node.session_id {
                            for descendant in self.nodes.values_mut() {
                                if descendant.session_id.as_deref() == Some(&session_id) {
                                    descendant.session_id = None;
                                    descendant.root_pid = None;
                                    descendant.depth = None;
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn findings(&mut self, event: &EndpointSecurityEvent) -> Vec<EndpointSecurityFinding> {
        let mut findings = Vec::new();
        if event.dropped_events > 0 {
            findings.push(EndpointSecurityFinding {
                rule_id: "endpoint_security_event_gap",
                severity: "high",
                message: format!(
                    "Endpoint Security dropped {} event(s) before this message",
                    event.dropped_events
                ),
                path: None,
            });
        }
        if event.attribution.session_id.is_some()
            && event.event_type == "exec"
            && event.action == "notify"
        {
            let target = event
                .target
                .as_ref()
                .and_then(|process| process.executable_path.clone())
                .unwrap_or_else(|| "an unknown executable".to_string());
            findings.push(EndpointSecurityFinding {
                rule_id: "agent_descendant_exec",
                severity: "info",
                message: format!("Agent process tree executed {target}"),
                path: Some(target),
            });
            let interpreter = event
                .target
                .as_ref()
                .and_then(|process| process.executable_path.as_deref())
                .and_then(|path| path.rsplit('/').next())
                .is_some_and(|name| {
                    matches!(
                        name,
                        "sh" | "bash"
                            | "zsh"
                            | "fish"
                            | "python"
                            | "python3"
                            | "node"
                            | "ruby"
                            | "perl"
                            | "osascript"
                    )
                });
            if interpreter {
                findings.push(EndpointSecurityFinding {
                    rule_id: "unexpected_interpreter_chain",
                    severity: "low",
                    message: "Agent descendant launched an interpreter; arguments and ancestry were captured"
                        .to_string(),
                    path: event
                        .target
                        .as_ref()
                        .and_then(|process| process.executable_path.clone()),
                });
            }
        }
        if event.event_type == "fork" && event.action == "notify" {
            if let Some(session_id) = event.attribution.session_id.as_deref() {
                let descendants = self
                    .nodes
                    .values()
                    .filter(|node| node.session_id.as_deref() == Some(session_id))
                    .count();
                if descendants > 128 && self.fanout_reported.insert(session_id.to_string()) {
                    findings.push(EndpointSecurityFinding {
                        rule_id: "agent_process_fanout",
                        severity: "high",
                        message: format!(
                            "Agent session has expanded to {descendants} tracked process identities"
                        ),
                        path: None,
                    });
                }
            }
        }
        findings
    }

    pub fn health(&self) -> Value {
        json!({
            "tracked_processes": self.nodes.len(),
            "active_session_roots": self.active_roots.len(),
            "exited_processes": self.exited.len(),
            "last_global_seq_num": self.last_global_seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(
        pid: u32,
        version: u32,
        ppid: Option<u32>,
        parent_version: Option<u32>,
    ) -> EndpointSecurityProcess {
        EndpointSecurityProcess {
            pid,
            pidversion: version,
            ppid,
            parent_pidversion: parent_version,
            executable_path: Some(format!("/bin/p{pid}")),
            ..EndpointSecurityProcess::default()
        }
    }

    fn event(kind: &str, actor: EndpointSecurityProcess) -> EndpointSecurityEvent {
        EndpointSecurityEvent {
            schema_version: 1,
            event_id: format!("event-{kind}"),
            boot_id: "boot-1".to_string(),
            observed_at_ms: 1,
            event_type: kind.to_string(),
            action: "notify".to_string(),
            message_version: 4,
            seq_num: Some(1),
            global_seq_num: Some(1),
            dropped_events: 0,
            actor,
            target: None,
            file: None,
            destination: None,
            cwd: None,
            script: None,
            arguments: vec![],
            open_flags: None,
            exit_status: None,
            modified: None,
            attribution: EndpointSecurityAttribution::default(),
            decision: EndpointSecurityDecision::default(),
            cowork: None,
        }
    }

    fn session() -> AgentSession {
        AgentSession {
            session_id: "session-1".to_string(),
            agent_binary: "codex".to_string(),
            root_pid: 10,
            cwd: "/repo".to_string(),
            repo_path: Some("/repo".to_string()),
            mode: None,
            workspace_mode: None,
            original_workspace: None,
            staged_workspace: None,
            sandbox_profile: None,
            sandbox_profile_path: None,
            started_at_ms: 1,
            ended_at_ms: None,
            exit_code: None,
        }
    }

    #[test]
    fn follows_fork_and_exec_with_pidversion_identity() {
        let mut ingestor = EndpointSecurityIngestor::new(&[session()]);
        let (root_event, _) = ingestor.ingest(event("open", process(10, 1, Some(1), Some(1))));
        assert_eq!(
            root_event.attribution.session_id.as_deref(),
            Some("session-1")
        );

        let mut fork = event("fork", process(10, 1, Some(1), Some(1)));
        fork.target = Some(process(11, 1, Some(10), Some(1)));
        ingestor.ingest(fork);

        let mut exec = event("exec", process(11, 1, Some(10), Some(1)));
        exec.target = Some(process(11, 2, Some(10), Some(1)));
        let (exec, findings) = ingestor.ingest(exec);
        assert_eq!(exec.attribution.session_id.as_deref(), Some("session-1"));
        assert_eq!(exec.attribution.depth, Some(1));
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "agent_descendant_exec"));

        let (post_exec, _) = ingestor.ingest(event("open", process(11, 2, Some(10), Some(1))));
        assert_eq!(
            post_exec.attribution.session_id.as_deref(),
            Some("session-1")
        );
    }

    #[test]
    fn rename_uses_destination_as_primary_and_persisted_path() {
        let mut rename = event("rename", process(11, 1, Some(10), Some(1)));
        rename.file = Some(EndpointSecurityFile {
            path: "/repo/.source.swift.tmp".to_string(),
            ..EndpointSecurityFile::default()
        });
        rename.destination = Some(EndpointSecurityFile {
            path: "/repo/Source.swift".to_string(),
            ..EndpointSecurityFile::default()
        });

        assert_eq!(rename.primary_path(), Some("/repo/Source.swift"));
        assert_eq!(
            rename
                .clone()
                .into_system_event()
                .unwrap()
                .file_path
                .as_deref(),
            Some("/repo/Source.swift")
        );
    }

    #[test]
    fn honors_sensor_reported_sequence_gaps() {
        let mut ingestor = EndpointSecurityIngestor::new(&[]);
        ingestor.ingest(event("open", process(50, 1, None, None)));
        let mut next = event("open", process(50, 1, None, None));
        next.global_seq_num = Some(4);
        next.dropped_events = 2;
        let (next, findings) = ingestor.ingest(next);
        assert_eq!(next.dropped_events, 2);
        assert_eq!(findings[0].rule_id, "endpoint_security_event_gap");
    }

    #[test]
    fn does_not_infer_gaps_from_filtered_global_sequence_numbers() {
        let mut ingestor = EndpointSecurityIngestor::new(&[]);
        ingestor.ingest(event("open", process(50, 1, None, None)));
        let mut next = event("open", process(50, 1, None, None));
        next.global_seq_num = Some(400);
        let (next, findings) = ingestor.ingest(next);
        assert_eq!(next.dropped_events, 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn maps_read_open_to_normalized_system_event() {
        let mut raw = event("open", process(50, 1, None, None));
        raw.open_flags = Some(1);
        raw.file = Some(EndpointSecurityFile {
            path: "/tmp/example".to_string(),
            inode: Some(42),
            ..EndpointSecurityFile::default()
        });
        let system = raw.into_system_event().unwrap();
        assert_eq!(system.source, "macos-endpoint-security");
        assert_eq!(system.event_kind, "file_read");
        assert_eq!(system.file_path.as_deref(), Some("/tmp/example"));
    }

    #[test]
    fn maps_write_only_open_to_file_mutation() {
        let mut raw = event("open", process(50, 1, None, None));
        raw.open_flags = Some(2);
        raw.file = Some(EndpointSecurityFile {
            path: "/tmp/output".to_string(),
            ..EndpointSecurityFile::default()
        });
        let system = raw.into_system_event().unwrap();
        assert_eq!(system.event_kind, "file_mutation");
        assert_eq!(system.file_path.as_deref(), Some("/tmp/output"));
    }

    #[test]
    fn preserves_extension_supplied_session_attribution() {
        let mut ingestor = EndpointSecurityIngestor::new(&[]);
        let mut raw = event("open", process(88, 3, Some(1), Some(1)));
        raw.attribution.session_id = Some("live-session".to_string());
        raw.attribution.root_pid = Some(88);
        raw.attribution.depth = Some(0);
        let (attributed, _) = ingestor.ingest(raw);
        assert_eq!(
            attributed.attribution.session_id.as_deref(),
            Some("live-session")
        );
    }

    #[test]
    fn root_exit_revokes_attribution_from_surviving_background_helpers() {
        let mut ingestor = EndpointSecurityIngestor::new(&[session()]);
        ingestor.ingest(event("open", process(10, 1, Some(1), Some(1))));

        let mut fork = event("fork", process(10, 1, Some(1), Some(1)));
        fork.target = Some(process(11, 1, Some(10), Some(1)));
        ingestor.ingest(fork);
        ingestor.ingest(event("exit", process(10, 1, Some(1), Some(1))));

        let (helper_event, _) = ingestor.ingest(event("open", process(11, 1, Some(10), Some(1))));
        assert_eq!(helper_event.attribution.session_id, None);
        assert_eq!(ingestor.health()["active_session_roots"], 0);
    }

    #[test]
    fn sensor_attributed_root_exit_revokes_helpers_without_depth() {
        let mut ingestor = EndpointSecurityIngestor::new(&[]);
        let mut root = event("open", process(10, 1, Some(1), Some(1)));
        root.attribution.session_id = Some("session-1".to_string());
        root.attribution.root_pid = Some(10);
        ingestor.ingest(root);

        let mut helper = event("open", process(11, 1, Some(10), Some(1)));
        helper.attribution.session_id = Some("session-1".to_string());
        helper.attribution.root_pid = Some(10);
        ingestor.ingest(helper);

        let mut exit = event("exit", process(10, 1, Some(1), Some(1)));
        exit.attribution.session_id = Some("session-1".to_string());
        exit.attribution.root_pid = Some(10);
        ingestor.ingest(exit);

        let (helper_event, _) = ingestor.ingest(event("open", process(11, 1, Some(10), Some(1))));
        assert_eq!(helper_event.attribution.session_id, None);
        assert_eq!(ingestor.health()["active_session_roots"], 0);
    }

    #[test]
    fn coalesces_open_write_and_close_into_one_mutation() {
        let mut pipeline = EndpointSecurityAlertPipeline::new(10_000);
        let mut open = event("open", process(20, 2, Some(10), Some(1)));
        open.open_flags = Some(2);
        open.file = Some(EndpointSecurityFile {
            path: "/repo/output.txt".to_string(),
            ..EndpointSecurityFile::default()
        });
        assert_eq!(
            pipeline.logical_operation(&open, "session-1", Some("/repo")),
            Some(("mutation", "/repo/output.txt".to_string()))
        );

        let mut write = event("write", process(20, 2, Some(10), Some(1)));
        write.observed_at_ms = 2;
        write.file = open.file.clone();
        assert_eq!(
            pipeline.logical_operation(&write, "session-1", Some("/repo")),
            None
        );

        let mut close = event("close", process(20, 2, Some(10), Some(1)));
        close.observed_at_ms = 3;
        close.modified = Some(true);
        close.file = open.file;
        assert_eq!(
            pipeline.logical_operation(&close, "session-1", Some("/repo")),
            None
        );
    }

    #[test]
    fn keeps_same_path_operations_from_different_processes_distinct() {
        let mut pipeline = EndpointSecurityAlertPipeline::new(10_000);
        let mut first = event("write", process(20, 2, Some(10), Some(1)));
        first.file = Some(EndpointSecurityFile {
            path: "/repo/output.txt".to_string(),
            ..EndpointSecurityFile::default()
        });
        let mut second = first.clone();
        second.actor = process(21, 1, Some(10), Some(1));
        second.observed_at_ms = 2;
        assert!(pipeline
            .logical_operation(&first, "session-1", Some("/repo"))
            .is_some());
        assert!(pipeline
            .logical_operation(&second, "session-1", Some("/repo"))
            .is_some());
    }

    #[test]
    fn excludes_crash_reports_transcripts_build_outputs_and_sqlite_sidecars() {
        for (process_path, path) in [
            (
                "/Applications/Codex.app/Contents/Frameworks/browser_crashpad_handler",
                "/tmp/report.dmp",
            ),
            ("/bin/codex", "/Users/me/.codex/sessions/2026/session.jsonl"),
            (
                "/Users/me/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc",
                "/repo/target/debug/deps/output.o",
            ),
            ("/usr/bin/swiftc", "/repo/.build/debug/output.o"),
            ("/usr/bin/xcodebuild", "/repo/deriveddata/Build/output.o"),
            (
                "/opt/homebrew/bin/npm",
                "/repo/node_modules/.cache/cache.bin",
            ),
            ("/usr/bin/xctest", "/repo/test-results/result.xml"),
            ("/bin/codex", "/Users/me/.codex/state.sqlite-wal"),
            ("/bin/codex", "/dev/null"),
        ] {
            let mut raw = event("write", process(20, 2, Some(10), Some(1)));
            raw.actor.executable_path = Some(process_path.to_string());
            raw.file = Some(EndpointSecurityFile {
                path: path.to_string(),
                ..EndpointSecurityFile::default()
            });
            assert!(
                endpoint_security_event_is_bookkeeping(&raw, Some("/repo")),
                "{path}"
            );
        }
    }

    #[test]
    fn does_not_hide_agent_files_in_build_named_directories() {
        for path in [
            "/repo/target/exfil.env",
            "/repo/src/test-results/id_rsa",
            "/other/target/exfil.env",
        ] {
            let mut raw = event("write", process(20, 2, Some(10), Some(1)));
            raw.actor.executable_path =
                Some("/Applications/Codex.app/Contents/MacOS/Codex".to_string());
            raw.file = Some(EndpointSecurityFile {
                path: path.to_string(),
                ..EndpointSecurityFile::default()
            });
            assert!(
                !endpoint_security_event_is_bookkeeping(&raw, Some("/repo")),
                "{path}"
            );
        }

        let mut nested_build = event("write", process(20, 2, Some(10), Some(1)));
        nested_build.actor.executable_path = Some("/bin/rustc".to_string());
        nested_build.file = Some(EndpointSecurityFile {
            path: "/repo/src/target/output.o".to_string(),
            ..EndpointSecurityFile::default()
        });
        assert!(!endpoint_security_event_is_bookkeeping(
            &nested_build,
            Some("/repo")
        ));

        let mut planted_build_name = event("write", process(20, 2, Some(10), Some(1)));
        planted_build_name.actor.executable_path = Some("/repo/npm".to_string());
        planted_build_name.file = Some(EndpointSecurityFile {
            path: "/repo/target/exfil.env".to_string(),
            ..EndpointSecurityFile::default()
        });
        assert!(!endpoint_security_event_is_bookkeeping(
            &planted_build_name,
            Some("/repo")
        ));
    }

    #[test]
    fn does_not_hide_workspace_files_with_bookkeeping_like_extensions() {
        let mut raw = event("write", process(20, 2, Some(10), Some(1)));
        raw.file = Some(EndpointSecurityFile {
            path: "/repo/security-events.log".to_string(),
            ..EndpointSecurityFile::default()
        });
        assert!(!endpoint_security_event_is_bookkeeping(&raw, Some("/repo")));
    }
}
