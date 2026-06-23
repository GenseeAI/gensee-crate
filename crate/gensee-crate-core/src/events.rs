#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    FileOpen,
    FileWrite,
    FileDelete,
    ProcessExec,
    NetworkConnect,
}

#[derive(Debug, Clone)]
pub struct AgentAttribution {
    pub root_process_id: u32,
    pub parent_process_id: Option<u32>,
    pub process_id: u32,
    pub process_tree_id: String,
    pub agent_name: Option<String>,
    pub working_directory: Option<String>,
    pub repo_path: Option<String>,
    pub terminal_session_id: Option<String>,
    pub attribution_confidence: f32,
}

#[derive(Debug, Clone)]
pub struct AgentEvent {
    pub kind: EventKind,
    pub timestamp_ms: u64,
    pub process_name: String,
    pub file_path: Option<String>,
    pub command_args: Option<String>,
    pub network_dest: Option<String>,
    pub attribution: AgentAttribution,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemEvent {
    pub source: String,
    pub event_type: String,
    pub event_kind: String,
    pub observed_at_ms: u64,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub process_name: Option<String>,
    pub executable_path: Option<String>,
    pub file_path: Option<String>,
    pub command_line: Option<String>,
    pub raw_json: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkspaceEffect {
    pub source: String,
    pub session_id: Option<String>,
    pub workspace: String,
    pub path: String,
    pub effect_type: String,
    pub observed_at_ms: u64,
    pub attribution: String,
    pub confidence: String,
}
