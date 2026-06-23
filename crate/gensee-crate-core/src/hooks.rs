#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentHookEvent {
    pub provider: String,
    pub session_id: Option<String>,
    pub hook_event_name: Option<String>,
    pub cwd: Option<String>,
    pub transcript_path: Option<String>,
    pub tool_name: Option<String>,
    pub tool_use_id: Option<String>,
    pub tool_input_command: Option<String>,
    pub tool_input_description: Option<String>,
    pub tool_response_stdout: Option<String>,
    pub tool_response_stderr: Option<String>,
    pub tool_response_interrupted: Option<bool>,
    pub duration_ms: Option<u64>,
    pub permission_mode: Option<String>,
    pub effort_level: Option<String>,
    pub observed_at_ms: u64,
    pub raw_json: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessObservation {
    pub provider: String,
    pub session_id: Option<String>,
    pub tool_use_id: Option<String>,
    pub observed_at_ms: u64,
    pub pid: u32,
    pub ppid: u32,
    pub binary: String,
    pub command: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileIntent {
    pub provider: String,
    pub session_id: Option<String>,
    pub tool_use_id: Option<String>,
    pub observed_at_ms: u64,
    pub operation: String,
    pub path: String,
    pub source_command: String,
    pub sensitive: bool,
    pub confidence: String,
}
